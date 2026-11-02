//! OIDC tokens from CI (research §5.1, PLAN.md phase 3): the verification side only.
//!
//! The operator lists the issuers the server trusts (`--oidc-issuer`), each with its kind and JWKS
//! URL; there is no discovery. A target lists the claims a token must carry (`oidc` bindings), and
//! every bound claim must match exactly. A token is accepted when its signature verifies against
//! the issuer's keys (RS256 or ES256), `iss` and `aud` match, it hasn't expired, and one of the
//! target's bindings matches.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// GitHub Actions' issuer.
pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
/// The audience Azure DevOps puts in every token; the caller can't choose it.
pub const AZURE_AUDIENCE: &str = "api://AzureADTokenExchange";

/// Clock skew allowed on `exp` and `nbf`.
const LEEWAY_SECS: i64 = 60;
/// Keys are fetched again after this long.
const JWKS_TTL: Duration = Duration::from_secs(600);
/// An unknown `kid` fetches the keys again, but not more often than this.
const JWKS_REFETCH: Duration = Duration::from_secs(60);
const MAX_TOKEN: usize = 16 * 1024;
const MAX_JWKS: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Github,
    Gitlab,
    Azure,
}

impl Kind {
    /// The claim a binding must include: an id that a deleted and recreated repository, project or
    /// service connection with the same name doesn't inherit.
    pub fn required_claim(self) -> &'static str {
        match self {
            Kind::Github => "repository_id",
            Kind::Gitlab => "project_id",
            Kind::Azure => "sub",
        }
    }
}

/// One trusted issuer (`--oidc-issuer KIND=ISSUER[,JWKS_URL]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issuer {
    pub kind: Kind,
    pub issuer: String,
    pub jwks: String,
}

impl Issuer {
    /// Parses `github`, `github=ISSUER`, `gitlab=ISSUER[,JWKS]` or `azure=ISSUER,JWKS`.
    pub fn parse(spec: &str) -> Result<Issuer, String> {
        let (kind, rest) = spec.split_once('=').unwrap_or((spec, ""));
        let kind = match kind {
            "github" => Kind::Github,
            "gitlab" => Kind::Gitlab,
            "azure" => Kind::Azure,
            _ => return Err(format!("--oidc-issuer {spec}: the kind must be github, gitlab or azure")),
        };
        let (issuer, jwks) = match rest.split_once(',') {
            Some((i, j)) => (i.trim(), Some(j.trim())),
            None => (rest.trim(), None),
        };
        let issuer = match (kind, issuer) {
            (Kind::Github, "") => GITHUB_ISSUER,
            (_, "") => {
                return Err(format!("--oidc-issuer {spec}: give the issuer URL, e.g. gitlab=https://gitlab.com"));
            }
            (_, i) => i,
        }
        .trim_end_matches('/')
        .to_string();
        let jwks = match (kind, jwks) {
            (_, Some(j)) => j.to_string(),
            (Kind::Github, None) => format!("{issuer}/.well-known/jwks"),
            (Kind::Gitlab, None) => format!("{issuer}/oauth/discovery/keys"),
            (Kind::Azure, None) => {
                return Err(format!("--oidc-issuer {spec}: give the JWKS URL too: azure=ISSUER,JWKS_URL"));
            }
        };
        for url in [&issuer, &jwks] {
            if !secure_url(url) {
                return Err(format!("--oidc-issuer {spec}: {url} must be an https:// URL"));
            }
        }
        Ok(Issuer { kind, issuer, jwks })
    }
}

/// https, or http to this machine (for tests and a local identity provider).
fn secure_url(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    let Some(rest) = url.strip_prefix("http://") else { return false };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit_once(':').filter(|(h, p)| !h.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    matches!(host.map_or(rest.split('/').next().unwrap_or(""), |(h, _)| h), "127.0.0.1" | "localhost" | "[::1]")
}

/// A target's binding: tokens from `issuer` whose claims all equal these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub issuer: String,
    pub claims: BTreeMap<String, String>,
}

/// The longest claim name or value a binding may hold.
const MAX_CLAIM: usize = 300;

/// Checks a target's bindings against the trusted issuers.
pub fn check_bindings(bindings: &[Binding], issuers: &[Issuer]) -> Result<(), String> {
    if bindings.len() > 20 {
        return Err("oidc: at most 20 bindings".into());
    }
    for b in bindings {
        let issuer = b.issuer.trim_end_matches('/');
        let Some(i) = issuers.iter().find(|i| i.issuer == issuer) else {
            return Err(format!("oidc: the server doesn't trust the issuer {issuer} (see --oidc-issuer)"));
        };
        let need = i.kind.required_claim();
        if !b.claims.contains_key(need) {
            return Err(format!(
                "oidc: a binding for {issuer} must include the claim {need}, which a recreated \
                 repository or project with the same name doesn't inherit"
            ));
        }
        for (k, v) in &b.claims {
            if k.is_empty() || k.len() > MAX_CLAIM || v.is_empty() || v.len() > MAX_CLAIM {
                return Err(format!("oidc: claim names and values must be 1-{MAX_CLAIM} characters"));
            }
            if matches!(k.as_str(), "iss" | "aud" | "exp" | "nbf" | "iat" | "jti") {
                return Err(format!("oidc: the server checks {k} itself; don't bind it"));
            }
        }
    }
    Ok(())
}

/// A verified token: who it is, for the audit log and the rate limits.
#[derive(Debug, Clone)]
pub struct Identity {
    /// Stable for one pipeline identity: the issuer and the subject.
    pub owner: String,
    /// For the audit log: issuer, subject, repository or project, and run or pipeline id.
    pub actor: String,
}

/// A public key from a JWKS.
#[derive(Clone)]
enum Key {
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    /// An uncompressed P-256 point (0x04 || x || y).
    P256(Vec<u8>),
}

#[derive(Default)]
struct Keys {
    by_kid: HashMap<String, (Key, Option<String>)>,
    fetched: Option<Instant>,
    attempted: Option<Instant>,
}

/// The JWKS cache and the verifier.
pub struct Verifier {
    pub issuers: Vec<Issuer>,
    /// The `aud` tokens must carry: the server's own URL (`--oidc-audience`).
    pub audience: Option<String>,
    keys: Mutex<HashMap<String, Keys>>,
}

/// Something wrong with a token. The message goes to the audit log, never to the caller.
#[derive(Debug)]
pub struct Refused(pub String);

fn refuse(m: impl Into<String>) -> Refused {
    Refused(m.into())
}

/// `true` if this looks like a JWT rather than a target token.
pub fn looks_like_jwt(token: &str) -> bool {
    token.starts_with("eyJ") && token.bytes().filter(|&b| b == b'.').count() == 2
}

impl Verifier {
    pub fn new(issuers: Vec<Issuer>, audience: Option<String>) -> Verifier {
        Verifier { issuers, audience: audience.map(|a| a.trim_end_matches('/').to_string()), keys: Mutex::default() }
    }

    pub fn enabled(&self) -> bool {
        !self.issuers.is_empty()
    }

    /// Verifies `token` for a target with `bindings`, at `now` (Unix seconds).
    pub async fn verify(&self, token: &str, bindings: &[Binding], now: i64) -> Result<Identity, Refused> {
        if token.len() > MAX_TOKEN {
            return Err(refuse("the token is too long"));
        }
        let mut parts = token.split('.');
        let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            return Err(refuse("not a JWT"));
        };
        let header: Value = decode_json(h).ok_or_else(|| refuse("unreadable JWT header"))?;
        let claims: Value = decode_json(p).ok_or_else(|| refuse("unreadable JWT claims"))?;
        let sig = URL_SAFE_NO_PAD.decode(s).map_err(|_| refuse("unreadable JWT signature"))?;
        if header.get("crit").is_some() {
            return Err(refuse("the JWT header has critical extensions"));
        }
        let alg = header["alg"].as_str().unwrap_or("");
        if !matches!(alg, "RS256" | "ES256") {
            return Err(refuse(format!("algorithm {alg:?} isn't accepted (RS256 or ES256)")));
        }
        let iss = claims["iss"].as_str().ok_or_else(|| refuse("no iss"))?;
        // Only the issuers this target binds count, so a token from another trusted issuer can't
        // be tried against keys it has nothing to do with.
        let issuer = self
            .issuers
            .iter()
            .find(|i| i.issuer == iss && bindings.iter().any(|b| b.issuer.trim_end_matches('/') == iss))
            .ok_or_else(|| refuse(format!("issuer {iss} isn't bound to this target")))?;
        let kid = header["kid"].as_str().unwrap_or("").to_string();
        let (key, key_alg) = self.key(issuer, &kid).await?;
        if key_alg.as_deref().is_some_and(|a| a != alg) {
            return Err(refuse(format!("key {kid:?} is for {}, not {alg}", key_alg.unwrap_or_default())));
        }
        verify_signature(&key, alg, format!("{h}.{p}").as_bytes(), &sig)?;

        // Signed by the issuer: now the claims.
        let audience = match issuer.kind {
            Kind::Azure => AZURE_AUDIENCE.to_string(),
            _ => self.audience.clone().ok_or_else(|| refuse("the server has no --oidc-audience"))?,
        };
        let aud_ok = match &claims["aud"] {
            Value::String(a) => a.trim_end_matches('/') == audience,
            Value::Array(a) => a.iter().any(|v| v.as_str().is_some_and(|a| a.trim_end_matches('/') == audience)),
            _ => false,
        };
        if !aud_ok {
            return Err(refuse(format!("the token is for another audience, not {audience}")));
        }
        let exp = claims["exp"].as_i64().ok_or_else(|| refuse("no exp"))?;
        if exp + LEEWAY_SECS <= now {
            return Err(refuse("the token expired"));
        }
        if let Some(nbf) = claims["nbf"].as_i64()
            && nbf - LEEWAY_SECS > now
        {
            return Err(refuse("the token isn't valid yet"));
        }
        let matched = bindings
            .iter()
            .filter(|b| b.issuer.trim_end_matches('/') == iss)
            .any(|b| b.claims.iter().all(|(k, v)| claim_eq(&claims[k.as_str()], v)));
        if !matched {
            return Err(refuse(format!("no binding matches ({})", describe(&claims, issuer.kind))));
        }
        let sub = claims["sub"].as_str().unwrap_or("");
        Ok(Identity {
            owner: format!("oidc:{iss}|{sub}"),
            actor: format!("oidc {iss} {}", describe(&claims, issuer.kind)),
        })
    }

    /// The key `kid` of `issuer`, fetching the JWKS when it is stale or doesn't have it.
    async fn key(&self, issuer: &Issuer, kid: &str) -> Result<(Key, Option<String>), Refused> {
        let lookup = |keys: &Keys| -> Option<(Key, Option<String>)> {
            let fresh = keys.fetched.is_some_and(|t| t.elapsed() < JWKS_TTL);
            if !fresh {
                return None;
            }
            if kid.is_empty() && keys.by_kid.len() == 1 {
                return keys.by_kid.values().next().cloned();
            }
            keys.by_kid.get(kid).cloned()
        };
        {
            let mut map = self.keys.lock().unwrap_or_else(|e| e.into_inner());
            let entry = map.entry(issuer.issuer.clone()).or_default();
            if let Some(k) = lookup(entry) {
                return Ok(k);
            }
            if entry.attempted.is_some_and(|t| t.elapsed() < JWKS_REFETCH) {
                return Err(refuse(format!("no key {kid:?} for {} (fetched recently)", issuer.issuer)));
            }
            entry.attempted = Some(Instant::now());
        }
        let url = issuer.jwks.clone();
        let fetched = tokio::task::spawn_blocking(move || fetch_jwks(&url))
            .await
            .map_err(|e| refuse(format!("JWKS fetch: {e}")))?
            .map_err(|e| refuse(format!("JWKS {}: {e}", issuer.jwks)))?;
        let mut map = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(issuer.issuer.clone()).or_default();
        entry.by_kid = fetched;
        entry.fetched = Some(Instant::now());
        lookup(entry).ok_or_else(|| refuse(format!("no key {kid:?} in the JWKS of {}", issuer.issuer)))
    }
}

/// Claims as the audit log shows them: subject, repository or project, run or pipeline.
fn describe(claims: &Value, kind: Kind) -> String {
    let get = |k: &str| match &claims[k] {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    let mut out = vec![format!("sub={}", get("sub").unwrap_or_default())];
    let extra: &[&str] = match kind {
        Kind::Github => &["repository", "repository_id", "ref", "run_id"],
        Kind::Gitlab => &["project_path", "project_id", "ref", "pipeline_id"],
        Kind::Azure => &[],
    };
    for k in extra {
        if let Some(v) = get(k) {
            out.push(format!("{k}={v}"));
        }
    }
    out.join(" ").chars().filter(|c| !c.is_control()).take(300).collect()
}

/// A claim equals a bound value: strings exactly, numbers and booleans by their JSON text.
fn claim_eq(claim: &Value, want: &str) -> bool {
    match claim {
        Value::String(s) => s == want,
        Value::Number(n) => n.to_string() == want,
        Value::Bool(b) => b.to_string() == want,
        _ => false,
    }
}

fn decode_json(part: &str) -> Option<Value> {
    let bytes = URL_SAFE_NO_PAD.decode(part).ok()?;
    serde_json::from_slice::<Value>(&bytes).ok().filter(Value::is_object)
}

fn verify_signature(key: &Key, alg: &str, message: &[u8], sig: &[u8]) -> Result<(), Refused> {
    let ok = match (key, alg) {
        (Key::Rsa { n, e }, "RS256") => {
            RsaPublicKeyComponents { n, e }.verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, sig).is_ok()
        }
        (Key::P256(point), "ES256") => {
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point).verify(message, sig).is_ok()
        }
        _ => return Err(refuse(format!("the key doesn't fit algorithm {alg}"))),
    };
    if ok { Ok(()) } else { Err(refuse("bad signature")) }
}

/// Reads a JWKS document: RSA and P-256 signing keys, by `kid`.
fn parse_jwks(doc: &Value) -> HashMap<String, (Key, Option<String>)> {
    let mut out = HashMap::new();
    for k in doc["keys"].as_array().into_iter().flatten() {
        if k["use"].as_str().is_some_and(|u| u != "sig") {
            continue;
        }
        let b = |name: &str| k[name].as_str().and_then(|v| URL_SAFE_NO_PAD.decode(v).ok());
        let key = match (k["kty"].as_str(), k["crv"].as_str()) {
            (Some("RSA"), _) => match (b("n"), b("e")) {
                (Some(n), Some(e)) => Key::Rsa { n, e },
                _ => continue,
            },
            (Some("EC"), Some("P-256")) => match (b("x"), b("y")) {
                (Some(x), Some(y)) if x.len() == 32 && y.len() == 32 => Key::P256([&[4u8][..], &x, &y].concat()),
                _ => continue,
            },
            _ => continue,
        };
        let kid = k["kid"].as_str().unwrap_or("").to_string();
        out.insert(kid, (key, k["alg"].as_str().map(String::from)));
    }
    out
}

fn fetch_jwks(url: &str) -> Result<HashMap<String, (Key, Option<String>)>, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into();
    let mut resp = agent.get(url).call().map_err(|e| e.to_string())?;
    if resp.status() != 200 {
        return Err(format!("HTTP {}", resp.status()));
    }
    let doc: Value = resp.body_mut().with_config().limit(MAX_JWKS).read_json().map_err(|e| e.to_string())?;
    let keys = parse_jwks(&doc);
    if keys.is_empty() {
        return Err("no RSA or P-256 signing keys".into());
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
    use serde_json::json;

    fn issuer(kind: Kind, iss: &str) -> Issuer {
        Issuer { kind, issuer: iss.into(), jwks: "http://127.0.0.1:1/jwks".into() }
    }

    fn binding(iss: &str, claims: &[(&str, &str)]) -> Binding {
        Binding { issuer: iss.into(), claims: claims.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() }
    }

    /// A verifier with one ES256 key cached for `iss`, and a signer for it.
    fn setup(kind: Kind, iss: &str) -> (Verifier, impl Fn(Value, Value) -> String) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let v = Verifier::new(vec![issuer(kind, iss)], Some("https://scan.corp.test/".into()));
        let mut keys = Keys { fetched: Some(Instant::now()), ..Keys::default() };
        keys.by_kid.insert("k1".into(), (Key::P256(pair.public_key().as_ref().to_vec()), None));
        v.keys.lock().unwrap().insert(iss.into(), keys);
        let sign = move |header: Value, claims: Value| {
            let h = URL_SAFE_NO_PAD.encode(header.to_string());
            let p = URL_SAFE_NO_PAD.encode(claims.to_string());
            let sig = pair.sign(&SystemRandom::new(), format!("{h}.{p}").as_bytes()).unwrap();
            format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
        };
        (v, sign)
    }

    fn github_claims(now: i64) -> Value {
        json!({"iss": GITHUB_ISSUER, "aud": "https://scan.corp.test", "exp": now + 300, "nbf": now - 5,
               "sub": "repo:acme/shop:ref:refs/heads/main", "repository": "acme/shop",
               "repository_id": "123456", "repository_owner_id": "42", "ref": "refs/heads/main", "run_id": "7"})
    }

    fn run<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
    }

    #[test]
    fn accepts_a_matching_token_and_refuses_the_rest() {
        let now = 1_800_000_000;
        let (v, sign) = setup(Kind::Github, GITHUB_ISSUER);
        let es = json!({"alg": "ES256", "kid": "k1", "typ": "JWT"});
        let b = [binding(GITHUB_ISSUER, &[("repository_id", "123456"), ("ref", "refs/heads/main")])];
        let ok = run(v.verify(&sign(es.clone(), github_claims(now)), &b, now)).unwrap();
        assert_eq!(ok.owner, "oidc:https://token.actions.githubusercontent.com|repo:acme/shop:ref:refs/heads/main");
        assert!(ok.actor.contains("repository_id=123456"));

        let refused = |claims: Value, header: &Value| run(v.verify(&sign(header.clone(), claims), &b, now)).is_err();
        let mut c = github_claims(now);
        c["repository_id"] = json!("999");
        assert!(refused(c, &es), "another repository");
        let mut c = github_claims(now);
        c["ref"] = json!("refs/heads/dev");
        assert!(refused(c, &es), "another branch");
        let mut c = github_claims(now);
        c["aud"] = json!("https://other.test");
        assert!(refused(c, &es), "another audience");
        let mut c = github_claims(now);
        c["exp"] = json!(now - 120);
        assert!(refused(c, &es), "expired");
        let mut c = github_claims(now);
        c["nbf"] = json!(now + 600);
        assert!(refused(c, &es), "not yet valid");
        let mut c = github_claims(now);
        c.as_object_mut().unwrap().remove("exp");
        assert!(refused(c, &es), "no exp");
        assert!(refused(github_claims(now), &json!({"alg": "none", "kid": "k1"})), "alg none");
        assert!(refused(github_claims(now), &json!({"alg": "HS256", "kid": "k1"})), "HMAC");
        assert!(refused(github_claims(now), &json!({"alg": "RS256", "kid": "k1"})), "key type mismatch");
        assert!(refused(github_claims(now), &json!({"alg": "ES256", "kid": "k1", "crit": ["x"]})), "crit");
        assert!(run(v.verify(&sign(es.clone(), github_claims(now)), &[], now)).is_err(), "no bindings");

        // A tampered payload under the old signature.
        let token = sign(es.clone(), github_claims(now));
        let mut c = github_claims(now);
        c["repository_id"] = json!("999");
        let parts: Vec<&str> = token.split('.').collect();
        let forged = format!("{}.{}.{}", parts[0], URL_SAFE_NO_PAD.encode(c.to_string()), parts[2]);
        assert!(run(v.verify(&forged, &[binding(GITHUB_ISSUER, &[("repository_id", "999")])], now)).is_err());

        // Numbers in claims match their text; arrays of audiences work.
        let mut c = github_claims(now);
        c["repository_id"] = json!(123456);
        c["aud"] = json!(["x", "https://scan.corp.test/"]);
        assert!(run(v.verify(&sign(es, c), &b, now)).is_ok());
    }

    #[test]
    fn a_token_from_an_issuer_the_target_does_not_bind_is_refused() {
        let now = 1_800_000_000;
        let (v, sign) = setup(Kind::Gitlab, "https://gitlab.corp.test");
        let mut c = github_claims(now);
        c["iss"] = json!("https://gitlab.corp.test");
        c["project_id"] = json!("5");
        let token = sign(json!({"alg": "ES256", "kid": "k1"}), c);
        let other = [binding(GITHUB_ISSUER, &[("repository_id", "123456")])];
        assert!(run(v.verify(&token, &other, now)).is_err());
        let bound = [binding("https://gitlab.corp.test", &[("project_id", "5")])];
        assert!(run(v.verify(&token, &bound, now)).is_ok());
    }

    #[test]
    fn azure_tokens_carry_the_fixed_audience() {
        let now = 1_800_000_000;
        let iss = "https://vstoken.dev.azure.com/0000-org";
        let (v, sign) = setup(Kind::Azure, iss);
        let claims = json!({"iss": iss, "aud": AZURE_AUDIENCE, "exp": now + 300, "sub": "sc://acme/shop/scan"});
        let b = [binding(iss, &[("sub", "sc://acme/shop/scan")])];
        assert!(run(v.verify(&sign(json!({"alg": "ES256", "kid": "k1"}), claims), &b, now)).is_ok());
    }

    #[test]
    fn rs256_verifies() {
        // A 2048-bit key made once with openssl; the token expires in 2100.
        let (n, e, token) = (RS_N, "AQAB", RS_TOKEN);
        let mut keys = Keys { fetched: Some(Instant::now()), ..Keys::default() };
        let key = Key::Rsa { n: URL_SAFE_NO_PAD.decode(n).unwrap(), e: URL_SAFE_NO_PAD.decode(e).unwrap() };
        keys.by_kid.insert("rs".into(), (key, None));
        let v = Verifier::new(vec![issuer(Kind::Github, GITHUB_ISSUER)], Some("https://scan.corp.test".into()));
        v.keys.lock().unwrap().insert(GITHUB_ISSUER.into(), keys);
        let b = [binding(GITHUB_ISSUER, &[("repository_id", "123456")])];
        assert!(run(v.verify(token, &b, 1_800_000_000)).is_ok());
        let bad = format!("{}x", &token[..token.len() - 1]);
        assert!(run(v.verify(&bad, &b, 1_800_000_000)).is_err());
    }

    #[test]
    fn issuers_and_bindings() {
        let gh = Issuer::parse("github").unwrap();
        assert_eq!(gh.issuer, GITHUB_ISSUER);
        assert_eq!(gh.jwks, "https://token.actions.githubusercontent.com/.well-known/jwks");
        let gl = Issuer::parse("gitlab=https://gitlab.corp.test/").unwrap();
        assert_eq!(gl.jwks, "https://gitlab.corp.test/oauth/discovery/keys");
        assert!(Issuer::parse("azure=https://vstoken.dev.azure.com/x").is_err());
        assert!(Issuer::parse("azure=https://vstoken.dev.azure.com/x,https://vstoken.dev.azure.com/x/keys").is_ok());
        assert!(Issuer::parse("gitlab=http://gitlab.corp.test").is_err());
        assert!(Issuer::parse("gitlab=http://127.0.0.1:8080").is_ok());
        assert!(Issuer::parse("gitlab=http://127.0.0.1.evil.test").is_err());
        assert!(Issuer::parse("jenkins=https://x").is_err());

        let issuers = [gh, gl];
        assert!(check_bindings(&[binding(GITHUB_ISSUER, &[("repository_id", "1")])], &issuers).is_ok());
        assert!(
            check_bindings(&[binding(GITHUB_ISSUER, &[("sub", "repo:a/b:ref:refs/heads/main")])], &issuers).is_err()
        );
        assert!(check_bindings(&[binding("https://gitlab.corp.test", &[("project_id", "5")])], &issuers).is_ok());
        assert!(check_bindings(&[binding("https://elsewhere.test", &[("project_id", "5")])], &issuers).is_err());
        assert!(check_bindings(&[binding(GITHUB_ISSUER, &[("repository_id", "1"), ("aud", "x")])], &issuers).is_err());
    }

    #[test]
    fn jwks_parsing() {
        let doc = json!({"keys": [
            {"kty": "RSA", "kid": "a", "n": "AQAB", "e": "AQAB", "use": "sig"},
            {"kty": "RSA", "kid": "enc", "n": "AQAB", "e": "AQAB", "use": "enc"},
            {"kty": "EC", "crv": "P-384", "kid": "p384", "x": "AA", "y": "AA"},
            {"kty": "oct", "kid": "hmac", "k": "AA"}
        ]});
        let keys = parse_jwks(&doc);
        assert_eq!(keys.keys().collect::<Vec<_>>(), vec!["a"]);
        assert!(looks_like_jwt("eyJhbGciOiJ.eyJ.sig"));
        assert!(!looks_like_jwt("bpt_shop_abc"));
    }

    const RS_N: &str = "3Kr-jlMEbQnriDvvDkDWdSc-oH-Q6fPkRwDoip8KUHu2AZGUWF7ShpV0CbleGy9eWcxVh_XFSm2CqVNh-PQiUZNqLiKNNCzy9aqytEDf-05LAf2eIHKVXbWGnfXQ7vY9gbE3QWi7YKz7aV7xqMFSO4VjUSGXatKvTjcWBbI-oThYwUzB3AF600Fm4cUkh_kc_ZzixEhJLWZ5Q3WMXxHHZxJP-dDS8KiPSnD8q1HAFZxvprB9aciBOjEVrk-WYr19QmtnnFD83ME2P7gR87NayNkNtDxOV_KaU0PUq0VAyr-Yv4_JCfGKtVKdLplQVxcF6AvNofZ3ByDcRj1mlzSQmQ";
    const RS_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InJzIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiaHR0cHM6Ly9zY2FuLmNvcnAudGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwic3ViIjoicmVwbzphY21lL3Nob3A6cmVmOnJlZnMvaGVhZHMvbWFpbiIsInJlcG9zaXRvcnlfaWQiOiIxMjM0NTYifQ.XCfqjWpJ5GE6OJBIDIkVwcFsb8HDa66yqhKQPXoCI81iB4iOETjwj7mTP_IH-UIEA5osOtTSnspv5s2AKuql6DmIvbZvcjFvE4w8u-IxAeCA843YtR0VcOD2x005RMCg9pbqDMtJNg80SYiidTWsVXiKaO6Itb4PkoguyPoKdg2vRyX60wUEOPxMPEgz5D3tNjMM5l_EC_RjEf4lU1DNfghXgVDv9DY7uayqYPOyuZ1FdCg67MDsLtocf4kuAN4wtlQNA4KyaG1D70t5vor6Vzm1GT2W8EG1soVmzbb7jqOt5z6sb8lmixqhurcPStOc0K1R0w14QopW2XkqpJR34Q";
}
