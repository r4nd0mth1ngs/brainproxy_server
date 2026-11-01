//! Targets: what an admin registers (research §4.2, §5.2), the checks on it, and the project the
//! server generates for it or accepts as an upload (§5.3).
//!
//! Everything a run sends to the CLI comes from here; callers only name a target id (§5.4, layer 1).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `[a-z0-9-]{1,32}`, not starting or ending with `-`: used in paths, file names and tokens.
pub fn valid_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-')
}

/// Commit and ref strings from callers: only stored, never passed to the CLI.
pub fn valid_label(s: &str) -> bool {
    (1..=200).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_/".contains(&b))
}

/// An environment variable name a target may use for a secret. Names the CLI or the system reads
/// for itself are refused, so a registration can't steer the child process.
pub fn valid_secret_var(name: &str) -> bool {
    let shape = (1..=64).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && !name.as_bytes()[0].is_ascii_digit();
    let reserved = ["PATH", "HOME", "TZ", "LANG", "SHELL", "USER", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR"];
    shape
        && !reserved.contains(&name)
        && !name.starts_with("BRAINPROXY")
        && !name.starts_with("LD_")
        && !name.starts_with("DYLD_")
        && !name.starts_with("LC_")
        && !name.starts_with("RUST")
        && !name.ends_with("_PROXY")
}

pub const PRESETS: [&str; 3] = ["quick", "standard", "thorough"];
pub const RISKS: [&str; 4] = ["info", "low", "medium", "high"];

pub fn preset_rank(p: &str) -> Option<usize> {
    PRESETS.iter().position(|x| *x == p)
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateConfig {
    /// Fail (exit 5) on findings at or above this risk; none: never fail on findings.
    #[serde(default)]
    pub fail_on: Option<String>,
    /// Count only findings new since the previous passed run.
    #[serde(default)]
    pub new_only: bool,
}

/// A login profile the server creates in a generated project (`auth add`). The password is never
/// in it: only the name of the variable that holds it at run time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSpec {
    pub name: String,
    pub login_url: Option<String>,
    pub login_method: Option<String>,
    pub login_body: Option<String>,
    /// Headers for the login request only ("Name: value"), e.g. a form body's Content-Type.
    #[serde(default)]
    pub login_header: Vec<String>,
    pub username: Option<String>,
    pub password_env: Option<String>,
    pub csrf_url: Option<String>,
    pub csrf_regex: Option<String>,
    pub token_regex: Option<String>,
    pub token_header: Option<String>,
    pub logged_in: Option<String>,
    pub logged_out: Option<String>,
    pub check_url: Option<String>,
}

impl AuthSpec {
    /// `auth add NAME --flag=value ...`. The `=` form keeps a value that starts with `-` a value.
    pub fn argv(&self) -> Vec<String> {
        let mut v = vec!["auth".to_string(), "add".into(), self.name.clone()];
        let flags = [
            ("login-url", &self.login_url),
            ("login-method", &self.login_method),
            ("login-body", &self.login_body),
            ("username", &self.username),
            ("password-env", &self.password_env),
            ("csrf-url", &self.csrf_url),
            ("csrf-regex", &self.csrf_regex),
            ("token-regex", &self.token_regex),
            ("token-header", &self.token_header),
            ("logged-in", &self.logged_in),
            ("logged-out", &self.logged_out),
            ("check-url", &self.check_url),
        ];
        for (flag, value) in flags {
            if let Some(value) = value {
                v.push(format!("--{flag}={value}"));
            }
        }
        for h in &self.login_header {
            v.push(format!("--login-header={h}"));
        }
        v
    }
}

/// Where the target's project comes from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectSource {
    /// The server runs `engagement start` (and `auth add`) from the registration.
    #[default]
    Generate,
    /// An admin uploads a project prepared in the app (`PUT .../project`) before the first run.
    Upload,
}

/// A registered target, as stored and as `POST /v1/targets` takes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    pub id: String,
    pub base_url: String,
    /// Exact hosts or addresses (optionally with a port, or an IPv4 CIDR of /24 or narrower).
    pub scope: Vec<String>,
    #[serde(default = "default_preset")]
    pub preset: String,
    #[serde(default = "default_max_minutes")]
    pub max_minutes: u64,
    #[serde(default)]
    pub rate: Option<u32>,
    #[serde(default)]
    pub gate: GateConfig,
    #[serde(default)]
    pub project: ProjectSource,
    /// For a generated project: the login profile to create.
    #[serde(default)]
    pub auth: Option<AuthSpec>,
    /// For an uploaded project: the profile in it to scan with.
    #[serde(default)]
    pub auth_profile: Option<String>,
    /// Variable the CLI reads (e.g. `--password-env APP_PW`) → the server-side source of its value:
    /// the file `<secrets dir>/<target>/<CLI variable>`, else the server's environment variable.
    #[serde(default)]
    pub secret_env: BTreeMap<String, String>,
}

fn default_preset() -> String {
    "standard".into()
}

fn default_max_minutes() -> u64 {
    60
}

impl TargetConfig {
    /// The profile runs scan with.
    pub fn profile(&self) -> Option<&str> {
        self.auth.as_ref().map(|a| a.name.as_str()).or(self.auth_profile.as_deref())
    }

    /// What callers may see: everything but where the secrets come from.
    pub fn public_json(&self) -> Value {
        let mut v = serde_json::to_value(self).unwrap_or_default();
        if let Some(m) = v.as_object_mut() {
            let names: Vec<&String> = self.secret_env.keys().collect();
            m.insert("secret_env".into(), serde_json::json!(names));
        }
        v
    }

    /// Checks everything that doesn't need the CLI. `allow_loopback` lets a scope name this machine
    /// (for trying the server out locally; never in a deployment).
    pub fn validate(&mut self, allow_loopback: bool) -> Result<(), String> {
        if !valid_id(&self.id) {
            return Err("id must be 1-32 characters of a-z, 0-9 and -, not starting or ending with -".into());
        }
        if self.scope.is_empty() || self.scope.len() > 16 {
            return Err("scope must list 1 to 16 hosts".into());
        }
        let mut entries = Vec::new();
        for s in &self.scope {
            entries.push(ScopeEntry::parse(s, allow_loopback).map_err(|e| format!("scope {s:?}: {e}"))?);
        }
        self.scope = entries.iter().map(ScopeEntry::to_string).collect();
        let (host, port) = url_host_port(&self.base_url)?;
        if !entries.iter().any(|e| e.covers(&host, port)) {
            return Err(format!("base_url's host {host}:{port} is not in scope"));
        }
        if preset_rank(&self.preset).is_none() {
            return Err(format!("preset must be one of {}", PRESETS.join(", ")));
        }
        if !(1..=24 * 60).contains(&self.max_minutes) {
            return Err("max_minutes must be 1 to 1440".into());
        }
        if self.rate.is_some_and(|r| !(1..=10_000).contains(&r)) {
            return Err("rate must be 1 to 10000 requests per second".into());
        }
        if let Some(r) = &self.gate.fail_on
            && !RISKS.contains(&r.as_str())
        {
            return Err(format!("gate.fail_on must be one of {}", RISKS.join(", ")));
        }
        if self.gate.new_only && self.gate.fail_on.is_none() {
            return Err("gate.new_only needs gate.fail_on".into());
        }
        match self.project {
            ProjectSource::Generate if self.auth_profile.is_some() => {
                return Err("auth_profile is for an uploaded project; a generated one takes auth".into());
            }
            ProjectSource::Upload if self.auth.is_some() => {
                return Err("auth is for a generated project; an uploaded one names its profile in auth_profile".into());
            }
            _ => {}
        }
        if let Some(name) = self.profile()
            && !valid_id(name)
        {
            return Err("the auth profile name must be 1-32 characters of a-z, 0-9 and -".into());
        }
        if let Some(a) = &self.auth {
            let texts = [
                &a.login_url,
                &a.login_method,
                &a.login_body,
                &a.username,
                &a.password_env,
                &a.csrf_url,
                &a.csrf_regex,
                &a.token_regex,
                &a.token_header,
                &a.logged_in,
                &a.logged_out,
                &a.check_url,
            ];
            let headers = a.login_header.iter().map(String::as_str);
            if texts.iter().flat_map(|t| t.as_deref()).chain(headers).any(|t| t.len() > 4096 || t.contains('\0'))
                || a.login_header.len() > 16
            {
                return Err("auth values must be under 4 KB".into());
            }
            if let Some(var) = &a.password_env
                && !self.secret_env.contains_key(var)
            {
                return Err(format!("auth.password_env {var} has no entry in secret_env"));
            }
        }
        for (cli_var, source) in &self.secret_env {
            if !valid_secret_var(cli_var) || !valid_secret_var(source) {
                return Err(format!(
                    "secret_env {cli_var} -> {source}: names must be A-Z, 0-9 and _, and not one the CLI or the system uses"
                ));
            }
        }
        if self.secret_env.len() > 16 {
            return Err("at most 16 secret_env entries".into());
        }
        Ok(())
    }
}

/// `scheme://host[:port]/...` → (host, port), lower-cased, brackets kept off IPv6.
pub fn url_host_port(url: &str) -> Result<(String, u16), String> {
    let (scheme, rest) = url.split_once("://").ok_or("base_url must start with http:// or https://")?;
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return Err("base_url must start with http:// or https://".into()),
    };
    if url.len() > 2048 || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("base_url is not a valid URL".into());
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return Err("base_url must not carry a user name or password".into());
    }
    let (host, port) = split_host_port(authority)?;
    if host.is_empty() {
        return Err("base_url has no host".into());
    }
    Ok((host.to_ascii_lowercase(), port.unwrap_or(default_port)))
}

/// `host`, `host:port`, `[v6]`, `[v6]:port`.
fn split_host_port(s: &str) -> Result<(String, Option<u16>), String> {
    let bad_port = |p: &str| -> Result<u16, String> {
        p.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| format!("bad port {p:?}"))
    };
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or("unclosed [")?;
        let port = match after {
            "" => None,
            p => Some(bad_port(p.strip_prefix(':').ok_or("junk after ]")?)?),
        };
        return Ok((host.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Ok((h.to_string(), Some(bad_port(p)?))),
        Some(_) => Err("an IPv6 address needs brackets".into()),
        None => Ok((s.to_string(), None)),
    }
}

/// One scope entry, in the engagement's own syntax.
#[derive(Debug, Clone, PartialEq)]
pub enum ScopeEntry {
    Host { name: String, port: Option<u16> },
    Ip { addr: IpAddr, port: Option<u16> },
    Cidr { net: Ipv4Addr, bits: u8 },
}

impl ScopeEntry {
    /// Exact hosts, addresses and narrow IPv4 networks only (research §5.2): no wildcards, no
    /// loopback, link-local, metadata, unspecified, multicast or broadcast addresses.
    pub fn parse(s: &str, allow_loopback: bool) -> Result<ScopeEntry, String> {
        let s = s.trim().to_ascii_lowercase();
        if s.contains('*') {
            return Err("wildcards aren't allowed; list each host".into());
        }
        if let Some((net, bits)) = s.split_once('/') {
            let net: Ipv4Addr = net.parse().map_err(|_| "a network must be an IPv4 CIDR")?;
            let bits: u8 = bits.parse().map_err(|_| "bad prefix length")?;
            if !(24..=32).contains(&bits) {
                return Err("a network may be /24 at the widest".into());
            }
            let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
            if u32::from(net) & !mask != 0 {
                return Err("the address has bits set beyond the prefix".into());
            }
            check_ip(IpAddr::V4(net), allow_loopback)?;
            return Ok(ScopeEntry::Cidr { net, bits });
        }
        let (host, port) = split_host_port(&s)?;
        if let Ok(addr) = host.parse::<IpAddr>() {
            check_ip(addr, allow_loopback)?;
            return Ok(ScopeEntry::Ip { addr, port });
        }
        let label_ok = |l: &str| {
            (1..=63).contains(&l.len())
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        };
        if host.len() > 253 || !host.split('.').all(label_ok) {
            return Err("not a host name".into());
        }
        if host.split('.').next_back().is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit())) {
            return Err("not a host name or an IPv4 address".into());
        }
        let local = host == "localhost" || host.ends_with(".localhost");
        if local && !allow_loopback {
            return Err("this machine (loopback) can't be a target".into());
        }
        let metadata = ["metadata", "metadata.google.internal", "metadata.azure.com", "instance-data"];
        if metadata.contains(&host.as_str()) || host.ends_with(".internal") && host.starts_with("metadata") {
            return Err("cloud metadata hosts can't be targets".into());
        }
        Ok(ScopeEntry::Host { name: host, port })
    }

    /// The entry allows this exact host and port.
    pub fn covers(&self, host: &str, port: u16) -> bool {
        let port_ok = |p: &Option<u16>| p.is_none_or(|p| p == port);
        match self {
            ScopeEntry::Host { name, port: p } => name == host && port_ok(p),
            ScopeEntry::Ip { addr, port: p } => host.parse::<IpAddr>().is_ok_and(|h| h == *addr) && port_ok(p),
            ScopeEntry::Cidr { net, bits } => host.parse::<Ipv4Addr>().is_ok_and(|h| {
                let mask = u32::MAX.checked_shl(32 - u32::from(*bits)).unwrap_or(0);
                u32::from(h) & mask == u32::from(*net)
            }),
        }
    }
}

impl std::fmt::Display for ScopeEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopeEntry::Host { name, port: None } => write!(f, "{name}"),
            ScopeEntry::Host { name, port: Some(p) } => write!(f, "{name}:{p}"),
            ScopeEntry::Ip { addr: IpAddr::V4(a), port: None } => write!(f, "{a}"),
            ScopeEntry::Ip { addr: IpAddr::V4(a), port: Some(p) } => write!(f, "{a}:{p}"),
            ScopeEntry::Ip { addr: IpAddr::V6(a), port: None } => write!(f, "[{a}]"),
            ScopeEntry::Ip { addr: IpAddr::V6(a), port: Some(p) } => write!(f, "[{a}]:{p}"),
            ScopeEntry::Cidr { net, bits } => write!(f, "{net}/{bits}"),
        }
    }
}

/// Refuses addresses no target may have (loopback unless allowed, link-local, metadata, ...).
pub fn check_ip(addr: IpAddr, allow_loopback: bool) -> Result<(), String> {
    let refused = match addr {
        IpAddr::V4(a) => {
            if a.is_loopback() {
                if allow_loopback {
                    return Ok(());
                }
                Some("loopback")
            } else if a.is_link_local() {
                Some("link-local (cloud metadata)")
            } else if a.is_unspecified() || a.is_broadcast() || a.is_multicast() || a.octets()[0] == 0 {
                Some("not a host address")
            } else {
                None
            }
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return check_ip(IpAddr::V4(v4), allow_loopback);
            }
            let metadata = Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254);
            if a.is_loopback() {
                if allow_loopback {
                    return Ok(());
                }
                Some("loopback")
            } else if a == metadata {
                Some("cloud metadata")
            } else if (a.segments()[0] & 0xffc0) == 0xfe80 {
                Some("link-local")
            } else if a.is_unspecified() || a.is_multicast() {
                Some("not a host address")
            } else {
                None
            }
        }
    };
    match refused {
        Some(why) => Err(format!("{why} addresses can't be targets")),
        None => Ok(()),
    }
}

/// The system scope (§5.4, layer 3): the union of every target's scope, in the shape of
/// `engagement show` that the CLI reads from `BRAINPROXY_SYSTEM_SCOPE`.
pub fn system_scope(targets: &[&TargetConfig]) -> Value {
    let mut include: Vec<&str> = targets.iter().flat_map(|t| t.scope.iter().map(String::as_str)).collect();
    include.sort_unstable();
    include.dedup();
    serde_json::json!({ "name": "brainproxy-server targets", "include": include, "exclude": [] })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(scope: &[&str], url: &str) -> TargetConfig {
        serde_json::from_value(serde_json::json!({"id": "shop-dev", "base_url": url, "scope": scope})).unwrap()
    }

    #[test]
    fn ids_and_labels() {
        assert!(valid_id("shop-dev"));
        assert!(valid_id("a"));
        for bad in ["", "-a", "a-", "A", "a_b", "a/b", "..", &"a".repeat(33)] {
            assert!(!valid_id(bad), "{bad}");
        }
        assert!(valid_label("9f2c1e7"));
        assert!(valid_label("refs/heads/main"));
        assert!(!valid_label("a b"));
        assert!(!valid_label("$(x)"));
        assert!(!valid_label(""));
    }

    #[test]
    fn secret_vars() {
        assert!(valid_secret_var("APP_PW"));
        assert!(valid_secret_var("SHOP_DEV_APP_PW"));
        for bad in
            ["PATH", "HOME", "LD_PRELOAD", "BRAINPROXY_HOME", "BRAINPROXY_SYSTEM_SCOPE", "HTTPS_PROXY", "app", "1X"]
        {
            assert!(!valid_secret_var(bad), "{bad}");
        }
    }

    #[test]
    fn scope_entries() {
        let ok = |s: &str| ScopeEntry::parse(s, false).map(|e| e.to_string());
        assert_eq!(ok("Shop.Dev.Corp.Test:443").unwrap(), "shop.dev.corp.test:443");
        assert_eq!(ok("10.0.0.5").unwrap(), "10.0.0.5");
        assert_eq!(ok("10.0.0.0/24").unwrap(), "10.0.0.0/24");
        assert_eq!(ok("[2001:db8::1]:8443").unwrap(), "[2001:db8::1]:8443");
        for bad in [
            "*.corp.test",
            "*",
            "10.0.0.0/16",
            "0.0.0.0/0",
            "10.0.0.1/24",
            "169.254.169.254",
            "169.254.0.0/24",
            "[fd00:ec2::254]",
            "[fe80::1]",
            "127.0.0.1",
            "localhost:3000",
            "[::1]",
            "[::ffff:127.0.0.1]",
            "0.0.0.0",
            "metadata.google.internal",
            "a b",
            "host:0",
            "host:99999",
            "1.2.3",
        ] {
            assert!(ok(bad).is_err(), "{bad} accepted");
        }
        assert_eq!(ScopeEntry::parse("localhost:3000", true).unwrap().to_string(), "localhost:3000");
        assert_eq!(ScopeEntry::parse("127.0.0.1", true).unwrap().to_string(), "127.0.0.1");
    }

    #[test]
    fn base_url_must_be_in_scope() {
        assert!(config(&["shop.test:443"], "https://shop.test/").validate(false).is_ok());
        assert!(config(&["shop.test"], "http://shop.test:8080/app").validate(false).is_ok());
        assert!(config(&["shop.test:443"], "http://shop.test/").validate(false).is_err());
        assert!(config(&["shop.test"], "https://other.test/").validate(false).is_err());
        assert!(config(&["shop.test"], "https://u:p@shop.test/").validate(false).is_err());
        assert!(config(&["shop.test"], "ftp://shop.test/").validate(false).is_err());
        assert!(config(&["10.0.0.0/24"], "http://10.0.0.7/").validate(false).is_ok());
        assert!(config(&["10.0.0.0/24"], "http://10.0.1.7/").validate(false).is_err());
    }

    #[test]
    fn auth_needs_its_secret_mapped() {
        let mut c = config(&["shop.test"], "https://shop.test/");
        c.auth = Some(AuthSpec {
            name: "app".into(),
            login_url: Some("https://shop.test/login".into()),
            login_method: None,
            login_body: Some("-x".into()),
            login_header: vec![],
            username: Some("ci".into()),
            password_env: Some("APP_PW".into()),
            csrf_url: None,
            csrf_regex: None,
            token_regex: None,
            token_header: None,
            logged_in: None,
            logged_out: None,
            check_url: None,
        });
        assert!(c.validate(false).unwrap_err().contains("secret_env"));
        c.secret_env.insert("APP_PW".into(), "SHOP_DEV_APP_PW".into());
        c.validate(false).unwrap();
        let argv = c.auth.as_ref().unwrap().argv();
        assert!(argv.contains(&"--login-body=-x".to_string()));
        assert!(argv.contains(&"--password-env=APP_PW".to_string()));
        assert!(!c.public_json().to_string().contains("SHOP_DEV_APP_PW"));
    }

    #[test]
    fn unknown_fields_are_refused() {
        let r: Result<TargetConfig, _> = serde_json::from_value(
            serde_json::json!({"id": "a", "base_url": "https://a.test/", "scope": ["a.test"], "crawl_any_port": true}),
        );
        assert!(r.is_err());
    }
}
