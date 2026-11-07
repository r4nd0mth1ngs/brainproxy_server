//! A target's project file and its host, outside of `serve`: creating a project from a target's
//! settings, the checks on a project the server didn't make (an upload or a template, research
//! §5.3), the check that the target's hosts resolve to allowed addresses, and the ownership check.
//! `serve` uses these for registration, uploads and each run; stateless `ci` will use them for its
//! fresh project per run (research/CI-STATELESS.md).

use std::ffi::OsString;
use std::fs::File;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use crate::brainproxy::{self, Cli, code};
use crate::target::{self, AuthSpec, ScopeEntry, TargetConfig};

/// Why a project or a host was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The project or the CLI's answer doesn't fit the target.
    Invalid(String),
    /// Something outside the target's registered scope.
    OutOfScope(String),
    /// The CLI couldn't be run.
    Internal(String),
}

/// Runs a CLI command that must succeed. A failure exiting 6 is out of scope.
async fn cli_ok<I, S>(cli: &Cli, args: I) -> Result<brainproxy::Output, Refused>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let what = args.iter().take(2).map(|a| a.to_string_lossy()).collect::<Vec<_>>().join(" ");
    let out = cli.run(args).await.map_err(|e| Refused::Internal(format!("can't run {}: {e}", cli.bin.display())))?;
    if !out.ok() {
        let message = format!("{what}: {}", out.message());
        return Err(if out.code == code::OUT_OF_SCOPE {
            Refused::OutOfScope(message)
        } else {
            Refused::Invalid(message)
        });
    }
    Ok(out)
}

/// The target's secrets for the CLI's environment: each `secret_env` variable from the file
/// `<secrets_dir>/<target>/<variable>`, else from this process's variable it names.
pub fn secrets(t: &TargetConfig, secrets_dir: &Path) -> Result<Vec<(OsString, OsString)>, String> {
    let mut env = Vec::new();
    for (cli_var, source) in &t.secret_env {
        let file = secrets_dir.join(&t.id).join(cli_var);
        let value = match std::fs::read_to_string(&file) {
            Ok(v) => OsString::from(v.trim_end_matches(['\r', '\n'])),
            Err(_) => std::env::var_os(source).ok_or_else(|| {
                // Where secrets come from stays in the server log, not in what read tokens see.
                eprintln!(
                    "brainproxy-server: secret {cli_var} of target {} isn't set: no file {} and no variable {source}",
                    t.id,
                    file.display()
                );
                format!("secret {cli_var} of target {} isn't set on the server (see its log)", t.id)
            })?,
        };
        env.push((cli_var.into(), value));
    }
    Ok(env)
}

/// Starts the engagement for `t` in `cli`'s project (which must not exist yet): its scope entries,
/// named after the target, then the login profile `auth` if given.
pub async fn create(cli: &Cli, t: &TargetConfig, auth: Option<&AuthSpec>) -> Result<(), Refused> {
    let mut argv = vec!["engagement".to_string(), "start".into()];
    for s in &t.scope {
        argv.push(format!("--target={s}"));
    }
    argv.push(format!("--name={}", t.id));
    cli_ok(cli, &argv).await?;
    if let Some(a) = auth {
        cli_ok(cli, &a.argv()).await?;
    }
    Ok(())
}

/// What a vetted project holds.
#[derive(Debug)]
pub struct Vetted {
    /// The engagement's scope entries, as `engagement show` gives them.
    pub scope: Value,
    /// Its login profiles.
    pub profiles: Vec<String>,
}

/// The checks on a project the server didn't make, run on `cli`'s project: a brainproxy project
/// with an engagement scope inside the target's registered one, no upstream proxies, no connection
/// settings but host overrides to scoped addresses, no password stored in it, and the profile the
/// target scans with.
pub async fn vet(cli: &Cli, t: &TargetConfig, allow_loopback: bool) -> Result<Vetted, Refused> {
    let mut magic = [0u8; 16];
    use std::io::Read;
    let is_sqlite =
        File::open(&cli.project).and_then(|mut f| f.read_exact(&mut magic)).is_ok() && &magic == b"SQLite format 3\0";
    if !is_sqlite {
        return Err(Refused::Invalid("the upload is not a brainproxy project (SQLite) file".into()));
    }
    let eng = cli_ok(cli, ["engagement", "show"]).await?;
    let e = &eng.data()["engagement"];
    if e.is_null() {
        return Err(Refused::Invalid("the project has no engagement scope".into()));
    }
    let allowed: Vec<String> = t.scope.clone();
    for inc in e["include"].as_array().into_iter().flatten() {
        let s = inc.as_str().unwrap_or_default();
        let norm = ScopeEntry::parse(s, allow_loopback).map(|x| x.to_string());
        if !norm.as_ref().is_ok_and(|n| allowed.contains(n)) {
            return Err(Refused::OutOfScope(format!(
                "the project's scope includes {s}, which isn't in the target's registered scope ({})",
                allowed.join(", ")
            )));
        }
    }
    if eng.data()["engagement_proxies"].as_array().is_some_and(|p| !p.is_empty()) {
        return Err(Refused::Invalid("the project allows upstream proxies; the server doesn't accept those".into()));
    }
    // Connection settings the CLI applies on top of the scope: an upstream proxy (allowed on
    // loopback by the CLI) or a host override to an address the scope doesn't list would send
    // the scan somewhere the registration never named.
    let conn = cli_ok(cli, ["connection", "show"]).await?;
    let c = conn.data();
    // An allowlist: host overrides (checked below) and nothing else, including keys a later CLI
    // may add. Client certificates are file paths read on the server, which could name another
    // target's secret files.
    for (key, value) in c.as_object().into_iter().flatten() {
        let empty = value.as_array().is_some_and(Vec::is_empty);
        if !matches!(key.as_str(), "hosts" | "warnings" | "note") && !empty && !value.is_null() {
            return Err(Refused::Invalid(format!(
                "the project has connection settings the server doesn't accept (`connection {key}`); \
                 only host overrides to addresses in the scope"
            )));
        }
    }
    let entries: Vec<ScopeEntry> = t.scope.iter().filter_map(|s| ScopeEntry::parse(s, allow_loopback).ok()).collect();
    for h in c["hosts"].as_array().into_iter().flatten() {
        let ip_text = h["ip"].as_str().unwrap_or_default();
        let listed = ip_text
            .parse::<IpAddr>()
            .ok()
            .filter(|ip| target::check_ip(*ip, allow_loopback).is_ok() && entries.iter().any(|e| e.covers_addr(*ip)));
        if listed.is_none() {
            return Err(Refused::OutOfScope(format!(
                "the project maps {} to {ip_text}, an address the target's scope doesn't list",
                h["host"].as_str().unwrap_or("?")
            )));
        }
    }
    let profiles = cli_ok(cli, ["auth", "list"]).await?;
    let mut names = Vec::new();
    for p in profiles.data()["profiles"].as_array().into_iter().flatten() {
        let name = p["name"].as_str().unwrap_or_default().to_string();
        let shown = cli_ok(cli, ["auth", "show", &name]).await?;
        if !shown.data()["profile"]["password"]["literal"].is_null() {
            return Err(Refused::Invalid(format!(
                "auth profile {name} stores its password in the project; use --password-env and the target's secret_env"
            )));
        }
        names.push(name);
    }
    if let Some(p) = t.profile()
        && !names.iter().any(|n| n == p)
    {
        return Err(Refused::Invalid(format!("the project has no auth profile {p}")));
    }
    Ok(Vetted { scope: e["include"].clone(), profiles: names })
}

/// `engagement check` of the base URL's host and every other host name in the scope: allowed,
/// and not resolving to this machine or a link-local address (a registered name pointed at the
/// server itself would reach its admin port). Returns the base URL host's addresses, as the CLI
/// resolves it (host overrides included). DNS can change after registration: `serve` runs this
/// before each scan.
pub async fn check_host(cli: &Cli, t: &TargetConfig, allow_loopback: bool) -> Result<Vec<IpAddr>, (i32, String)> {
    let (host, port) = target::url_host_port(&t.base_url).map_err(|e| (code::USAGE, e))?;
    let base = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let mut names = vec![(base, true)];
    for s in &t.scope {
        if let Ok(ScopeEntry::Host { name, port }) = ScopeEntry::parse(s, true) {
            names.push((format!("{name}:{}", port.unwrap_or(443)), false));
        }
    }
    let mut base_addrs = Vec::new();
    for (name, must_be_allowed) in names {
        let out = cli
            .run(["engagement", "check", &name])
            .await
            .map_err(|e| (code::ERROR, format!("can't run {}: {e}", cli.bin.display())))?;
        if !out.ok() {
            let c = if out.code == code::OK { code::ERROR } else { out.code };
            return Err((c, format!("engagement check: {}", out.message())));
        }
        let result = &out.data()["results"][0];
        if must_be_allowed && result["allowed"] != true {
            let why = result["reason"].as_str().unwrap_or("not allowed");
            return Err((code::OUT_OF_SCOPE, format!("{name}: {why}")));
        }
        for a in result["addresses"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            let Ok(ip) = a.parse::<IpAddr>() else { continue };
            if let Err(e) = target::check_ip(ip, allow_loopback) {
                return Err((code::OUT_OF_SCOPE, format!("{name} resolves to {ip}: {e}")));
            }
            if must_be_allowed {
                base_addrs.push(ip);
            }
        }
    }
    Ok(base_addrs)
}

/// Fetches `/.well-known/brainproxy-<id>.txt` from the target's origin and looks for its token.
/// It connects only to `addrs`, the addresses [`check_host`] just vetted, so a name resolving
/// elsewhere a moment later can't send the request anywhere else.
pub async fn check_ownership(t: &TargetConfig, addrs: Vec<IpAddr>) -> Result<(), String> {
    let Some(token) = t.ownership_token.clone() else { return Err("ownership is on but has no token".into()) };
    let (host, port) = target::url_host_port(&t.base_url)?;
    let scheme = if t.base_url.starts_with("https://") { "https" } else { "http" };
    let host = if host.contains(':') { format!("[{host}]") } else { host };
    let url = format!("{scheme}://{host}:{port}/.well-known/brainproxy-{}.txt", t.id);
    let shown = url.clone();
    if addrs.is_empty() {
        return Err(format!("{} resolved to no addresses", t.base_url));
    }
    let pinned: Vec<SocketAddr> = addrs.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();
    let body = tokio::task::spawn_blocking(move || fetch_small(&url, pinned)).await.map_err(|e| e.to_string())??;
    if body.lines().any(|l| l.trim() == token) {
        Ok(())
    } else {
        Err(format!("{shown} doesn't hold this target's ownership token"))
    }
}

/// GETs a small text file over HTTP(S): no redirects, 10 s, 4 KB. Certificates aren't checked:
/// dev instances often have self-signed ones, nothing secret is sent, and the ownership check
/// guards against typos, not attackers.
/// It connects only to `addrs`, never through a proxy.
fn fetch_small(url: &str, addrs: Vec<SocketAddr>) -> Result<String, String> {
    let tls = ureq::tls::TlsConfig::builder().disable_verification(true).build();
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .max_redirects(0)
        .http_status_as_error(false)
        .proxy(None)
        .tls_config(tls)
        .build();
    let agent = ureq::Agent::with_parts(config, ureq::unversioned::transport::DefaultConnector::new(), Pinned(addrs));
    let mut resp = agent.get(url).call().map_err(|e| format!("{url}: {e}"))?;
    if resp.status() != 200 {
        return Err(format!("{url}: HTTP {}", resp.status()));
    }
    resp.body_mut().with_config().limit(4096).read_to_string().map_err(|e| format!("{url}: {e}"))
}

/// A resolver that answers every name with the addresses it was given.
#[derive(Debug)]
struct Pinned(Vec<SocketAddr>);

impl ureq::unversioned::resolver::Resolver for Pinned {
    fn resolve(
        &self,
        _uri: &axum::http::Uri,
        _config: &ureq::config::Config,
        _timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let mut out = self.empty();
        for a in self.0.iter().take(16) {
            out.push(*a);
        }
        if out.is_empty() { Err(ureq::Error::HostNotFound) } else { Ok(out) }
    }
}
