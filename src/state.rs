//! The state stateless `ci` carries between runs (research/CI-STATELESS.md): `state.json`, the
//! findings known from earlier runs (`known.json`, a `report json`), and an optional HMAC of
//! `state.json` (`state.sig`). Whoever runs `ci` moves the folder between runs; this module only
//! reads one and writes the next.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::target::{self, ScopeEntry};

pub const SCHEMA: u32 = 1;
pub const STATE_FILE: &str = "state.json";
pub const KNOWN_FILE: &str = "known.json";
pub const SIG_FILE: &str = "state.sig";
/// The shortest `--state-key-env` key accepted.
pub const MIN_KEY_LEN: usize = 32;

/// `state.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub schema: u32,
    pub target: String,
    pub generation: u64,
    #[serde(default)]
    pub known: Option<Known>,
    #[serde(default)]
    pub coverage: Option<CoverageState>,
}

/// The run that last replaced the known set, with the settings it ran under: a later run uses
/// the set only if that run would be its `--since-scan` run (`record::since_scan_candidates`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Known {
    /// The run folder's name.
    pub run: String,
    pub finished_at: String,
    pub url: String,
    pub preset: String,
    pub auth: Option<String>,
    pub fail_on: Option<String>,
    pub new_only: bool,
    pub policy: Option<String>,
    pub baseline: bool,
    pub file: String,
    pub sha256: String,
}

/// The coverage of the last run whose scan completed (`record::coverage_candidates`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageState {
    pub run: String,
    pub job: u64,
    pub url: String,
    pub preset: String,
    pub targets: u64,
    pub endpoints: u64,
    pub requests: u64,
}

/// A state folder as read: `None` state on a first run (an empty or missing folder).
#[derive(Debug)]
pub struct Loaded {
    pub state: Option<State>,
    /// `known.json`, checked against its hash.
    pub known: Option<Vec<u8>>,
}

/// Reads and checks a state folder. Anything present but unreadable, or not matching, is an
/// error: a broken state must never turn into a first run, where every finding is new again.
pub fn read(dir: &Path, target: &str, key: Option<&[u8]>, expect: Option<u64>) -> Result<Loaded, String> {
    let entries: Vec<String> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with('.'))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
        Err(e) => return Err(format!("--state {}: {e}", dir.display())),
    };
    if entries.is_empty() {
        // With the wrapper's pointer: a first run only where it says so, so deleting the state
        // can't reset the coverage baseline.
        if let Some(n) = expect.filter(|n| *n != 0) {
            return Err(format!("--state {} is empty, but --expect-generation is {n}", dir.display()));
        }
        return Ok(Loaded { state: None, known: None });
    }
    let path = dir.join(STATE_FILE);
    let bytes = std::fs::read(&path).map_err(|e| {
        format!("--state {}: no readable {STATE_FILE} ({e}), but the folder isn't empty", dir.display())
    })?;
    match (key, std::fs::read(dir.join(SIG_FILE))) {
        (Some(key), Ok(sig)) => {
            let sig = hex_decode(String::from_utf8_lossy(&sig).trim())
                .ok_or_else(|| format!("{SIG_FILE} isn't a hex HMAC"))?;
            hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, key), &bytes, &sig)
                .map_err(|_| format!("{SIG_FILE} doesn't match {STATE_FILE}: changed, or signed with another key"))?;
        }
        (Some(_), Err(_)) => return Err(format!("--state-key-env is given but the state has no {SIG_FILE}")),
        (None, Ok(_)) => return Err(format!("the state is signed ({SIG_FILE}); give --state-key-env")),
        (None, Err(_)) => {}
    }
    let state: State = serde_json::from_slice(&bytes).map_err(|e| format!("{STATE_FILE}: {e}"))?;
    if state.schema != SCHEMA {
        return Err(format!("{STATE_FILE} has schema {}; this server reads {SCHEMA}", state.schema));
    }
    if state.target != target {
        return Err(format!("{STATE_FILE} is target {:?}'s, not {target:?}'s", state.target));
    }
    // An older state, signed or not, mustn't be replayed: its known set may hold a finding fixed since.
    if let Some(n) = expect
        && n != state.generation
    {
        return Err(format!("{STATE_FILE} is generation {}, not {n} (--expect-generation)", state.generation));
    }
    let known = match &state.known {
        None => None,
        Some(k) => {
            if k.file != KNOWN_FILE {
                return Err(format!("{STATE_FILE}: known.file must be {KNOWN_FILE}"));
            }
            let bytes = std::fs::read(dir.join(KNOWN_FILE)).map_err(|e| format!("{KNOWN_FILE}: {e}"))?;
            if sha256_hex(&bytes) != k.sha256 {
                return Err(format!("{KNOWN_FILE} doesn't match the SHA-256 in {STATE_FILE}"));
            }
            Some(bytes)
        }
    };
    Ok(Loaded { state: Some(state), known })
}

/// Writes `state` and `known` (when it has a known set) to `dir`, and `state.sig` with `key`.
pub fn write(dir: &Path, state: &State, known: Option<&[u8]>, key: Option<&[u8]>) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    if let Some(k) = known {
        std::fs::write(dir.join(KNOWN_FILE), k)?;
    }
    let bytes = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
    std::fs::write(dir.join(STATE_FILE), &bytes)?;
    if let Some(key) = key {
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), &bytes);
        std::fs::write(dir.join(SIG_FILE), hex_encode(tag.as_ref()))?;
    }
    Ok(())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// The identity findings match by in `findings compare` (the CLI's `dedupe_key`).
fn key(alert_ref: &str, i: &Value) -> String {
    let s = |k: &str| i[k].as_str().unwrap_or_default().to_string();
    let url = s("url");
    let base = url.split('?').next().unwrap_or(&url).to_string();
    format!("{alert_ref}|{}|{base}|{}", s("method"), s("param"))
}

/// Keys of the findings a `findings compare` list names (its `fixed` list).
pub fn keys_of(list: &Value) -> HashSet<String> {
    list.as_array().into_iter().flatten().map(|f| key(f["alert_ref"].as_str().unwrap_or_default(), f)).collect()
}

/// The next known set, as a `report json`: everything `found` (this run's findings) holds,
/// plus each instance of `used` (the known set this run compared against) that `found` doesn't
/// have, isn't in `fixed`, isn't a removed tombstone, and is on a host and port `scope` still
/// covers. An instance of `used` goes under `found`'s alert of the same `alert_ref` when there is
/// one, else its own alert (with its `rule_id`) is kept. False-positive marks aren't kept: the
/// suppressions list is their only source, so a finding taken off it opens again. Returns the set
/// and how many instances of `used` were dropped for being out of scope.
pub fn carry_forward(found: &Value, used: Option<&Value>, fixed: &HashSet<String>, scope: &[String]) -> (Value, usize) {
    let mut out = found.clone();
    let entries: Vec<ScopeEntry> = scope.iter().filter_map(|s| ScopeEntry::parse(s, true).ok()).collect();
    let in_scope =
        |url: &str| target::url_host_port(url).is_ok_and(|(host, port)| entries.iter().any(|e| e.covers(&host, port)));
    let mut alerts: Vec<Value> = out["alerts"].as_array().cloned().unwrap_or_default();
    let mut seen: HashSet<String> = HashSet::new();
    let mut by_ref: HashMap<String, usize> = HashMap::new();
    for (n, a) in alerts.iter().enumerate() {
        let r = a["alert_ref"].as_str().unwrap_or_default().to_string();
        for i in a["instances"].as_array().into_iter().flatten() {
            seen.insert(key(&r, i));
        }
        by_ref.entry(r).or_insert(n);
    }
    let mut dropped = 0;
    for a in used.and_then(|u| u["alerts"].as_array()).into_iter().flatten() {
        let r = a["alert_ref"].as_str().unwrap_or_default().to_string();
        let mut kept = Vec::new();
        for i in a["instances"].as_array().into_iter().flatten() {
            let k = key(&r, i);
            if i["state"] == "removed" || fixed.contains(&k) || !seen.insert(k) {
                continue;
            }
            if !in_scope(i["url"].as_str().unwrap_or_default()) {
                dropped += 1;
                continue;
            }
            kept.push(i.clone());
        }
        if kept.is_empty() {
            continue;
        }
        match by_ref.get(&r) {
            Some(&n) => {
                if let Some(list) = alerts[n]["instances"].as_array_mut() {
                    list.extend(kept);
                }
            }
            None => {
                let mut alert = a.clone();
                alert["instances"] = Value::Array(kept);
                by_ref.insert(r, alerts.len());
                alerts.push(alert);
            }
        }
    }
    for i in alerts.iter_mut().flat_map(|a| a["instances"].as_array_mut().into_iter().flatten()) {
        if i["state"] == "false_positive" {
            i["state"] = json!("open");
        }
    }
    let total: usize = alerts.iter().map(|a| a["instances"].as_array().map_or(0, Vec::len)).sum();
    out["alerts"] = Value::Array(alerts);
    if !out["filters"].is_object() {
        out["filters"] = json!({});
    }
    out["filters"]["state"] = json!("all");
    if !out["summary"].is_object() {
        out["summary"] = json!({});
    }
    out["summary"]["truncated"] = json!(false);
    out["summary"]["total"] = json!(total);
    out["summary"]["included"] = json!(total);
    out["summary"]["alert_types"] = json!(out["alerts"].as_array().map_or(0, Vec::len));
    (out, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(alerts: Value) -> Value {
        json!({"filters": {"state": "all"}, "summary": {"truncated": false}, "alerts": alerts})
    }

    fn inst(url: &str, state: &str) -> Value {
        json!({"url": url, "method": "GET", "param": "", "state": state, "risk": "low", "confidence": "medium", "source": "active"})
    }

    fn urls(r: &Value) -> Vec<String> {
        let mut v: Vec<String> = r["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|a| {
                let r = a["alert_ref"].as_str().unwrap().to_string();
                a["instances"].as_array().unwrap().iter().map(move |i| format!("{r} {}", i["url"].as_str().unwrap()))
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn carry_forward_keeps_what_the_scan_missed_and_drops_what_it_fixed() {
        let found =
            report(json!([{"alert_ref": "1", "rule_id": 1, "instances": [inst("https://a.test/x?q=1", "open")]}]));
        let used = report(json!([
            {"alert_ref": "1", "rule_id": 1, "instances": [inst("https://a.test/x?q=2", "false_positive"), inst("https://a.test/flaky", "open")]},
            {"alert_ref": "2", "rule_id": 2, "instances": [inst("https://a.test/fixed", "open"), inst("https://a.test/kept", "open")]},
            {"alert_ref": "3", "rule_id": 3, "instances": [inst("https://gone.test/", "open"), inst("https://a.test/rm", "removed")]},
        ]));
        let fixed = keys_of(&json!([{"alert_ref": "2", "url": "https://a.test/fixed", "method": "GET", "param": ""}]));
        let (next, dropped) = carry_forward(&found, Some(&used), &fixed, &["a.test".to_string()]);
        // The same finding found again (query aside) is this run's; the flaky one stays; the fixed
        // one and the tombstone go; the one on a host the scope dropped goes.
        assert_eq!(urls(&next), ["1 https://a.test/flaky", "1 https://a.test/x?q=1", "2 https://a.test/kept"]);
        // No false-positive mark is carried: the suppressions list is their only source.
        assert!(!next.to_string().contains("false_positive"));
        assert_eq!(dropped, 1);
        // An alert only the known set had keeps its rule id, so a later scan can still cover it.
        let two = next["alerts"].as_array().unwrap().iter().find(|a| a["alert_ref"] == "2").unwrap();
        assert_eq!(two["rule_id"], 2);
        assert_eq!(next["summary"]["truncated"], false);
        assert_eq!(next["summary"]["total"], 3);
        assert_eq!(next["filters"]["state"], "all");
    }

    #[test]
    fn a_first_pass_is_what_it_found() {
        let found = report(json!([{"alert_ref": "1", "instances": [inst("https://a.test/", "open")]}]));
        let (next, _) = carry_forward(&found, None, &HashSet::new(), &["a.test".to_string()]);
        assert_eq!(urls(&next), ["1 https://a.test/"]);
    }

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("bps-state-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn state(known: Option<&[u8]>) -> State {
        State {
            schema: SCHEMA,
            target: "shop".into(),
            generation: 3,
            known: known.map(|k| Known {
                run: "r".into(),
                finished_at: "t".into(),
                url: "https://a.test/".into(),
                preset: "standard".into(),
                auth: None,
                fail_on: Some("high".into()),
                new_only: true,
                policy: None,
                baseline: false,
                file: KNOWN_FILE.into(),
                sha256: sha256_hex(k),
            }),
            coverage: None,
        }
    }

    #[test]
    fn hex_is_hex_digits_only() {
        assert_eq!(hex_decode("0aff"), Some(vec![0x0a, 0xff]));
        assert!(hex_decode("+a").is_none());
        assert!(hex_decode("abc").is_none());
    }

    #[test]
    fn state_round_trip_and_refusals() {
        let key = b"0123456789abcdef0123456789abcdef";
        let d = dir("rt");
        // Missing and empty folders are a first run.
        assert!(read(&d, "shop", None, None).unwrap().state.is_none());
        std::fs::create_dir_all(&d).unwrap();
        assert!(read(&d, "shop", None, Some(0)).unwrap().state.is_none());
        assert!(read(&d, "shop", None, Some(2)).unwrap_err().contains("empty"));

        write(&d, &state(Some(b"{}")), Some(b"{}"), Some(key)).unwrap();
        let l = read(&d, "shop", Some(key), Some(3)).unwrap();
        assert!(read(&d, "shop", Some(key), Some(4)).unwrap_err().contains("generation 3"));
        assert_eq!(l.state.unwrap().generation, 3);
        assert_eq!(l.known.as_deref(), Some(&b"{}"[..]));

        assert!(read(&d, "other", Some(key), None).unwrap_err().contains("target"));
        assert!(read(&d, "shop", None, None).unwrap_err().contains("signed"));
        assert!(
            read(&d, "shop", Some(b"another key, also 32 characters!"), None).unwrap_err().contains("doesn't match")
        );
        std::fs::write(d.join(KNOWN_FILE), b"{ }").unwrap();
        assert!(read(&d, "shop", Some(key), None).unwrap_err().contains("SHA-256"));
        std::fs::remove_file(d.join(SIG_FILE)).unwrap();
        assert!(read(&d, "shop", Some(key), None).unwrap_err().contains("no state.sig"));
        std::fs::write(d.join(STATE_FILE), b"{").unwrap();
        assert!(read(&d, "shop", None, None).is_err());
        std::fs::remove_file(d.join(STATE_FILE)).unwrap();
        // Something else in the folder, but no state.json: not a first run.
        assert!(read(&d, "shop", None, None).unwrap_err().contains("isn't empty"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
