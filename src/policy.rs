//! Alert policies: what the gate does with each rule, in the style of ZAP's baseline rules file
//! (PLAN.md phase 3).
//!
//! A rule is a check id such as `10020`, or one variant of it such as `10020-1`; the variant wins
//! over the id. `ignore` leaves the rule out of the gate, `warn` lists it without failing, and
//! `fail` fails the gate whatever the finding's risk. Rules not in the policy follow the gate's
//! `fail_on`. Reports still list every finding: a policy only changes the verdict.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::record::{Gate, PolicyResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Ignore,
    Warn,
    Fail,
}

pub type Policy = BTreeMap<String, Action>;

pub const MAX_RULES: usize = 500;

/// A rule id: digits, optionally `-` and the variant's digits.
pub fn valid_rule(rule: &str) -> bool {
    let (id, variant) = rule.split_once('-').unwrap_or((rule, "1"));
    let digits = |s: &str| (1..=10).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit());
    digits(id) && digits(variant)
}

pub fn check(policy: &Policy) -> Result<(), String> {
    if policy.len() > MAX_RULES {
        return Err(format!("policy: at most {MAX_RULES} rules"));
    }
    match policy.keys().find(|r| !valid_rule(r)) {
        Some(r) => Err(format!("policy: {r:?} isn't a rule id (digits, optionally -variant, e.g. 10020 or 10020-1)")),
        None => Ok(()),
    }
}

/// Reads a policy file: a JSON object (`{"10020": "ignore"}`), or ZAP's rules file format, a line
/// per rule of `ID<tab>IGNORE|WARN|FAIL<tab>(name)`, with `#` comments.
pub fn load(path: &Path) -> Result<Policy, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn parse(text: &str) -> Result<Policy, String> {
    let policy: Policy = if text.trim_start().starts_with('{') {
        serde_json::from_str(text).map_err(|e| e.to_string())?
    } else {
        let mut p = Policy::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split('\t').map(str::trim);
            let (Some(rule), Some(action)) = (fields.next(), fields.next()) else {
                return Err(format!("line {}: expected ID<tab>IGNORE|WARN|FAIL", n + 1));
            };
            let action = match action.to_ascii_uppercase().as_str() {
                "IGNORE" => Action::Ignore,
                "WARN" => Action::Warn,
                "FAIL" => Action::Fail,
                other => return Err(format!("line {}: {other:?} isn't IGNORE, WARN or FAIL", n + 1)),
            };
            p.insert(rule.to_string(), action);
        }
        p
    };
    check(&policy)?;
    Ok(policy)
}

/// A short, stable fingerprint of a policy, so a run can tell whether an earlier one was gated
/// under the same rules.
pub fn fingerprint(policy: &Policy) -> Option<String> {
    use sha2::{Digest, Sha256};
    if policy.is_empty() {
        return None;
    }
    let text = serde_json::to_string(policy).unwrap_or_default();
    let digest = Sha256::digest(text.as_bytes());
    Some(digest.iter().take(8).map(|b| format!("{b:02x}")).collect())
}

const RISKS: [&str; 4] = ["info", "low", "medium", "high"];

fn risk_rank(r: &str) -> Option<usize> {
    RISKS.iter().position(|x| x.eq_ignore_ascii_case(r))
}

/// What the policy says for an alert: its variant (`10020-1`) first, then its id (`10020`).
fn action_for<'a>(policy: &'a Policy, alert_ref: &str) -> Option<&'a Action> {
    policy.get(alert_ref).or_else(|| alert_ref.split_once('-').and_then(|(id, _)| policy.get(id)))
}

/// The gate over `findings compare` output (its `new` and `unchanged` lists), under `policy`.
pub fn gate(compare: &Value, fail_on: Option<&str>, new_only: bool, policy: &Policy) -> Gate {
    let threshold = fail_on.and_then(risk_rank);
    let mut lists = vec![&compare["new"]];
    if !new_only {
        lists.push(&compare["unchanged"]);
    }
    let mut result = PolicyResult::default();
    let mut count = 0;
    for f in lists.into_iter().filter_map(Value::as_array).flatten() {
        let alert_ref = f["alert_ref"].as_str().unwrap_or("");
        let by_risk = threshold.is_some_and(|t| f["risk"].as_str().and_then(risk_rank).is_some_and(|r| r >= t));
        let label = || {
            format!(
                "{alert_ref} {} ({}) {}",
                f["name"].as_str().unwrap_or("?"),
                f["risk"].as_str().unwrap_or("?"),
                f["url"].as_str().unwrap_or("")
            )
        };
        match action_for(policy, alert_ref) {
            Some(Action::Ignore) => result.ignored += 1,
            Some(Action::Warn) => {
                result.warned += 1;
                if result.warnings.len() < 20 {
                    result.warnings.push(label());
                }
            }
            Some(Action::Fail) => {
                count += 1;
                if !by_risk {
                    result.forced += 1;
                }
            }
            None if by_risk => count += 1,
            None => {}
        }
    }
    Gate { fail_on: fail_on.unwrap_or("").to_string(), new_only, passed: count == 0, count, policy: Some(result) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn finding(alert_ref: &str, risk: &str) -> Value {
        json!({"alert_ref": alert_ref, "name": "n", "risk": risk, "url": "http://x/"})
    }

    #[test]
    fn rules_files() {
        let zap = "# ZAP style\n10020\tIGNORE\t(Missing Anti-clickjacking Header)\n10038-1\twarn\n40012\tFAIL\n";
        let p = parse(zap).unwrap();
        assert_eq!(p["10020"], Action::Ignore);
        assert_eq!(p["10038-1"], Action::Warn);
        assert_eq!(p["40012"], Action::Fail);
        assert_eq!(parse(r#"{"10020": "warn"}"#).unwrap()["10020"], Action::Warn);
        assert!(parse("10020 IGNORE").is_err(), "fields are tab-separated");
        assert!(parse("abc\tIGNORE").is_err());
        assert!(parse("10020\tSKIP").is_err());
        assert!(parse(r#"{"10020": "drop"}"#).is_err());
        assert!(fingerprint(&p).is_some());
        assert_eq!(fingerprint(&Policy::new()), None);
    }

    #[test]
    fn the_gate_under_a_policy() {
        let cmp = json!({
            "new": [finding("10020-1", "medium"), finding("40018", "high"), finding("90022", "low")],
            "unchanged": [finding("10038", "high"), finding("10021", "low")]
        });
        let none = Policy::new();
        let g = gate(&cmp, Some("high"), false, &none);
        assert_eq!((g.passed, g.count), (false, 2));
        assert_eq!(gate(&cmp, Some("high"), true, &none).count, 1);
        assert_eq!(gate(&cmp, None, false, &none).count, 0);

        let p = parse("40018\tIGNORE\n10038\tWARN\n10021\tFAIL\n10020-2\tFAIL\n").unwrap();
        let g = gate(&cmp, Some("high"), false, &p);
        assert_eq!((g.passed, g.count), (false, 1), "10021 fails by rule");
        let r = g.policy.unwrap();
        assert_eq!((r.ignored, r.warned, r.forced), (1, 1, 1));
        assert_eq!(r.warnings.len(), 1);

        let p = parse("40018\tIGNORE\n").unwrap();
        assert!(gate(&cmp, Some("high"), true, &p).passed);
        // The variant wins over the id.
        let p = parse("10020\tFAIL\n10020-1\tIGNORE\n").unwrap();
        assert!(gate(&json!({"new": [finding("10020-1", "medium")]}), None, false, &p).passed);
        assert!(!gate(&json!({"new": [finding("10020-2", "medium")]}), None, false, &p).passed);
    }
}
