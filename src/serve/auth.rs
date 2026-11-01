//! Credentials and rate limits (research §5.1, §5.8).
//!
//! Target tokens are `bpt_<target>_<52 base32 characters>` (32 random bytes); only their SHA-256 is
//! stored, and a token is found by that hash. The admin token comes from a file.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

pub const TOKEN_PREFIX: &str = "bpt_";

/// Days a new token lives unless the request says otherwise.
pub const DEFAULT_TOKEN_DAYS: u64 = 180;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("the system random number generator failed");
    b
}

/// RFC 4648 base32, lower case, no padding.
pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// A new token for `target`: (the token, shown once; its hash, stored).
pub fn new_token(target: &str) -> (String, [u8; 32]) {
    let token = format!("{TOKEN_PREFIX}{target}_{}", base32(&random_bytes::<32>()));
    let hash = sha256(token.as_bytes());
    (token, hash)
}

/// The target a token's prefix names, if it has the token shape.
pub fn token_target(token: &str) -> Option<&str> {
    let rest = token.strip_prefix(TOKEN_PREFIX)?;
    let (target, secret) = rest.rsplit_once('_')?;
    (secret.len() == 52 && secret.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)))
        .then_some(target)
}

/// Compares two byte strings in time that depends only on their lengths.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The admin token's hash, from its file. The file must hold at least 32 characters.
pub fn load_admin_token(path: &Path) -> Result<[u8; 32], String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("admin token file {}: {e}", path.display()))?;
    let token = text.trim();
    if token.len() < 32 {
        return Err(format!(
            "admin token file {} holds {} characters; use at least 32 random ones (openssl rand -hex 32)",
            path.display(),
            token.len()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path)
            && meta.permissions().mode() & 0o004 != 0
        {
            eprintln!("brainproxy-server: warning: {} is readable by everyone on this machine", path.display());
        }
    }
    Ok(sha256(token.as_bytes()))
}

/// The bearer token of an `Authorization` header value.
pub fn bearer(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim()).filter(|t| !t.is_empty())
}

/// What a rate limit counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bucket {
    /// Triggers per token: 10 an hour.
    Trigger,
    /// Reads per token: 600 an hour.
    Read,
    /// Failed authentications per client address: 30 per 10 minutes.
    AuthFailure,
}

impl Bucket {
    fn limit(self) -> (f64, Duration) {
        match self {
            Bucket::Trigger => (10.0, Duration::from_secs(3600)),
            Bucket::Read => (600.0, Duration::from_secs(3600)),
            Bucket::AuthFailure => (30.0, Duration::from_secs(600)),
        }
    }
}

/// Token buckets in memory: a restart refills them, which is fine at this scale.
#[derive(Default)]
pub struct Limits {
    buckets: Mutex<HashMap<(Bucket, String), (f64, Instant)>>,
}

impl Limits {
    /// Takes one from the bucket; false when it is empty.
    pub fn take(&self, bucket: Bucket, key: &str) -> bool {
        self.update(bucket, key, true)
    }

    fn update(&self, bucket: Bucket, key: &str, take: bool) -> bool {
        let (capacity, per) = bucket.limit();
        let now = Instant::now();
        let mut map = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() > 10_000 {
            // Many client addresses: drop the full buckets rather than grow without end, and if
            // that isn't enough (a flood from many addresses), start over: forgetting counts is
            // better than scanning a huge map on every request.
            map.retain(|(b, _), (n, t)| {
                let (cap, per) = b.limit();
                *n + now.duration_since(*t).as_secs_f64() * cap / per.as_secs_f64() < cap
            });
            if map.len() > 10_000 {
                map.clear();
            }
        }
        let (tokens, last) = map.entry((bucket, key.to_string())).or_insert((capacity, now));
        *tokens = (*tokens + now.duration_since(*last).as_secs_f64() * capacity / per.as_secs_f64()).min(capacity);
        *last = now;
        if *tokens < 1.0 {
            return false;
        }
        if take {
            *tokens -= 1.0;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_rfc4648() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "my");
        assert_eq!(base32(b"foobar"), "mzxw6ytboi");
        assert_eq!(base32(&[0u8; 32]).len(), 52);
    }

    #[test]
    fn tokens_name_their_target() {
        let (token, hash) = new_token("shop-dev");
        assert!(token.starts_with("bpt_shop-dev_"));
        assert_eq!(token_target(&token), Some("shop-dev"));
        assert_eq!(hash, sha256(token.as_bytes()));
        assert_ne!(new_token("shop-dev").0, token);
        assert_eq!(token_target("bpt_shop-dev_short"), None);
        assert_eq!(token_target("nope"), None);
    }

    #[test]
    fn bearer_header() {
        assert_eq!(bearer("Bearer abc"), Some("abc"));
        assert_eq!(bearer("bearer  abc "), Some("abc"));
        assert_eq!(bearer("Basic abc"), None);
        assert_eq!(bearer("Bearer "), None);
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn buckets_run_dry() {
        let l = Limits::default();
        for _ in 0..10 {
            assert!(l.take(Bucket::Trigger, "t"));
        }
        assert!(!l.take(Bucket::Trigger, "t"));
        assert!(l.take(Bucket::Trigger, "other"));
        assert!(l.take(Bucket::AuthFailure, "1.2.3.4"));
    }
}
