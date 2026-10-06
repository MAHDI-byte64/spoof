//! Authentication primitives for the web panel: salted password hashing,
//! constant-time comparison, opaque session tokens, and login throttling.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use rand::Rng;
use sha2::{Digest, Sha256};

/// Number of consecutive failed logins from one source before a lockout.
const MAX_FAILS: u32 = 8;
/// How long a source is locked out after exceeding [`MAX_FAILS`].
const LOCKOUT: Duration = Duration::from_secs(300);

/// Derive the salted password hash used by the panel.
///
/// `hash = SHA-256( "CandyTunnel-panel-v1:" || salt || ":" || password )`
pub fn hash_password(salt_hex: &str, password: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"CandyTunnel-panel-v1:");
    h.update(salt_hex.as_bytes());
    h.update(b":");
    h.update(password.as_bytes());
    hex::encode(h.finalize())
}

/// Generate a fresh random 16-byte salt, hex-encoded.
pub fn random_salt() -> String {
    let bytes: [u8; 16] = rand::random();
    hex::encode(bytes)
}

/// Constant-time comparison of two hex strings of equal purpose.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Generate a 256-bit opaque session token (hex).
pub fn new_token() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// Session + login-throttle store.
pub struct Sessions {
    /// token -> absolute expiry.
    tokens: DashMap<String, Instant>,
    ttl: Duration,
    fails: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl Sessions {
    pub fn new(ttl: Duration) -> Self {
        Self {
            tokens: DashMap::new(),
            ttl,
            fails: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new session and return its token.
    pub fn create(&self) -> String {
        let token = new_token();
        self.tokens.insert(token.clone(), Instant::now() + self.ttl);
        token
    }

    /// True if `token` is a live, non-expired session. Sliding expiry: a valid
    /// hit extends the session by the full TTL.
    pub fn validate(&self, token: &str) -> bool {
        let now = Instant::now();
        if let Some(mut e) = self.tokens.get_mut(token) {
            if *e.value() > now {
                *e.value_mut() = now + self.ttl;
                return true;
            }
        }
        // Expired or missing: drop it.
        self.tokens.remove(token);
        false
    }

    pub fn revoke(&self, token: &str) {
        self.tokens.remove(token);
    }

    /// Opportunistically drop expired sessions.
    pub fn sweep(&self) {
        let now = Instant::now();
        self.tokens.retain(|_, exp| *exp > now);
    }

    /// Whether `src` is currently locked out from logging in.
    pub fn is_locked(&self, src: IpAddr) -> bool {
        let mut map = self.fails.lock().unwrap();
        if let Some((count, until)) = map.get(&src).copied() {
            if count >= MAX_FAILS {
                if Instant::now() < until {
                    return true;
                }
                // Lockout elapsed — reset.
                map.remove(&src);
            }
        }
        false
    }

    pub fn record_failure(&self, src: IpAddr) {
        let mut map = self.fails.lock().unwrap();
        let entry = map.entry(src).or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now() + LOCKOUT;
    }

    pub fn record_success(&self, src: IpAddr) {
        self.fails.lock().unwrap().remove(&src);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_and_salted() {
        let salt = "abc123";
        let a = hash_password(salt, "hunter2");
        let b = hash_password(salt, "hunter2");
        assert_eq!(a, b);
        // Different salt → different hash for the same password.
        assert_ne!(a, hash_password("def456", "hunter2"));
        // Different password → different hash.
        assert_ne!(a, hash_password(salt, "hunter3"));
    }

    #[test]
    fn constant_time_eq_matches_semantics() {
        assert!(constant_time_eq("deadbeef", "deadbeef"));
        assert!(!constant_time_eq("deadbeef", "deadbee0"));
        assert!(!constant_time_eq("short", "longer"));
    }

    #[test]
    fn sessions_validate_and_revoke() {
        let s = Sessions::new(Duration::from_secs(60));
        let tok = s.create();
        assert!(s.validate(&tok));
        assert!(!s.validate("nonexistent"));
        s.revoke(&tok);
        assert!(!s.validate(&tok));
    }

    #[test]
    fn tokens_are_unique() {
        let a = new_token();
        let b = new_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64); // 32 bytes hex
    }
}
