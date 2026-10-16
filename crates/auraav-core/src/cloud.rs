//! Optional online confirmation of a file by its SHA-256 hash.
//!
//! auraAV is offline-first: this module is only consulted when the caller has
//! enabled cloud checks *and* a local scan already found the file non-clean.
//! Only the hash is sent — never the file contents. The backend is
//! [MalwareBazaar](https://bazaar.abuse.ch/api/), which is free and keyless.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Deserialize;

const MB_ENDPOINT: &str = "https://mb-api.abuse.ch/api/v1/";
const USER_AGENT: &str = concat!("auraAV/", env!("CARGO_PKG_VERSION"));

/// Set after the first network failure so a run does not stall on every file
/// when the machine is offline.
static CLOUD_UNREACHABLE: AtomicBool = AtomicBool::new(false);

/// Outcome of an online hash lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudVerdict {
    /// The hash is a known malware sample (possibly with a family/signature name).
    Known { family: Option<String> },
    /// The backend responded but does not know this hash.
    Unknown,
    /// The backend could not be reached or gave an unexpected response.
    Unavailable(String),
}

#[derive(Debug, Deserialize)]
struct MbResponse {
    query_status: String,
    #[serde(default)]
    data: Option<Vec<MbEntry>>,
}

#[derive(Debug, Deserialize)]
struct MbEntry {
    #[serde(default)]
    signature: Option<String>,
}

fn valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Read the optional MalwareBazaar API key from the environment.
fn api_key() -> Option<String> {
    for var in ["AURAAV_MB_KEY", "MALWAREBAZAAR_API_KEY"] {
        if let Ok(v) = std::env::var(var) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Look up a SHA-256 hash online. Never panics; returns `Unavailable` on error.
///
/// MalwareBazaar requires a free API key. Set it in `AURAAV_MB_KEY` (or the
/// legacy `MALWAREBAZAAR_API_KEY`). Without a key the check is skipped.
pub fn lookup_hash(sha256: &str) -> CloudVerdict {
    if CLOUD_UNREACHABLE.load(Ordering::Relaxed) {
        return CloudVerdict::Unavailable("cloud checks disabled after an earlier failure".into());
    }
    let Some(key) = api_key() else {
        return CloudVerdict::Unavailable("no MalwareBazaar API key configured".into());
    };
    let sha = sha256.trim().to_ascii_lowercase();
    if !valid_sha256(&sha) {
        return CloudVerdict::Unknown;
    }

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(8))
        .user_agent(USER_AGENT)
        .build();

    match agent
        .post(MB_ENDPOINT)
        .set("Auth-Key", &key)
        .send_form(&[("query", "get_info"), ("hash", &sha)])
    {
        Ok(resp) => match resp.into_json::<MbResponse>() {
            Ok(body) => match body.query_status.as_str() {
                "ok" => {
                    let family = body
                        .data
                        .and_then(|d| d.into_iter().next())
                        .and_then(|e| e.signature)
                        .filter(|s| !s.trim().is_empty());
                    CloudVerdict::Known { family }
                }
                "unknown_auth_key" | "unauthorized" => {
                    CLOUD_UNREACHABLE.store(true, Ordering::Relaxed);
                    CloudVerdict::Unavailable("invalid MalwareBazaar API key".into())
                }
                _ => CloudVerdict::Unknown,
            },
            Err(e) => {
                CLOUD_UNREACHABLE.store(true, Ordering::Relaxed);
                CloudVerdict::Unavailable(format!("malformed response: {e}"))
            }
        },
        Err(err) => {
            CLOUD_UNREACHABLE.store(true, Ordering::Relaxed);
            CloudVerdict::Unavailable(err.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_validation() {
        assert!(valid_sha256(
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        ));
        assert!(!valid_sha256("not-a-hash"));
        assert!(!valid_sha256(""));
    }

    #[test]
    fn parses_known_sample() {
        let body: MbResponse =
            serde_json::from_str(r#"{"query_status":"ok","data":[{"signature":"WannaCry"}]}"#)
                .unwrap();
        assert_eq!(body.query_status, "ok");
        let family = body
            .data
            .and_then(|d| d.into_iter().next())
            .and_then(|e| e.signature);
        assert_eq!(family.as_deref(), Some("WannaCry"));
    }

    #[test]
    fn parses_not_found() {
        let body: MbResponse =
            serde_json::from_str(r#"{"query_status":"hash_not_found"}"#).unwrap();
        assert_eq!(body.query_status, "hash_not_found");
        assert!(body.data.is_none());
    }
}
