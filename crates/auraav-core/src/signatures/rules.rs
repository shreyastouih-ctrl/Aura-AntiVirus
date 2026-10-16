use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::types::DetectionType;

use super::fingerprints::{CodeSignature, FuzzySignature};

/// A known-malware hash entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashSignature {
    pub sha256: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub family: String,
    #[serde(default = "default_type")]
    pub detection_type: DetectionType,
    #[serde(default = "default_severity")]
    pub severity: f32,
}

fn default_type() -> DetectionType {
    DetectionType::Known
}
fn default_severity() -> f32 {
    0.95
}

/// One string/byte/regex pattern inside a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RulePattern {
    Text(String),
    Hex(Vec<u8>),
    Regex(String),
}

impl RulePattern {
    pub fn len(&self) -> usize {
        match self {
            RulePattern::Text(t) => t.len(),
            RulePattern::Hex(h) => h.len(),
            RulePattern::Regex(r) => r.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    All,
    Any,
    AtLeast(usize),
}

/// A parsed YARA-like rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub family: String,
    #[serde(default = "default_type")]
    pub detection_type: DetectionType,
    #[serde(default = "default_rule_severity")]
    pub severity: f32,
    pub patterns: Vec<RulePattern>,
    pub condition: RuleCondition,
}

fn default_rule_severity() -> f32 {
    0.7
}

impl Rule {
    pub fn matches(&self, data: &[u8]) -> bool {
        self.match_count(data).is_some()
    }

    /// Number of distinct patterns that matched, if the rule's condition is
    /// satisfied. Used to require corroboration when scanning binaries.
    pub fn match_count(&self, data: &[u8]) -> Option<usize> {
        if self.patterns.is_empty() {
            return None;
        }
        let hits = self
            .patterns
            .iter()
            .filter(|p| Self::pattern_matches(p, data))
            .count();
        let matched = match self.condition {
            RuleCondition::All => hits == self.patterns.len(),
            RuleCondition::Any => hits >= 1,
            RuleCondition::AtLeast(n) => hits >= n,
        };
        matched.then_some(hits)
    }

    fn pattern_matches(pattern: &RulePattern, data: &[u8]) -> bool {
        match pattern {
            RulePattern::Text(t) => !t.is_empty() && contains_bytes(data, t.as_bytes()),
            RulePattern::Hex(h) => !h.is_empty() && contains_bytes(data, h),
            RulePattern::Regex(r) => {
                // Regex compiled lazily; parse errors simply do not match.
                match regex::Regex::new(r) {
                    Ok(re) => re.is_match(&String::from_utf8_lossy(data)),
                    Err(_) => false,
                }
            }
        }
    }
}

/// Naive substring search. Good enough for signature scanning of small files;
/// callers cap the amount of data scanned.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// In-memory signature database.
#[derive(Debug, Default)]
pub struct SignatureDb {
    hashes: HashMap<String, HashSignature>,
    rules: Vec<Rule>,
    fuzzy: Vec<FuzzySignature>,
    code: Vec<CodeSignature>,
}

impl SignatureDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn hash_count(&self) -> usize {
        self.hashes.len()
    }
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
    pub fn fuzzy_count(&self) -> usize {
        self.fuzzy.len()
    }
    pub fn code_count(&self) -> usize {
        self.code.len()
    }

    pub fn lookup_hash(&self, sha256: &str) -> Option<&HashSignature> {
        self.hashes.get(&sha256.to_ascii_lowercase())
    }

    pub fn add_hash(&mut self, sig: HashSignature) {
        self.hashes.insert(sig.sha256.to_ascii_lowercase(), sig);
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Rules matched by `data`, together with the number of patterns each hit.
    pub fn match_rules_with_counts<'a>(&'a self, data: &[u8]) -> Vec<(&'a Rule, usize)> {
        self.rules
            .iter()
            .filter_map(|r| r.match_count(data).map(|n| (r, n)))
            .collect()
    }

    pub fn add_fuzzy(&mut self, sig: FuzzySignature) {
        self.fuzzy.push(sig);
    }

    pub fn add_code(&mut self, sig: CodeSignature) {
        self.code.push(sig);
    }

    pub fn fuzzy_signatures(&self) -> &[FuzzySignature] {
        &self.fuzzy
    }

    pub fn code_signatures(&self) -> &[CodeSignature] {
        &self.code
    }

    pub fn match_rules(&self, data: &[u8]) -> Vec<&Rule> {
        self.rules.iter().filter(|r| r.matches(data)).collect()
    }

    /// Best fuzzy (byte-level) match for `digest`, within `max_distance`.
    pub fn best_fuzzy_match(
        &self,
        digest: &crate::detection::similarity::FuzzyDigest,
        max_distance: u32,
    ) -> Option<(&FuzzySignature, u32)> {
        let mut best: Option<(&FuzzySignature, u32)> = None;
        for sig in &self.fuzzy {
            let d = sig.digest.distance(digest);
            if d <= max_distance && best.map(|(_, bd)| d < bd).unwrap_or(true) {
                best = Some((sig, d));
            }
        }
        best
    }

    /// Best normalized-code match for `fp`, with similarity >= `min_sim`.
    pub fn best_code_match(
        &self,
        fp: &crate::detection::disasm::CodeFingerprint,
        min_sim: f32,
    ) -> Option<(&CodeSignature, f32)> {
        let mut best: Option<(&CodeSignature, f32)> = None;
        for sig in &self.code {
            let s = sig.similarity(fp);
            if s >= min_sim && best.map(|(_, bs)| s > bs).unwrap_or(true) {
                best = Some((sig, s));
            }
        }
        best
    }

    /// Load a hash list (JSONL). Each line is a [`HashSignature`] JSON object.
    pub fn load_hashes_jsonl(&mut self, path: &Path) -> anyhow::Result<usize> {
        let text = std::fs::read_to_string(path)?;
        let mut n = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match serde_json::from_str::<HashSignature>(line) {
                Ok(sig) => {
                    self.add_hash(sig);
                    n += 1;
                }
                Err(e) => {
                    tracing::warn!("skipping malformed hash signature: {e}");
                }
            }
        }
        Ok(n)
    }

    /// Load a YARA-like rule file. See `parse_rules`.
    pub fn load_rule_file(&mut self, path: &Path) -> anyhow::Result<usize> {
        let text = std::fs::read_to_string(path)?;
        let rules = parse_rules(&text)?;
        let n = rules.len();
        for r in rules {
            self.add_rule(r);
        }
        Ok(n)
    }

    /// Load fuzzy fingerprints (JSONL of [`FuzzySignature`]).
    pub fn load_fuzzy_jsonl(&mut self, path: &Path) -> anyhow::Result<usize> {
        let text = std::fs::read_to_string(path)?;
        let mut n = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(sig) = serde_json::from_str::<FuzzySignature>(line) {
                self.add_fuzzy(sig);
                n += 1;
            }
        }
        Ok(n)
    }

    /// Load code fingerprints (JSONL of [`CodeSignature`]).
    pub fn load_code_jsonl(&mut self, path: &Path) -> anyhow::Result<usize> {
        let text = std::fs::read_to_string(path)?;
        let mut n = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(sig) = serde_json::from_str::<CodeSignature>(line) {
                self.add_code(sig);
                n += 1;
            }
        }
        Ok(n)
    }

    /// Load every signature/rule/fingerprint file in a directory.
    /// Returns `(hashes, rules, fuzzy, code)` counts.
    pub fn load_dir(&mut self, dir: &Path) -> anyhow::Result<(usize, usize, usize, usize)> {
        let (mut nh, mut nr, mut nf, mut nc) = (0, 0, 0, 0);
        if !dir.exists() {
            return Ok((0, 0, 0, 0));
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if name.ends_with(".fuzzy.jsonl") {
                if let Ok(n) = self.load_fuzzy_jsonl(&path) {
                    nf += n;
                }
            } else if name.ends_with(".code.jsonl") {
                if let Ok(n) = self.load_code_jsonl(&path) {
                    nc += n;
                }
            } else {
                match ext.as_str() {
                    "jsonl" | "json" => {
                        if let Ok(n) = self.load_hashes_jsonl(&path) {
                            nh += n;
                        }
                    }
                    "yar" | "yara" | "rules" => {
                        if let Ok(n) = self.load_rule_file(&path) {
                            nr += n;
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok((nh, nr, nf, nc))
    }
}

/// Parse a simplified YARA-like syntax:
///
/// ```text
/// rule MyRule
///   family = "SomeFamily"
///   type = Trojan
///   severity = 0.9
///   strings:
///     $a = "powershell"
///     $b = { 4D 5A 90 00 }
///     $c = /cmd\.exe/i
///   condition:
///     all of them
/// ```
pub fn parse_rules(input: &str) -> anyhow::Result<Vec<Rule>> {
    let mut rules = Vec::new();
    let mut current: Option<Rule> = None;
    let mut section = Section::Meta;

    #[derive(PartialEq)]
    enum Section {
        Meta,
        Strings,
        Condition,
    }

    for raw in input.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
            continue;
        }

        if let Some(rest) = line.strip_prefix("rule ") {
            if let Some(rule) = current.take() {
                rules.push(rule);
            }
            let name = rest.trim().trim_end_matches('{').trim().to_string();
            current = Some(Rule {
                name,
                family: String::new(),
                detection_type: DetectionType::Other,
                severity: 0.7,
                patterns: Vec::new(),
                condition: RuleCondition::All,
            });
            section = Section::Meta;
            continue;
        }

        if line == "}" {
            if let Some(rule) = current.take() {
                rules.push(rule);
            }
            continue;
        }

        let Some(rule) = current.as_mut() else {
            continue;
        };

        if line.eq_ignore_ascii_case("strings:") {
            section = Section::Strings;
            continue;
        }
        if line.eq_ignore_ascii_case("condition:") {
            section = Section::Condition;
            continue;
        }

        match section {
            Section::Meta => {
                if let Some((k, v)) = split_meta(line) {
                    match k.as_str() {
                        "family" => rule.family = v,
                        "type" => rule.detection_type = parse_detection_type(&v),
                        "severity" => rule.severity = v.parse().unwrap_or(0.7),
                        _ => {}
                    }
                }
            }
            Section::Strings => {
                if let Some(pat) = parse_pattern(line) {
                    rule.patterns.push(pat);
                }
            }
            Section::Condition => {
                rule.condition = parse_condition(line);
            }
        }
    }

    if let Some(rule) = current.take() {
        rules.push(rule);
    }
    Ok(rules)
}

fn split_meta(line: &str) -> Option<(String, String)> {
    let (k, v) = line.split_once('=')?;
    let key = k.trim().to_ascii_lowercase();
    let value = v.trim().trim_matches('"').trim().to_string();
    Some((key, value))
}

fn parse_detection_type(v: &str) -> DetectionType {
    match v.to_ascii_lowercase().as_str() {
        "known" => DetectionType::Known,
        "polymorphic" => DetectionType::Polymorphic,
        "metamorphic" => DetectionType::Metamorphic,
        "fileinfector" | "infector" => DetectionType::FileInfector,
        "trojan" => DetectionType::Trojan,
        "worm" => DetectionType::Worm,
        "dropper" => DetectionType::Dropper,
        "downloader" => DetectionType::Downloader,
        "ransomware" => DetectionType::Ransomware,
        "backdoor" => DetectionType::Backdoor,
        "rootkit" => DetectionType::Rootkit,
        "script" => DetectionType::Script,
        "packed" => DetectionType::Packed,
        "suspicious" => DetectionType::Suspicious,
        _ => DetectionType::Other,
    }
}

fn parse_pattern(line: &str) -> Option<RulePattern> {
    // Formats: $id = "text" | $id = { AA BB } | $id = /regex/
    let (_id, rhs) = line.split_once('=')?;
    let rhs = rhs.trim();
    if rhs.starts_with('"') {
        let text = rhs.trim_matches('"').to_string();
        Some(RulePattern::Text(text))
    } else if rhs.starts_with('{') {
        let inner = rhs.trim_start_matches('{').trim_end_matches('}').trim();
        let bytes = parse_hex_bytes(inner)?;
        Some(RulePattern::Hex(bytes))
    } else if rhs.starts_with('/') {
        // strip trailing flags like /i
        let end = rhs.rfind('/').unwrap_or(rhs.len() - 1);
        let regex = rhs[1..end].to_string();
        Some(RulePattern::Regex(regex))
    } else {
        Some(RulePattern::Text(rhs.to_string()))
    }
}

fn parse_hex_bytes(inner: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for tok in inner.split_whitespace() {
        if tok == "??" {
            return None; // wildcards unsupported in this subset
        }
        if let Ok(b) = u8::from_str_radix(tok, 16) {
            out.push(b);
        }
    }
    (!out.is_empty()).then_some(out)
}

fn parse_condition(line: &str) -> RuleCondition {
    let l = line.to_ascii_lowercase();
    if l.contains("any of them") {
        RuleCondition::Any
    } else if let Some(rest) = l.strip_prefix("all of them") {
        let _ = rest;
        RuleCondition::All
    } else {
        // "N of them"
        let n = l
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<usize>().ok());
        match n {
            Some(n) => RuleCondition::AtLeast(n),
            None => RuleCondition::All,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_matches_rule() {
        let src = r#"
rule TestEicar
  family = Test
  type = Trojan
  severity = 0.9
  strings:
    $a = "EICAR"
    $b = { 45 49 43 41 52 }
  condition:
    any of them
"#;
        let rules = parse_rules(src).unwrap();
        assert_eq!(rules.len(), 1);
        let data = b"xxEICARxx";
        assert!(rules[0].matches(data));
        assert!(!rules[0].matches(b"nothing here"));
    }

    #[test]
    fn all_condition_requires_every_pattern() {
        let src = r#"
rule R
  strings:
    $a = "foo"
    $b = "bar"
  condition:
    all of them
"#;
        let rules = parse_rules(src).unwrap();
        assert!(rules[0].matches(b"foo and bar"));
        assert!(!rules[0].matches(b"foo only"));
    }
}
