//! Publisher-side importers that turn third-party feeds into content this
//! project can sign: hash lists into hash databases, and third-party YARA
//! files vetted one by one. Licences are recorded, never assumed
//! (docs/detection/content-sources.md).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use warden_core::{CancellationToken, Detector, FindingTarget, ScanConfig, SymlinkPolicy};
use warden_engine::Scanner;
use warden_engine::signatures::{HashSignatureDatabase, HashSignatureDetector};
use warden_yara::{RuleSource, YaraDetector};

/// SHA-256 values from a hash list: one per line, optionally followed by
/// whitespace and a file name (`sha256sum` output); `#` comments and blank
/// lines are skipped. Returns the digests (lower case, deduplicated) and the
/// number of lines that were not a SHA-256.
pub(crate) fn parse_hash_list(text: &str) -> (BTreeSet<String>, usize) {
    let mut out = BTreeSet::new();
    let mut rejected = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let token = line
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches('"');
        if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
            out.insert(token.to_ascii_lowercase());
        } else {
            rejected += 1;
        }
    }
    (out, rejected)
}

pub(crate) struct HashImport<'a> {
    pub(crate) db_name: &'a str,
    pub(crate) db_version: &'a str,
    pub(crate) detection_name: &'a str,
    pub(crate) id_prefix: &'a str,
    pub(crate) category: &'a str,
    pub(crate) severity: &'a str,
    pub(crate) license: &'a str,
    pub(crate) description: Option<&'a str>,
}

/// `text` reduced to `[A-Za-z0-9.-]` (at most 48 characters), for use in
/// signature IDs and detection names.
pub(crate) fn id_part(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c
            } else {
                '-'
            }
        })
        .take(48)
        .collect::<String>()
        .trim_matches(|c| c == '-' || c == '.')
        .to_owned()
}

/// Signature ID and detection name for `hash` in `group` (empty: none).
fn id_and_name(hash: &str, group: &str, m: &HashImport<'_>) -> (String, String) {
    let group = id_part(group);
    if group.is_empty() {
        (
            format!("{}-{}", m.id_prefix, &hash[..16]),
            m.detection_name.to_owned(),
        )
    } else {
        (
            format!("{}-{group}-{}", m.id_prefix, &hash[..16]),
            format!("{}.{group}", m.detection_name),
        )
    }
}

/// A validated hash database (JSON). `hashes` maps each SHA-256 to its
/// group (for example the feed directory it came from; empty for none),
/// which is added to the detection name and the ID.
pub(crate) fn hash_database(
    hashes: &BTreeMap<String, String>,
    m: &HashImport<'_>,
) -> Result<Vec<u8>, String> {
    let signatures: Vec<serde_json::Value> = hashes
        .iter()
        .map(|(h, group)| {
            let (id, name) = id_and_name(h, group, m);
            serde_json::json!({
                "id": id,
                "name": name,
                "sha256": h,
                "category": m.category,
                "severity": m.severity,
                "rule_version": 1,
            })
        })
        .collect();
    let mut database =
        serde_json::json!({ "name": m.db_name, "version": m.db_version, "license": m.license });
    if let Some(d) = m.description {
        database["description"] = serde_json::Value::String(d.to_owned());
    }
    let doc = serde_json::json!({
        "format": "abyssal-warden.hash-signatures",
        "format_version": 1,
        "database": database,
        "signatures": signatures,
    });
    let data = serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?;
    HashSignatureDatabase::from_slice(&data)
        .map_err(|e| format!("the result would not load: {e}"))?;
    Ok(data)
}

/// The outcome of vetting one third-party YARA file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Vetted {
    Accepted,
    Rejected(String),
}

/// Whether `text` compiles under this project's YARA restrictions (explicit
/// module list, no includes, no slow patterns, valid `aw_*` metadata).
pub(crate) fn vet_yara(name: &str, text: &str) -> Vetted {
    let src = [RuleSource {
        namespace: "vet".into(),
        origin: name.into(),
        text: text.into(),
    }];
    match YaraDetector::compile(&src, None) {
        Ok(d) if d.rule_count() == 0 => Vetted::Rejected("no rules".into()),
        Ok(_) => Vetted::Accepted,
        Err(e) => Vetted::Rejected(e.to_string().lines().next().unwrap_or("").to_owned()),
    }
}

/// What detectors find in known-clean files: `(rule or signature ID, file)`.
/// Links below the corpus are followed, so it can be a folder of links to
/// system files. Any match means the rule or hash would be a false positive.
pub(crate) fn clean_matches(
    detectors: Vec<Box<dyn Detector>>,
    corpus: &[PathBuf],
) -> Result<Vec<(String, String)>, String> {
    let mut config = ScanConfig::new(corpus.to_vec());
    config.symlink_policy = SymlinkPolicy::Follow;
    let mut scanner = Scanner::new(config).map_err(|e| e.to_string())?;
    for d in detectors {
        scanner.add_detector(d);
    }
    let report = scanner
        .scan(&CancellationToken::new(), |_, _| {})
        .map_err(|e| format!("clean corpus scan failed: {e}"))?;
    if report.stats.files_scanned == 0 {
        return Err("the clean corpus contains no files".into());
    }
    eprintln!(
        "clean corpus: {} file(s) checked, {} could not be read",
        report.stats.files_scanned,
        report.issues.len()
    );
    Ok(report
        .findings
        .iter()
        .map(|f| {
            let file = match &f.target {
                FindingTarget::File { path, .. } => path.text.clone(),
                other => serde_json::to_string(other).unwrap_or_default(),
            };
            (f.source.rule_id.clone().unwrap_or_default(), file)
        })
        .collect())
}

/// Removes hashes that match files in the clean corpus; returns what was
/// removed as `(hash, clean file)`.
pub(crate) fn drop_clean_hashes(
    hashes: &mut BTreeMap<String, String>,
    meta: &HashImport<'_>,
    corpus: &[PathBuf],
) -> Result<Vec<(String, String)>, String> {
    let db = HashSignatureDatabase::from_slice(&hash_database(hashes, meta)?)
        .map_err(|e| e.to_string())?;
    let by_id: BTreeMap<String, String> = hashes
        .iter()
        .map(|(h, g)| (id_and_name(h, g, meta).0, h.clone()))
        .collect();
    let mut dropped = Vec::new();
    for (id, file) in clean_matches(vec![Box::new(HashSignatureDetector::new(db))], corpus)? {
        if let Some(h) = by_id.get(&id)
            && hashes.remove(h).is_some()
        {
            dropped.push((h.clone(), file));
        }
    }
    Ok(dropped)
}

/// Indexes of `files` (name, text) whose rules match the clean corpus, with
/// the rule and file of the first match.
pub(crate) fn clean_rule_matches(
    files: &[(String, String)],
    corpus: &[PathBuf],
) -> Result<BTreeMap<usize, String>, String> {
    let sources: Vec<RuleSource> = files
        .iter()
        .enumerate()
        .map(|(i, (name, text))| RuleSource {
            namespace: format!("f{i}"),
            origin: name.clone(),
            text: text.clone(),
        })
        .collect();
    let det = YaraDetector::compile(&sources, None).map_err(|e| e.to_string())?;
    let mut out = BTreeMap::new();
    for (rule, file) in clean_matches(vec![Box::new(det)], corpus)? {
        let Some((ns, ident)) = rule.split_once(':') else {
            continue;
        };
        if let Some(i) = ns.strip_prefix('f').and_then(|n| n.parse::<usize>().ok()) {
            out.entry(i)
                .or_insert_with(|| format!("rule {ident} matched clean file {file}"));
        }
    }
    Ok(out)
}

/// `.yar`/`.yara` files below `dir` (not following links), sorted.
pub(crate) fn yara_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_owned()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))? {
            let e = e.map_err(|e| e.to_string())?;
            let ft = e.file_type().map_err(|e| e.to_string())?;
            let p = e.path();
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file()
                && p.extension().is_some_and(|x| {
                    x.eq_ignore_ascii_case("yar") || x.eq_ignore_ascii_case("yara")
                })
            {
                out.push(p);
            }
            if out.len() > 100_000 {
                return Err("more than 100,000 rule files".into());
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const H1: &str = "26d11a0d2767bb969011c61c58953c5d89035f8c2ca524efcafe3a9c92461eae";

    #[test]
    fn parses_hash_lists() {
        let text = format!(
            "# comment\n\n{}  file.exe\n{H1}\nnot-a-hash\n\"{}\"\n",
            H1.to_uppercase(),
            "ab".repeat(32)
        );
        let (set, rejected) = parse_hash_list(&text);
        assert_eq!(set.len(), 2);
        assert!(set.contains(H1));
        assert_eq!(rejected, 1);
    }

    #[test]
    fn builds_valid_databases() {
        let (set, _) = parse_hash_list(H1);
        let set: BTreeMap<String, String> = set.into_iter().map(|h| (h, String::new())).collect();
        let m = HashImport {
            db_name: "eset-test",
            db_version: "2026.09.28",
            detection_name: "ESET.Test",
            id_prefix: "ESET-TEST",
            category: "malware",
            severity: "high",
            license: "BSD-2-Clause (ESET malware-ioc)",
            description: None,
        };
        let data = hash_database(&set, &m).expect("valid");
        let db = HashSignatureDatabase::from_slice(&data).expect("loads");
        assert_eq!(db.len(), 1);
        let bad = HashImport {
            category: "nonsense",
            ..m
        };
        assert!(hash_database(&set, &bad).is_err());

        // Grouped by feed directory: the group joins the name and the ID.
        let good = HashImport {
            category: "malware",
            ..bad
        };
        let grouped: BTreeMap<String, String> =
            [(H1.to_owned(), "aceCryptor_h2 2023".to_owned())].into();
        let db =
            HashSignatureDatabase::from_slice(&hash_database(&grouped, &good).unwrap()).unwrap();
        let sig = db
            .lookup(&H1.parse::<warden_core::Sha256Digest>().unwrap())
            .unwrap();
        assert_eq!(sig.name, "ESET.Test.aceCryptor-h2-2023");
        assert_eq!(sig.id, "ESET-TEST-aceCryptor-h2-2023-26d11a0d2767bb96");
    }

    #[test]
    fn clean_corpus_drops_matching_rules_and_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let clean = dir.path().join("clean");
        std::fs::create_dir(&clean).unwrap();
        let content = b"an ordinary clean-marker file";
        std::fs::write(clean.join("readme.txt"), content).unwrap();
        let corpus = [clean];

        let files = vec![
            (
                "fp.yar".to_owned(),
                "rule fp { strings: $a = \"clean-marker\" condition: $a }".to_owned(),
            ),
            (
                "ok.yar".to_owned(),
                "rule ok { strings: $a = \"synthetic-evil\" condition: $a }".to_owned(),
            ),
        ];
        let bad = clean_rule_matches(&files, &corpus).unwrap();
        assert_eq!(bad.keys().copied().collect::<Vec<_>>(), [0]);
        assert!(
            bad[&0].contains("rule fp matched clean file"),
            "{}",
            bad[&0]
        );

        let clean_hex: String = Sha256::digest(content)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut hashes: BTreeMap<String, String> = [
            (clean_hex.clone(), String::new()),
            (H1.to_owned(), "g".to_owned()),
        ]
        .into();
        let m = HashImport {
            db_name: "t",
            db_version: "1",
            detection_name: "T",
            id_prefix: "T",
            category: "malware",
            severity: "high",
            license: "test",
            description: None,
        };
        let dropped = drop_clean_hashes(&mut hashes, &m, &corpus).unwrap();
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, clean_hex);
        assert_eq!(hashes.keys().collect::<Vec<_>>(), [H1]);
    }

    #[test]
    fn vets_rules() {
        assert_eq!(
            vet_yara("a.yar", "rule a { strings: $x = \"abc\" condition: $x }"),
            Vetted::Accepted
        );
        assert!(matches!(
            vet_yara("b.yar", "include \"x.yar\"\nrule b { condition: true }"),
            Vetted::Rejected(_)
        ));
        assert!(matches!(
            vet_yara("c.yar", "rule c { condition: filename == \"x\" }"),
            Vetted::Rejected(_)
        ));
        assert!(matches!(
            vet_yara("d.yar", "// nothing"),
            Vetted::Rejected(_)
        ));
    }
}
