//! Comparing the local audit chain with the anchors sent to the system log.
//!
//! Each audit entry's sequence number and hash are sent to syslog as
//! `audit seq=N hash=H chain=C action=A outcome=O` (see
//! `linux/anchor.rs`). A chain that was rewritten after the fact no longer
//! matches what the log received. Parsing and comparison are pure so they
//! are tested on every platform; reading the journal is the caller's job.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One anchor as found in the system log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub seq: u64,
    pub hash: String,
    /// Chain identifier; absent in anchors written before it existed.
    pub chain: Option<String>,
}

/// Parses an anchor message (with or without the syslog prefix).
pub fn parse_anchor(message: &str) -> Option<Anchor> {
    let rest = &message[message.find("audit seq=")? + "audit ".len()..];
    let mut seq = None;
    let mut hash = None;
    let mut chain = None;
    for field in rest.split_whitespace() {
        let (k, v) = field.split_once('=')?;
        match k {
            "seq" => seq = v.parse().ok(),
            "hash" if v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()) => {
                hash = Some(v.to_ascii_lowercase())
            }
            "chain" if v.len() == 16 && v.bytes().all(|b| b.is_ascii_hexdigit()) => {
                chain = Some(v.to_ascii_lowercase())
            }
            _ => {}
        }
    }
    Some(Anchor {
        seq: seq?,
        hash: hash?,
        chain,
    })
}

/// The outcome of comparing a chain with its anchors.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorComparison {
    /// Local entries.
    pub entries: u64,
    /// Local entries whose anchor matches.
    pub matched: u64,
    /// Sequence numbers anchored with a different hash: the local chain was
    /// altered.
    pub mismatched: Vec<u64>,
    /// Anchored sequence numbers beyond the local head: entries were
    /// removed from the end.
    pub missing_locally: Vec<u64>,
    /// Local entries with no anchor (logging was off or failed, or the log
    /// rotated them away).
    pub unanchored: u64,
    /// Anchors for other chains (another store, or this log rewritten from
    /// the start) and anchors without a chain identifier.
    pub other_chains: u64,
}

impl AnchorComparison {
    /// No evidence of tampering.
    pub fn consistent(&self) -> bool {
        self.mismatched.is_empty() && self.missing_locally.is_empty()
    }
}

/// Compares the local chain (`(seq, hash)` for every entry) with anchors.
pub fn compare_anchors(chain: &[(u64, String)], anchors: &[Anchor]) -> AnchorComparison {
    let id = chain.first().map(|(_, h)| crate::audit::chain_id(h));
    let local: BTreeMap<u64, &str> = chain.iter().map(|(s, h)| (*s, h.as_str())).collect();
    let head = chain.last().map_or(0, |(s, _)| *s);
    let mut out = AnchorComparison {
        entries: chain.len() as u64,
        ..AnchorComparison::default()
    };
    let mut anchored = std::collections::BTreeSet::new();
    for a in anchors {
        if a.chain.is_none() || a.chain != id {
            out.other_chains += 1;
            continue;
        }
        match local.get(&a.seq) {
            Some(h) if *h == a.hash => {
                if anchored.insert(a.seq) {
                    out.matched += 1;
                }
            }
            Some(_) => {
                if !out.mismatched.contains(&a.seq) {
                    out.mismatched.push(a.seq);
                }
            }
            None if a.seq > head && !out.missing_locally.contains(&a.seq) => {
                out.missing_locally.push(a.seq);
            }
            None => {}
        }
    }
    out.unanchored = out.entries - out.matched - out.mismatched.len() as u64;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(c: char) -> String {
        c.to_string().repeat(64)
    }

    #[test]
    fn parses_anchor_messages() {
        let a = parse_anchor(&format!(
            "<85>abyssal-warden[12]: audit seq=3 hash={} chain={} action=quarantine outcome=ok",
            h('a'),
            "b".repeat(16)
        ))
        .expect("anchor");
        assert_eq!((a.seq, a.chain.as_deref()), (3, Some("bbbbbbbbbbbbbbbb")));
        let old =
            parse_anchor(&format!("audit seq=1 hash={} action=x outcome=ok", h('c'))).expect("old");
        assert_eq!(old.chain, None);
        assert_eq!(parse_anchor("audit seq=1 hash=short"), None);
        assert_eq!(parse_anchor("something else"), None);
    }

    #[test]
    fn detects_rewrites_and_truncation() {
        let chain = vec![(1, h('1')), (2, h('2')), (3, h('3'))];
        let id = crate::audit::chain_id(&h('1'));
        let a = |seq, c| Anchor {
            seq,
            hash: h(c),
            chain: Some(id.clone()),
        };
        let good = compare_anchors(&chain, &[a(1, '1'), a(2, '2'), a(3, '3')]);
        assert!(good.consistent());
        assert_eq!((good.matched, good.unanchored), (3, 0));

        let altered = compare_anchors(&chain, &[a(1, '1'), a(2, 'x'), a(3, '3')]);
        assert_eq!(altered.mismatched, [2]);
        assert!(!altered.consistent());

        let truncated = compare_anchors(&chain, &[a(3, '3'), a(4, '4'), a(5, '5')]);
        assert_eq!(truncated.missing_locally, [4, 5]);
        assert_eq!(truncated.unanchored, 2);

        let foreign = Anchor {
            seq: 2,
            hash: h('z'),
            chain: Some("0".repeat(16)),
        };
        let other = compare_anchors(
            &chain,
            &[
                foreign,
                Anchor {
                    seq: 1,
                    hash: h('q'),
                    chain: None,
                },
            ],
        );
        assert!(other.consistent());
        assert_eq!(other.other_chains, 2);
    }
}
