//! Validation and neutralisation of untrusted display text.
//!
//! File names, rule names and rule metadata are attacker-influenced. Control
//! characters can drive a terminal (ANSI/OSC escape sequences) and
//! bidirectional formatting characters can disguise text
//! (`invoice\u{202E}fdp.exe` renders as `invoiceexe.pdf`).

use std::fmt::Write as _;

/// Unicode bidirectional formatting characters (embeddings, overrides,
/// isolates and marks).
pub fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}'
    )
}

/// True if `s` contains characters that must not appear in stored display
/// text: controls (other than `\n` and `\t` when `allow_newlines` is set)
/// and bidi formatting characters.
pub fn has_unsafe_chars(s: &str, allow_newlines: bool) -> bool {
    s.chars().any(|c| {
        let allowed_ws = allow_newlines && (c == '\n' || c == '\t');
        (c.is_control() && !allowed_ws) || is_bidi_control(c)
    })
}

/// Escape control and bidi characters as `\u{..}` so untrusted text is
/// inert when displayed.
pub fn escape_unsafe_chars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() || is_bidi_control(c) {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_and_escapes() {
        assert!(!has_unsafe_chars("plain name", false));
        assert!(has_unsafe_chars("a\x1bb", false));
        assert!(has_unsafe_chars("a\nb", false));
        assert!(!has_unsafe_chars("a\nb\tc", true));
        assert!(has_unsafe_chars("x\u{202E}y", true));
        assert!(has_unsafe_chars("x\u{9b}y", true));
        assert_eq!(escape_unsafe_chars("a\x1b[2Jb"), "a\\u{1b}[2Jb");
        assert_eq!(escape_unsafe_chars("i\u{202E}x"), "i\\u{202e}x");
        assert_eq!(escape_unsafe_chars("日本"), "日本");
    }
}
