//! SSH authorized_keys files: who can log in, and forced commands.

use std::path::Path;

use warden_core::{CheckResult, PersistenceMechanism, PersistenceScope};

use super::{note_user_limits, read};
use crate::ctx::{Ctx, Found, Run};

pub(crate) fn check(ctx: &mut Ctx<'_>) -> CheckResult {
    let mut run = Run::default();
    for u in ctx.users.clone() {
        for f in [".ssh/authorized_keys", ".ssh/authorized_keys2"] {
            let path = u.home.join(f);
            let Some((text, meta)) = read(ctx, &mut run, &path) else {
                continue;
            };
            let keys = parse_keys(&text);
            let scope = if u.uid == 0 {
                PersistenceScope::System
            } else {
                PersistenceScope::User
            };
            let found = |command: Option<String>, detail: String| Found {
                mechanism: PersistenceMechanism::SshAuthorizedKeys,
                scope,
                location: &path,
                command,
                enabled: None,
                detail: Some(detail),
                def_meta: Some(meta),
                owner_uid: Some(u.uid),
                find_executable: true,
            };
            let forced: Vec<&Key> = keys.iter().filter(|k| k.command.is_some()).collect();
            ctx.record(
                found(
                    None,
                    format!(
                        "{} key(s) for {}: {}",
                        keys.len(),
                        u.name,
                        keys.iter()
                            .map(|k| format!("{} {}", k.kind, k.comment))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ),
                None,
            );
            for k in forced {
                ctx.record(
                    found(
                        k.command.clone(),
                        format!("forced command for key {}", k.comment),
                    ),
                    Some(&k.options),
                );
            }
        }
    }
    check_sshd_config(ctx, &mut run);
    note_user_limits(ctx, &mut run);
    run.finish(
        "persistence.ssh_authorized_keys",
        "SSH authorized keys",
        ctx.cancel,
    )
}

/// Unusual `AuthorizedKeysFile` / `AuthorizedKeysCommand` settings are noted
/// in the check detail, since keys may then live elsewhere.
fn check_sshd_config(ctx: &mut Ctx<'_>, run: &mut Run) {
    let Some((text, _)) = read(ctx, run, Path::new("/etc/ssh/sshd_config")) else {
        return;
    };
    for line in text.lines().map(str::trim) {
        let mut it = line.splitn(2, char::is_whitespace);
        let (Some(k), Some(v)) = (it.next(), it.next()) else {
            continue;
        };
        let k = k.to_ascii_lowercase();
        if k == "authorizedkeyscommand"
            || (k == "authorizedkeysfile"
                && !v
                    .split_whitespace()
                    .all(|f| f.starts_with(".ssh/authorized_keys")))
        {
            run.notes.push(format!(
                "sshd_config sets {line}; keys may come from elsewhere"
            ));
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Key {
    kind: String,
    comment: String,
    options: String,
    command: Option<String>,
}

const KEY_TYPES: &[&str] = &["ssh-", "ecdsa-", "sk-"];

pub(crate) fn parse_keys(text: &str) -> Vec<Key> {
    let mut out = Vec::new();
    for line in text.lines().map(str::trim).take(10_000) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens = split_options_aware(line);
        let Some(type_idx) = tokens
            .iter()
            .position(|t| KEY_TYPES.iter().any(|p| t.starts_with(p)))
        else {
            continue;
        };
        let options = tokens[..type_idx].join(" ");
        let comment = tokens
            .get(type_idx + 2..)
            .map(|c| c.join(" "))
            .unwrap_or_default();
        out.push(Key {
            kind: tokens[type_idx].clone(),
            comment: if comment.is_empty() {
                "(no comment)".into()
            } else {
                comment
            },
            command: forced_command(&options),
            options,
        });
    }
    out
}

/// Whitespace split that keeps quoted option values together.
fn split_options_aware(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for c in line.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted => {
                cur.push(c);
                escaped = true;
            }
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn forced_command(options: &str) -> Option<String> {
    let start = options.find("command=\"")? + "command=\"".len();
    let rest = &options[start..];
    let mut out = String::new();
    let mut escaped = false;
    for c in rest.chars() {
        match (escaped, c) {
            (true, c) => {
                out.push(c);
                escaped = false;
            }
            (false, '\\') => escaped = true,
            (false, '"') => return Some(out),
            (false, c) => out.push(c),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_keys_and_forced_commands() {
        let keys = parse_keys(
            "# comment\nssh-ed25519 AAAA alice@host\n\
             no-pty,command=\"/usr/bin/rsync --server \\\"x\\\"\" ssh-rsa BBBB backup\n\
             garbage\n",
        );
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].comment, "alice@host");
        assert_eq!(keys[0].command, None);
        assert_eq!(
            keys[1].command.as_deref(),
            Some("/usr/bin/rsync --server \"x\"")
        );
        assert_eq!(keys[1].kind, "ssh-rsa");
    }
}
