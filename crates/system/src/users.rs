//! Users whose home directories are inspected.

use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct User {
    pub(crate) name: String,
    pub(crate) uid: u32,
    /// Logical home directory.
    pub(crate) home: PathBuf,
}

const NO_LOGIN: &[&str] = &["nologin", "false", "sync", "shutdown", "halt"];

/// Parses `/etc/passwd`. Users are kept when they are root, have a login
/// shell, or a UID of 1000 or more, and their home is an absolute path other
/// than `/`. Homes are deduplicated.
pub(crate) fn parse_passwd(text: &str) -> Vec<User> {
    let mut out: Vec<User> = Vec::new();
    for line in text.lines().take(100_000) {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 || f[0].is_empty() || f[0].starts_with('#') {
            continue;
        }
        let Ok(uid) = f[2].parse::<u32>() else {
            continue;
        };
        let home = Path::new(f[5]);
        // A Unix path whatever the host (offline images are read from any OS).
        if !f[5].starts_with('/') || f[5] == "/" {
            continue;
        }
        let shell = f[6].rsplit('/').next().unwrap_or("");
        let login = !shell.is_empty() && !NO_LOGIN.contains(&shell);
        if !(uid == 0 || login || (1000..65534).contains(&uid)) {
            continue;
        }
        if out.iter().any(|u| u.home == home) {
            continue;
        }
        out.push(User {
            name: f[0].to_owned(),
            uid,
            home: home.to_owned(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_login_users() {
        let users = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\n\
             bin:x:1:1:bin:/bin:/sbin/nologin\n\
             svc:x:990:990::/var/lib/svc:/bin/sh\n\
             alice:x:1000:1000::/home/alice:/bin/zsh\n\
             nobody:x:65534:65534::/:/sbin/nologin\n\
             broken line\n\
             dup:x:1001:1001::/home/alice:/bin/bash\n\
             rel:x:1002:1002::home/rel:/bin/bash\n",
        );
        let names: Vec<_> = users.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, ["root", "svc", "alice"]);
        assert_eq!(users[2].uid, 1000);
    }
}
