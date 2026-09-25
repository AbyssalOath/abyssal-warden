//! User and group lookups from `/etc/passwd` and `/etc/group`, and the
//! administrator decision.

use crate::config::ServiceConfig;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct User {
    pub(crate) name: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Group {
    pub(crate) name: String,
    pub(crate) gid: u32,
    pub(crate) members: Vec<String>,
}

pub(crate) fn parse_passwd(text: &str) -> Vec<User> {
    text.lines()
        .take(200_000)
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 7 && !f[0].is_empty()).then_some(())?;
            Some(User {
                name: f[0].to_owned(),
                uid: f[2].parse().ok()?,
                gid: f[3].parse().ok()?,
            })
        })
        .collect()
}

pub(crate) fn parse_group(text: &str) -> Vec<Group> {
    text.lines()
        .take(200_000)
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 4 && !f[0].is_empty()).then_some(())?;
            Some(Group {
                name: f[0].to_owned(),
                gid: f[2].parse().ok()?,
                members: f[3]
                    .split(',')
                    .filter(|m| !m.is_empty())
                    .map(str::to_owned)
                    .collect(),
            })
        })
        .collect()
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Accounts {
    pub(crate) users: Vec<User>,
    pub(crate) groups: Vec<Group>,
}

impl Accounts {
    /// Reads the system databases (re-read for every connection, so changes
    /// apply without a restart).
    pub(crate) fn load() -> Self {
        let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
        Self {
            users: parse_passwd(&read("/etc/passwd")),
            groups: parse_group(&read("/etc/group")),
        }
    }

    pub(crate) fn user(&self, uid: u32) -> Option<&User> {
        self.users.iter().find(|u| u.uid == uid)
    }

    pub(crate) fn user_by_name(&self, name: &str) -> Option<&User> {
        self.users.iter().find(|u| u.name == name)
    }

    pub(crate) fn group_by_name(&self, name: &str) -> Option<&Group> {
        self.groups.iter().find(|g| g.name == name)
    }

    /// Root, a listed administrator (name or uid), or a member of the
    /// admin group (listed member, or primary group).
    pub(crate) fn is_admin(&self, uid: u32, cfg: &ServiceConfig) -> bool {
        if uid == 0 {
            return true;
        }
        let user = self.user(uid);
        if cfg
            .admin_users
            .iter()
            .any(|a| a.parse::<u32>().ok() == Some(uid) || user.is_some_and(|u| &u.name == a))
        {
            return true;
        }
        let (Some(group), Some(user)) = (
            cfg.admin_group
                .as_deref()
                .and_then(|g| self.group_by_name(g)),
            user,
        ) else {
            return false;
        };
        user.gid == group.gid || group.members.iter().any(|m| m == &user.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accounts() -> Accounts {
        Accounts {
            users: parse_passwd(
                "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\ncarol:x:1002:990::/home/carol:/bin/bash\nbad line\n",
            ),
            groups: parse_group("wheel:x:10:alice\nwardenadm:x:990:\nbob:x:1001:\nbroken\n"),
        }
    }

    #[test]
    fn admin_decision() {
        let a = accounts();
        let mut cfg = ServiceConfig::default();
        assert!(a.is_admin(0, &cfg));
        assert!(!a.is_admin(1000, &cfg));
        cfg.admin_group = Some("wheel".into());
        assert!(a.is_admin(1000, &cfg));
        assert!(!a.is_admin(1001, &cfg));
        cfg.admin_group = Some("wardenadm".into());
        assert!(a.is_admin(1002, &cfg), "primary group counts");
        cfg.admin_users = vec!["bob".into(), "4242".into()];
        assert!(a.is_admin(1001, &cfg));
        assert!(a.is_admin(4242, &cfg));
        cfg.admin_group = Some("missing".into());
        assert!(!a.is_admin(1000, &cfg));
    }
}
