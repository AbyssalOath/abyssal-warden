//! Read-only file access confined to the inspected root.
//!
//! Every path the checks use is *logical* (as seen from inside the inspected
//! system, e.g. `/etc/crontab`). It is opened with
//! `openat2(RESOLVE_IN_ROOT)` relative to a handle on the root, so symbolic
//! links inside an offline image (`--root`) resolve inside the image and can
//! never reach the host. Reads are bounded and non-blocking, and only regular
//! files are read.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::{self as rfs, CWD, FileType, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

/// Largest configuration file read; longer files are read up to this size.
pub(crate) const MAX_READ: usize = 1 << 20;
/// Most directory entries listed per directory.
pub(crate) const MAX_DIR_ENTRIES: usize = 20_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Meta {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) mode: u32,
    pub(crate) kind: Kind,
    pub(crate) dev: u64,
    pub(crate) ino: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

impl Meta {
    fn from_stat(st: &rfs::Stat) -> Self {
        let kind = match FileType::from_raw_mode(st.st_mode) {
            FileType::RegularFile => Kind::File,
            FileType::Directory => Kind::Dir,
            FileType::Symlink => Kind::Symlink,
            _ => Kind::Other,
        };
        Self {
            uid: st.st_uid,
            gid: st.st_gid,
            mode: st.st_mode & 0o7777,
            kind,
            dev: st.st_dev,
            ino: st.st_ino,
        }
    }

    /// Writable by someone other than root (owner not root, group-writable
    /// with a non-root group, or world-writable).
    pub(crate) fn writable_by_non_root(&self) -> bool {
        self.uid != 0 || (self.mode & 0o020 != 0 && self.gid != 0) || self.mode & 0o002 != 0
    }

    /// Like [`Self::writable_by_non_root`] for a directory: a sticky,
    /// root-owned world-writable directory still lets others add files but
    /// not replace root's, so only the owner and non-sticky write bits count.
    pub(crate) fn dir_writable_by_non_root(&self) -> bool {
        let sticky = self.mode & 0o1000 != 0;
        self.uid != 0
            || (!sticky && self.mode & 0o020 != 0 && self.gid != 0)
            || (!sticky && self.mode & 0o002 != 0)
    }
}

#[derive(Debug)]
pub(crate) struct Text {
    pub(crate) text: String,
    pub(crate) meta: Meta,
    pub(crate) truncated: bool,
}

#[derive(Debug)]
pub(crate) struct Entry {
    pub(crate) name: String,
    pub(crate) kind: Kind,
}

#[derive(Debug)]
pub(crate) struct Root {
    dir: OwnedFd,
    path: PathBuf,
    /// The root is the running system's `/`.
    live: bool,
}

impl Root {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let dir = rfs::open(
            path,
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let live = rfs::fstat(&dir)
            .ok()
            .zip(rfs::stat("/").ok())
            .is_some_and(|(a, b)| a.st_dev == b.st_dev && a.st_ino == b.st_ino);
        Ok(Self {
            dir,
            path: path.to_owned(),
            live,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn is_live(&self) -> bool {
        self.live
    }

    fn open_at(&self, logical: &Path, flags: OFlags) -> io::Result<OwnedFd> {
        let rel = relative(logical);
        // O_PATH only combines with DIRECTORY, NOFOLLOW and CLOEXEC.
        let flags = if flags.contains(OFlags::PATH) {
            flags | OFlags::CLOEXEC
        } else {
            flags | OFlags::CLOEXEC | OFlags::NOCTTY
        };
        match rfs::openat2(
            &self.dir,
            rel,
            flags,
            Mode::empty(),
            ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS,
        ) {
            // Linux < 5.6: only the live root can be read safely without
            // RESOLVE_IN_ROOT (absolute links then mean the same thing).
            Err(Errno::NOSYS) if self.live => Ok(rfs::openat(CWD, logical, flags, Mode::empty())?),
            Err(Errno::NOSYS) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "inspecting another root needs openat2 (Linux 5.6 or later)",
            )),
            other => Ok(other?),
        }
    }

    /// Metadata of the file `logical` names (links followed inside the root).
    pub(crate) fn stat(&self, logical: &Path) -> io::Result<Meta> {
        let fd = self.open_at(logical, OFlags::PATH)?;
        Ok(Meta::from_stat(&rfs::fstat(&fd)?))
    }

    /// Metadata of `logical` itself (a final symlink is not followed).
    pub(crate) fn lstat(&self, logical: &Path) -> io::Result<Meta> {
        let fd = self.open_at(logical, OFlags::PATH | OFlags::NOFOLLOW)?;
        Ok(Meta::from_stat(&rfs::fstat(&fd)?))
    }

    /// Reads a regular file as (lossy) UTF-8, at most [`MAX_READ`] bytes.
    pub(crate) fn read_text(&self, logical: &Path) -> io::Result<Text> {
        let fd = self.open_at(logical, OFlags::RDONLY | OFlags::NONBLOCK)?;
        let meta = Meta::from_stat(&rfs::fstat(&fd)?);
        if meta.kind != Kind::File {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        let mut buf = vec![0u8; MAX_READ + 1];
        let mut len = 0;
        while len < buf.len() {
            match rustix::io::read(fd.as_fd(), &mut buf[len..]) {
                Ok(0) => break,
                Ok(n) => len += n,
                Err(Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let truncated = len > MAX_READ;
        buf.truncate(len.min(MAX_READ));
        Ok(Text {
            text: String::from_utf8_lossy(&buf).into_owned(),
            meta,
            truncated,
        })
    }

    /// Feeds a regular file's content to `f` in chunks. Returns `false`
    /// (having stopped early) when the file is larger than `max` bytes.
    pub(crate) fn read_chunks(
        &self,
        logical: &Path,
        max: u64,
        mut f: impl FnMut(&[u8]),
    ) -> io::Result<bool> {
        let fd = self.open_at(logical, OFlags::RDONLY | OFlags::NONBLOCK)?;
        let st = rfs::fstat(&fd)?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        if u64::try_from(st.st_size).unwrap_or(u64::MAX) > max {
            return Ok(false);
        }
        let mut buf = vec![0u8; 256 * 1024];
        let mut total = 0u64;
        loop {
            match rustix::io::read(fd.as_fd(), &mut buf) {
                Ok(0) => return Ok(true),
                Ok(n) => {
                    total += n as u64;
                    if total > max {
                        return Ok(false);
                    }
                    f(&buf[..n]);
                }
                Err(Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Directory entries (without `.` and `..`), sorted by name. Names that
    /// are not UTF-8 are included lossily.
    pub(crate) fn read_dir(&self, logical: &Path) -> io::Result<Vec<Entry>> {
        let fd = self.open_at(logical, OFlags::RDONLY | OFlags::DIRECTORY)?;
        let dir = rfs::Dir::read_from(&fd)?;
        let mut out = Vec::new();
        for entry in dir {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy();
            if name == "." || name == ".." {
                continue;
            }
            let kind = match entry.file_type() {
                FileType::RegularFile => Kind::File,
                FileType::Directory => Kind::Dir,
                FileType::Symlink => Kind::Symlink,
                _ => Kind::Other,
            };
            out.push(Entry {
                name: name.into_owned(),
                kind,
            });
            if out.len() >= MAX_DIR_ENTRIES {
                break;
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// The host path of the file `logical` resolves to inside the root, for
    /// handing it to the content scanner.
    pub(crate) fn host_path(&self, logical: &Path) -> io::Result<PathBuf> {
        let fd = self.open_at(logical, OFlags::PATH)?;
        let st = rfs::fstat(&fd)?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        let link = std::fs::read_link(format!(
            "/proc/self/fd/{}",
            std::os::fd::AsRawFd::as_raw_fd(&fd)
        ))?;
        // Double-check the resolved path is the same file.
        let again = rfs::stat(&link)?;
        if again.st_dev != st.st_dev || again.st_ino != st.st_ino {
            return Err(io::Error::other("file changed while resolving"));
        }
        Ok(link)
    }
}

/// `logical` without its leading `/`, for opening relative to the root.
fn relative(logical: &Path) -> &Path {
    let rel = logical.strip_prefix("/").unwrap_or(logical);
    if rel.as_os_str().is_empty() {
        Path::new(".")
    } else {
        rel
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn absolute_links_stay_inside_the_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("tempdir");
        std::fs::write(outside.path().join("secret"), "host").expect("write");
        std::fs::create_dir(dir.path().join("etc")).expect("mkdir");
        std::fs::write(dir.path().join("etc/real"), "image").expect("write");
        symlink("/etc/real", dir.path().join("etc/abs")).expect("symlink");
        symlink(outside.path().join("secret"), dir.path().join("etc/escape")).expect("symlink");
        symlink("../../../../../../etc/real", dir.path().join("etc/dots")).expect("symlink");

        let root = Root::open(dir.path()).expect("open");
        assert!(!root.is_live());
        assert_eq!(
            root.read_text(Path::new("/etc/abs")).expect("read").text,
            "image"
        );
        assert_eq!(
            root.read_text(Path::new("/etc/dots")).expect("read").text,
            "image"
        );
        // The absolute target is looked up inside the root, where it does not exist.
        assert!(root.read_text(Path::new("/etc/escape")).is_err());
        assert_eq!(
            root.lstat(Path::new("/etc/abs")).expect("lstat").kind,
            Kind::Symlink
        );
        let names: Vec<_> = root
            .read_dir(Path::new("/etc"))
            .expect("dir")
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["abs", "dots", "escape", "real"]);
        let host = root.host_path(Path::new("/etc/abs")).expect("host path");
        assert_eq!(
            host,
            dir.path().canonicalize().expect("canon").join("etc/real")
        );
    }

    #[test]
    fn only_regular_files_are_read_and_reads_are_bounded() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("big"), vec![b'a'; MAX_READ + 10]).expect("write");
        let root = Root::open(dir.path()).expect("open");
        let t = root.read_text(Path::new("/big")).expect("read");
        assert!(t.truncated);
        assert_eq!(t.text.len(), MAX_READ);
        assert!(root.read_text(Path::new("/")).is_err());
    }

    #[test]
    fn permission_predicates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("f");
        std::fs::write(&f, "x").expect("write");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let root = Root::open(dir.path()).expect("open");
        let m = root.stat(Path::new("/f")).expect("stat");
        assert_eq!(m.mode, 0o644);
        let root_owned = |mode, gid| Meta {
            uid: 0,
            gid,
            mode,
            ..m
        };
        assert!(!root_owned(0o755, 0).writable_by_non_root());
        assert!(root_owned(0o775, 10).writable_by_non_root());
        assert!(!root_owned(0o775, 0).writable_by_non_root());
        assert!(root_owned(0o757, 0).writable_by_non_root());
        assert!(!root_owned(0o1777, 0).dir_writable_by_non_root());
        assert!(root_owned(0o777, 0).dir_writable_by_non_root());
        assert!(
            Meta {
                uid: 1000,
                ..root_owned(0o755, 0)
            }
            .writable_by_non_root()
        );
    }
}
