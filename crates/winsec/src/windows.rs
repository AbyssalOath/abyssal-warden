//! Win32 FFI. Each `unsafe` block performs one call or one pointer
//! operation and states why it is sound. Handles and allocations are owned
//! by RAII types immediately after they are returned.

use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
    LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
    GetNamedSecurityInfoW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SE_KERNEL_OBJECT,
    SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, CheckTokenMembership, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
    GetTokenInformation, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX,
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_NAME_NORMALIZED, FileDispositionInfo,
    FileDispositionInfoEx, GetFinalPathNameByHandleW, PIPE_ACCESS_DUPLEX,
    SetFileInformationByHandle, VOLUME_NAME_DOS,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, RegisterEventSourceW,
    ReportEventW,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    QueryFullProcessImageNameW, TerminateProcess,
};

use crate::sddl;

/// NUL-terminated UTF-16; interior NULs are refused.
fn wide(s: &OsStr) -> io::Result<Vec<u16>> {
    let mut v: Vec<u16> = s.encode_wide().collect();
    if v.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "string contains NUL",
        ));
    }
    v.push(0);
    Ok(v)
}

/// Memory returned by the system that must be released with `LocalFree`.
struct LocalMem(HLOCAL);

impl Drop for LocalMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer was returned by an API documented to
            // allocate with LocalAlloc, and is freed exactly once here.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// Reads a NUL-terminated UTF-16 string.
///
/// # Safety
/// `p` must point to a readable, NUL-terminated UTF-16 string.
unsafe fn from_wide_ptr(p: *const u16) -> String {
    let mut len = 0usize;
    loop {
        let q = p.wrapping_add(len);
        // SAFETY: the caller guarantees a NUL terminator, so every offset up
        // to and including it is readable.
        if unsafe { *q } == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: `len` elements were just read from `p`.
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16_lossy(slice)
}

/// Takes ownership of a handle returned by a Win32 call (`null` and
/// `INVALID_HANDLE_VALUE` are errors).
fn own(h: HANDLE) -> io::Result<OwnedHandle> {
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `h` is a valid handle just returned to us and not owned by
    // anything else.
    Ok(unsafe { OwnedHandle::from_raw_handle(h) })
}

fn check(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Owner and DACL of a file or directory, as SDDL.
pub fn security_descriptor(path: &Path) -> io::Result<String> {
    let name = wide(path.as_os_str())?;
    let mut psd: PSECURITY_DESCRIPTOR = null_mut();
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    // SAFETY: `name` is NUL-terminated; all out-pointers are valid locals;
    // the descriptor is freed by LocalMem below.
    let err = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut psd,
        )
    };
    if err != 0 {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    let _sd = LocalMem(psd);
    descriptor_to_string(psd)
}

fn descriptor_to_string(psd: PSECURITY_DESCRIPTOR) -> io::Result<String> {
    let mut out: *mut u16 = null_mut();
    // SAFETY: `psd` is a valid descriptor owned by the caller; `out`
    // receives a LocalAlloc'd string freed below.
    check(unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut out,
            null_mut(),
        )
    })?;
    let _mem = LocalMem(out.cast());
    // SAFETY: the API returned a NUL-terminated string.
    Ok(unsafe { from_wide_ptr(out) })
}

/// Replaces the DACL of `path` with `dacl_sddl` (e.g. from
/// [`sddl::private_dacl`]) and stops inheritance from the parent.
pub fn set_protected_dacl(path: &Path, dacl_sddl: &str) -> io::Result<()> {
    let text = wide(OsStr::new(dacl_sddl))?;
    let mut psd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `text` is NUL-terminated; `psd` receives a LocalAlloc'd
    // descriptor freed by LocalMem.
    check(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut psd,
            null_mut(),
        )
    })?;
    let _sd = LocalMem(psd);
    let (mut present, mut defaulted) = (0i32, 0i32);
    let mut dacl: *mut ACL = null_mut();
    // SAFETY: `psd` is valid; the DACL pointer points into it and is used
    // only while `_sd` is alive.
    check(unsafe { GetSecurityDescriptorDacl(psd, &mut present, &mut dacl, &mut defaulted) })?;
    if present == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the SDDL has no DACL",
        ));
    }
    let name = wide(path.as_os_str())?;
    // SAFETY: `name` is NUL-terminated and `dacl` is valid for the call.
    let err = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if err != 0 {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    Ok(())
}

fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut out: *mut u16 = null_mut();
    // SAFETY: `sid` is a valid SID owned by the caller; `out` is freed below.
    check(unsafe { ConvertSidToStringSidW(sid, &mut out) })?;
    let _mem = LocalMem(out.cast());
    // SAFETY: the API returned a NUL-terminated string.
    Ok(unsafe { from_wide_ptr(out) })
}

fn token_user_sid(token: &OwnedHandle) -> io::Result<String> {
    let mut len = 0u32;
    // SAFETY: querying the size with a null buffer is documented.
    let ok =
        unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut len) };
    if ok == 0
        && io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
    {
        return Err(io::Error::last_os_error());
    }
    // u64 storage keeps the TOKEN_USER (pointer-aligned) correctly aligned.
    let mut buf = vec![0u64; (len as usize).div_ceil(8) + 1];
    let cap = u32::try_from(buf.len() * 8).map_err(io::Error::other)?;
    // SAFETY: `buf` is writable for `cap` bytes.
    check(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buf.as_mut_ptr().cast(),
            cap,
            &mut len,
        )
    })?;
    // SAFETY: on success the buffer starts with an initialised, aligned
    // TOKEN_USER whose SID points into the same buffer (alive here).
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    sid_to_string(sid)
}

/// Membership of BUILTIN\Administrators, counting only enabled groups (a
/// non-elevated UAC token does not count). `None` checks this thread.
fn token_is_admin(token: Option<&OwnedHandle>) -> io::Result<bool> {
    let text = wide(OsStr::new(sddl::ADMINISTRATORS))?;
    let mut sid: PSID = null_mut();
    // SAFETY: `text` is NUL-terminated; `sid` is LocalAlloc'd, freed below.
    check(unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid) })?;
    let _mem = LocalMem(sid);
    let mut member = 0i32;
    let handle = token.map_or(null_mut(), AsRawHandle::as_raw_handle);
    // SAFETY: `handle` is null (current thread) or a valid token; `sid` is valid.
    check(unsafe { CheckTokenMembership(handle, sid, &mut member) })?;
    Ok(member != 0)
}

fn process_token() -> io::Result<OwnedHandle> {
    let mut h: HANDLE = null_mut();
    // SAFETY: returns a pseudo-handle that needs no closing.
    let me = unsafe { GetCurrentProcess() };
    // SAFETY: `me` is the process pseudo-handle; `h` is a valid out-pointer.
    check(unsafe { OpenProcessToken(me, TOKEN_QUERY, &mut h) })?;
    own(h)
}

/// SID of the user this process runs as.
pub fn process_user_sid() -> io::Result<String> {
    token_user_sid(&process_token()?)
}

/// Whether this process runs elevated as an administrator (or as SYSTEM).
pub fn process_is_admin() -> io::Result<bool> {
    token_is_admin(None)
}

/// The normalised full path of an open file (reparse points resolved), in
/// `\\?\` form.
pub fn final_path(file: &File) -> io::Result<PathBuf> {
    let mut buf = vec![0u16; 512];
    loop {
        let cap = u32::try_from(buf.len()).map_err(io::Error::other)?;
        // SAFETY: `buf` is writable for `cap` UTF-16 units.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                buf.as_mut_ptr(),
                cap,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if (n as usize) < buf.len() {
            buf.truncate(n as usize);
            return Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf)));
        }
        if buf.len() > 1 << 16 {
            return Err(io::Error::other("path too long"));
        }
        buf.resize(n as usize + 1, 0);
    }
}

/// Deletes the file behind `file` (POSIX semantics where supported: the
/// name disappears at once). The handle must have DELETE access.
pub fn delete_by_handle(file: &File) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    // SAFETY: `info` is a valid FILE_DISPOSITION_INFO_EX of the given size.
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            (&raw const info).cast::<c_void>(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if ok != 0 {
        return Ok(());
    }
    // Filesystems without POSIX deletion (FAT): delete on last close.
    let legacy = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: `legacy` is a valid FILE_DISPOSITION_INFO of the given size.
    check(unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&raw const legacy).cast::<c_void>(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    })
}

/// Owner SID of the named pipe (or other kernel object) behind `file`.
/// Used by clients to check they reached the real service, not a pipe
/// created first by another user.
pub fn pipe_owner_sid(file: &File) -> io::Result<String> {
    let mut owner: PSID = null_mut();
    let mut psd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: the handle is valid (READ_CONTROL access); out-pointers are
    // locals; the descriptor is freed by LocalMem.
    let err = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut psd,
        )
    };
    if err != 0 {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    let _sd = LocalMem(psd);
    sid_to_string(owner)
}

/// A named-pipe server. Pipe instances carry the given security descriptor,
/// refuse remote clients, and the first instance fails if the name is
/// already taken (another process squatting it).
#[derive(Debug)]
pub struct PipeListener {
    name: Vec<u16>,
    sddl: Vec<u16>,
    next: Option<OwnedHandle>,
}

impl PipeListener {
    /// `name` like `\\.\pipe\AbyssalWarden`.
    pub fn bind(name: &str, sddl: &str) -> io::Result<Self> {
        let mut me = Self {
            name: wide(OsStr::new(name))?,
            sddl: wide(OsStr::new(sddl))?,
            next: None,
        };
        me.next = Some(me.instance(true)?);
        Ok(me)
    }

    fn instance(&self, first: bool) -> io::Result<OwnedHandle> {
        let mut psd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `sddl` is NUL-terminated; `psd` is freed by LocalMem.
        check(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                self.sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                null_mut(),
            )
        })?;
        let _sd = LocalMem(psd);
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd,
            bInheritHandle: 0,
        };
        let open_mode = PIPE_ACCESS_DUPLEX
            | if first {
                FILE_FLAG_FIRST_PIPE_INSTANCE
            } else {
                0
            };
        // SAFETY: `name` is NUL-terminated and `sa` (with `psd`) is valid
        // for the call; the returned handle is owned below.
        let h = unsafe {
            CreateNamedPipeW(
                self.name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                &sa,
            )
        };
        own(h)
    }

    /// Waits for a client.
    pub fn accept(&mut self) -> io::Result<PipeConnection> {
        let h = match self.next.take() {
            Some(h) => h,
            None => self.instance(false)?,
        };
        // SAFETY: `h` is a valid pipe handle; synchronous (no OVERLAPPED).
        let ok = unsafe { ConnectNamedPipe(h.as_raw_handle(), null_mut()) };
        if ok == 0 && io::Error::last_os_error().raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32)
        {
            return Err(io::Error::last_os_error());
        }
        self.next = self.instance(false).ok();
        Ok(PipeConnection {
            file: File::from(h),
        })
    }
}

/// Who is on the other end of a pipe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIdentity {
    pub sid: String,
    /// Elevated administrator (or SYSTEM).
    pub admin: bool,
    pub pid: u32,
}

/// A connected client.
#[derive(Debug)]
pub struct PipeConnection {
    file: File,
}

/// Forcibly ends a connection from another thread (for timeouts).
#[derive(Debug)]
pub struct Disconnector(OwnedHandle);

impl Disconnector {
    pub fn disconnect(&self) {
        // SAFETY: the handle (a duplicate of the pipe handle) is valid; a
        // pending read on the other handle then fails.
        unsafe { DisconnectNamedPipe(self.0.as_raw_handle()) };
    }
}

impl PipeConnection {
    /// The client's identity, taken from its token by impersonating it
    /// briefly. Call after reading from the pipe (Windows requires data to
    /// have been read first). Aborts the process if impersonation cannot be
    /// reverted, rather than continue with the client's identity.
    pub fn client(&self) -> io::Result<ClientIdentity> {
        let h = self.file.as_raw_handle();
        let mut pid = 0u32;
        // SAFETY: valid pipe handle and out-pointer.
        check(unsafe { GetNamedPipeClientProcessId(h, &mut pid) })?;
        // SAFETY: valid pipe handle.
        check(unsafe { ImpersonateNamedPipeClient(h) })?;
        let mut token: HANDLE = null_mut();
        // SAFETY: returns a pseudo-handle for this thread.
        let thread = unsafe { GetCurrentThread() };
        // SAFETY: `thread` is this thread's pseudo-handle; `token` is a valid out-pointer.
        let opened = unsafe { OpenThreadToken(thread, TOKEN_QUERY, 1, &mut token) };
        let opened_err = io::Error::last_os_error();
        // SAFETY: ends the impersonation started above.
        if unsafe { RevertToSelf() } == 0 {
            // Continuing as the client would be a privilege confusion.
            std::process::abort();
        }
        if opened == 0 {
            return Err(opened_err);
        }
        let token = own(token)?;
        Ok(ClientIdentity {
            sid: token_user_sid(&token)?,
            admin: token_is_admin(Some(&token))?,
            pid,
        })
    }

    pub fn disconnector(&self) -> io::Result<Disconnector> {
        Ok(Disconnector(self.file.try_clone().map(OwnedHandle::from)?))
    }
}

impl Read for PipeConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for PipeConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub image: Option<PathBuf>,
}

fn open_process(pid: u32, access: u32) -> io::Result<OwnedHandle> {
    // SAFETY: plain call; the handle is owned below.
    own(unsafe { OpenProcess(access, 0, pid) })
}

fn image_of(process: &OwnedHandle) -> io::Result<PathBuf> {
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` is writable for `len` units; `len` is updated.
    check(unsafe {
        QueryFullProcessImageNameW(
            process.as_raw_handle(),
            PROCESS_NAME_WIN32,
            buf.as_mut_ptr(),
            &mut len,
        )
    })?;
    buf.truncate(len as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf)))
}

/// Running processes with their image paths (where this process may query
/// them).
pub fn processes() -> io::Result<Vec<ProcessInfo>> {
    // SAFETY: plain call; the snapshot handle is owned below.
    let snap = own(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })?;
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..PROCESSENTRY32W::default()
    };
    let mut out = Vec::new();
    // SAFETY: valid snapshot handle and initialised entry with dwSize set.
    let mut ok = unsafe { Process32FirstW(snap.as_raw_handle(), &mut entry) };
    while ok != 0 && out.len() < 100_000 {
        let end = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        let pid = entry.th32ProcessID;
        let image = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)
            .and_then(|h| image_of(&h))
            .ok();
        out.push(ProcessInfo {
            pid,
            name: String::from_utf16_lossy(&entry.szExeFile[..end]),
            image,
        });
        // SAFETY: as above.
        ok = unsafe { Process32NextW(snap.as_raw_handle(), &mut entry) };
    }
    Ok(out)
}

/// Terminates `pid` if, checked through the same handle, it is still
/// running `image` (guards against PID reuse). Returns whether it did.
pub fn terminate_if_image(pid: u32, image: &Path) -> io::Result<bool> {
    let h = open_process(pid, PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION)?;
    let actual = image_of(&h)?;
    if !actual.as_os_str().eq_ignore_ascii_case(image.as_os_str()) {
        return Ok(false);
    }
    // SAFETY: valid process handle with PROCESS_TERMINATE access.
    check(unsafe { TerminateProcess(h.as_raw_handle(), 1) })?;
    Ok(true)
}

/// Writes one entry to the Application event log under `source`.
pub fn report_event(source: &str, message: &str, warning: bool) -> io::Result<()> {
    let src = wide(OsStr::new(source))?;
    let msg = wide(OsStr::new(message))?;
    // SAFETY: `src` is NUL-terminated; local machine (null server name).
    let h = unsafe { RegisterEventSourceW(null(), src.as_ptr()) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    struct Source(HANDLE);
    impl Drop for Source {
        fn drop(&mut self) {
            // SAFETY: handle from RegisterEventSourceW, released once.
            unsafe { DeregisterEventSource(self.0) };
        }
    }
    let src_handle = Source(h);
    let strings = [msg.as_ptr()];
    let kind = if warning {
        EVENTLOG_WARNING_TYPE
    } else {
        EVENTLOG_INFORMATION_TYPE
    };
    // SAFETY: one valid NUL-terminated string; no user SID or raw data.
    check(unsafe {
        ReportEventW(
            src_handle.0,
            kind,
            0,
            1,
            null_mut(),
            1,
            0,
            strings.as_ptr(),
            null(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;

    #[test]
    fn identity_and_descriptors() {
        let sid = process_user_sid().expect("sid");
        assert!(sid.starts_with("S-1-"), "{sid}");
        let _ = process_is_admin().expect("admin check");
        let dir = std::env::temp_dir().join(format!("aw-winsec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        set_protected_dacl(&dir, &sddl::private_dacl(&sid)).expect("set dacl");
        let text = security_descriptor(&dir).expect("read dacl");
        sddl::check_private(&text, &[sddl::SYSTEM, sddl::ADMINISTRATORS, &sid]).expect("private");
        let f = dir.join("x.txt");
        std::fs::write(&f, b"x").expect("write");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .access_mode(0x0012_0089 | 0x0001_0000)
            .open(&f)
            .expect("open");
        let fp = final_path(&file).expect("final path");
        assert!(
            fp.to_string_lossy().to_ascii_lowercase().ends_with("x.txt"),
            "{}",
            fp.display()
        );
        delete_by_handle(&file).expect("delete");
        drop(file);
        assert!(!f.exists());
        std::fs::remove_dir_all(&dir).expect("cleanup");
        assert!(
            processes()
                .expect("processes")
                .iter()
                .any(|p| p.pid == std::process::id())
        );
    }

    #[test]
    fn pipe_identifies_its_client() {
        let name = format!(r"\\.\pipe\aw-winsec-test-{}", std::process::id());
        let mut listener = PipeListener::bind(
            &name,
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x12008b;;;AU)",
        )
        .expect("bind");
        // A second server on the same name is refused.
        assert!(PipeListener::bind(&name, "D:P(A;;GA;;;OW)").is_err());
        let n2 = name.clone();
        let client = std::thread::spawn(move || {
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&n2)
                .expect("connect");
            f.write_all(b"ping").expect("send");
            let mut b = [0u8; 4];
            f.read_exact(&mut b).expect("reply");
            (b, pipe_owner_sid(&f).expect("owner"))
        });
        let mut conn = listener.accept().expect("accept");
        let mut b = [0u8; 4];
        conn.read_exact(&mut b).expect("read");
        let who = conn.client().expect("identity");
        assert_eq!(who.sid, process_user_sid().expect("sid"));
        assert_eq!(who.admin, process_is_admin().expect("admin"));
        conn.write_all(b"pong").expect("write");
        let (reply, owner) = client.join().expect("client");
        assert_eq!(&reply, b"pong");
        assert!(owner.starts_with("S-1-"));
    }
}
