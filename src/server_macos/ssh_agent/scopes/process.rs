//! macOS kernel process queries used only for peer attribution and scope discovery.

const PROC_PIDTBSDINFO: libc::c_int = 3;
const MAXPATHLEN: u32 = 1024;
const MAXCOMLEN: usize = 16;

#[repr(C)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    rfu_1: u32,
    pbi_comm: [u8; MAXCOMLEN],
    pbi_name: [u8; 2 * MAXCOMLEN],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

extern "C" {
    fn proc_pidinfo(
        pid: libc::c_int,
        flavor: libc::c_int,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
    fn proc_pidpath(pid: libc::c_int, buffer: *mut libc::c_void, buffersize: u32) -> libc::c_int;
}

/// Get process BSD info: returns (ppid, tdev, start_tvsec) or None.
pub(super) fn get_proc_bsdinfo(pid: i32) -> Option<(u32, u32, u64)> {
    let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<ProcBsdInfo>() as libc::c_int;
    let ret = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    if ret == size {
        Some((info.pbi_ppid, info.e_tdev, info.pbi_start_tvsec))
    } else {
        None
    }
}

/// Get process executable path.
pub(super) fn get_proc_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; MAXPATHLEN as usize];
    let ret = unsafe { proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, MAXPATHLEN) };
    if ret > 0 {
        buf.truncate(ret as usize);
        String::from_utf8(buf).ok()
    } else {
        None
    }
}

/// Get the controlling TTY device number for a process. Returns None
/// for processes with no controlling terminal (`tdev == 0`). Diag-only
/// since scopes V2; behavior must never depend on it.
pub(super) fn get_tty_dev(pid: i32) -> Option<u32> {
    let (_, tdev, _) = get_proc_bsdinfo(pid)?;
    if tdev == 0 {
        None
    } else {
        Some(tdev)
    }
}

const PROC_PIDVNODEPATHINFO: libc::c_int = 9;

/// Layout mirror of `struct vnode_info_path` from `<sys/proc_info.h>`:
/// `struct vnode_info` (a 136-byte `vinfo_stat` + type/pad/fsid = 152
/// bytes, opaque here) followed by a MAXPATHLEN path buffer.
#[repr(C)]
struct VnodeInfoPath {
    vip_vi: [u8; 152],
    vip_path: [u8; MAXPATHLEN as usize],
}

#[repr(C)]
struct ProcVnodePathInfo {
    pvi_cdir: VnodeInfoPath,
    pvi_rdir: VnodeInfoPath,
}

/// NUL-terminated kernel path buffer → PathBuf. `None` on a missing
/// NUL, an empty path, or non-UTF-8 bytes (callers degrade to Fresh).
pub(super) fn nul_terminated_path(buf: &[u8]) -> Option<std::path::PathBuf> {
    let len = buf.iter().position(|&b| b == 0)?;
    if len == 0 {
        return None;
    }
    let s = std::str::from_utf8(&buf[..len]).ok()?;
    Some(std::path::PathBuf::from(s))
}

/// Kernel-derived current working directory of `pid`
/// (`proc_pidinfo(PROC_PIDVNODEPATHINFO)` → `pvi_cdir.vip_path`). Same
/// trust level as `get_proc_path`; `None` on any failure. The strict
/// `ret == size` check makes a layout mismatch fail closed instead of
/// reading a truncated struct.
pub(super) fn get_cwd(pid: i32) -> Option<std::path::PathBuf> {
    const _: () = assert!(std::mem::size_of::<ProcVnodePathInfo>() == 2 * (152 + 1024));
    let mut info: ProcVnodePathInfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<ProcVnodePathInfo>() as libc::c_int;
    let ret = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDVNODEPATHINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    if ret != size {
        return None;
    }
    nul_terminated_path(&info.pvi_cdir.vip_path)
}

/// Get the process start time (seconds since epoch).
pub(super) fn get_start_tvsec(pid: i32) -> Option<u64> {
    get_proc_bsdinfo(pid).map(|(_, _, s)| s)
}

/// Fetch a process's argv via `sysctl(KERN_PROCARGS2)`, kernel-derived (same
/// trust level as `proc_pidpath`). `None` on any sysctl failure or malformed
/// buffer — callers treat that as "not the vt relay". The byte-buffer parse
/// itself is the pure, host-tested `ssh_sign::parse_procargs2`.
pub(super) fn get_proc_argv(pid: i32) -> Option<Vec<String>> {
    // 1. Upper bound on the args buffer size (`kern.argmax`).
    let mut argmax: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            &mut argmax as *mut _ as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || argmax <= 0 {
        return None;
    }

    // 2. Fetch KERN_PROCARGS2 for `pid` into a buffer of that size.
    let mut buf = vec![0u8; argmax as usize];
    let mut size = buf.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || size == 0 || size > buf.len() {
        return None;
    }
    buf.truncate(size);
    crate::ssh_sign::parse_procargs2(&buf)
}

/// Get the peer PID from a Unix stream using macOS LOCAL_PEERPID.
pub(super) fn get_peer_pid(stream: &tokio::net::UnixStream) -> Option<i32> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut pid: libc::pid_t = 0;
    let mut pid_size = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 0x002;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut pid_size,
        )
    };
    if ret == 0 && pid > 0 {
        Some(pid)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // --- proc_info tests (macOS only, require running process) ---

    #[test]
    #[ignore]
    fn test_proc_bsdinfo_self() {
        let pid = std::process::id() as i32;
        let result = get_proc_bsdinfo(pid);
        assert!(result.is_some(), "Should be able to query own process");
        let (ppid, _tdev, start) = result.unwrap();
        assert!(ppid > 0, "Parent PID should be positive");
        assert!(start > 0, "Start time should be positive");
    }

    #[test]
    #[ignore]
    fn test_proc_path_self() {
        let pid = std::process::id() as i32;
        let result = get_proc_path(pid);
        assert!(result.is_some(), "Should be able to get own process path");
        let path = result.unwrap();
        assert!(!path.is_empty(), "Path should not be empty");
    }
}
