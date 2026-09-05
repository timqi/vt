//! Lifetime ownership of the agent's filesystem socket. Kept Unix-only so the
//! ownership protocol can also be regression-tested without macOS/Keychain.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

pub struct SocketOwner {
    // Never unlink this file: all generations must flock the same inode. The
    // fd is CLOEXEC so launched commands cannot retain the agent's ownership.
    _lock: File,
    path: PathBuf,
    socket_id: Option<(u64, u64)>,
}

impl SocketOwner {
    pub fn bind(path: &Path) -> io::Result<(Self, UnixListener)> {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "agent socket has no parent")
        })?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lock_path)?;
        let metadata = lock.metadata()?;
        // SAFETY: geteuid has no preconditions.
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "agent lock must be a regular, singly-linked file owned by this user",
            ));
        }
        // SAFETY: the file owns a valid descriptor for the entire flock call.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            return Err(if error.kind() == io::ErrorKind::WouldBlock {
                io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "another vt agent owns this socket",
                )
            } else {
                error
            });
        }
        let named = fs::symlink_metadata(&lock_path)?;
        if (named.dev(), named.ino()) != (metadata.dev(), metadata.ino()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "agent lock path changed while acquiring ownership",
            ));
        }
        let mut owner = Self {
            _lock: lock,
            path: path.to_owned(),
            socket_id: None,
        };
        owner.remove_stale_socket()?;
        let listener = UnixListener::bind(path)?;
        let metadata = fs::symlink_metadata(path)?;
        owner.socket_id = Some((metadata.dev(), metadata.ino()));
        Ok((owner, listener))
    }

    fn remove_stale_socket(&self) -> io::Result<()> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "refusing to replace a non-socket at the agent socket path",
            ));
        }
        // Older agents have no ownership lock. Refuse a live/busy listener too;
        // a nonblocking connect avoids hanging on a full accept queue.
        if socket_is_live(&self.path)? {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "an existing agent is listening on this socket; stop it first",
            ));
        }
        remove_socket_generation(&self.path, (metadata.dev(), metadata.ino()))
    }

    pub fn cleanup(&self) -> io::Result<()> {
        match self.socket_id {
            Some(id) => remove_socket_generation(&self.path, id),
            None => Ok(()),
        }
    }
}

impl Drop for SocketOwner {
    fn drop(&mut self) {
        let _ = self.cleanup();
        // Release explicitly: a concurrent fork may briefly retain a copy of
        // the open file description before CLOEXEC closes it in the child.
        // SAFETY: the lock file is still open until after this destructor.
        unsafe { libc::flock(self._lock.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn remove_socket_generation(path: &Path, id: (u64, u64)) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket() && (metadata.dev(), metadata.ino()) == id =>
        {
            match fs::remove_file(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                result => result,
            }
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn socket_is_live(path: &Path) -> io::Result<bool> {
    // SAFETY: socket returns a new descriptor or -1; only the former is owned.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is newly created and has no other Rust owner.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: both fcntl calls operate on our live descriptor.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: zero is valid for every field of sockaddr_un.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid agent socket path",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dest, byte) in address.sun_path.iter_mut().zip(bytes) {
        *dest = *byte as libc::c_char;
    }
    let len =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
    #[cfg(target_os = "macos")]
    {
        address.sun_len = len as u8;
    }
    // SAFETY: address is initialized and len describes its populated prefix.
    if unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            len,
        )
    } == 0
    {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ECONNREFUSED | libc::ENOENT) => Ok(false),
        Some(libc::EINPROGRESS | libc::EALREADY | libc::EAGAIN) => Ok(true),
        _ => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetime_lock_is_close_on_exec() {
        let dir = std::env::temp_dir().join(format!(
            "vt-lock-flags-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let (owner, listener) = SocketOwner::bind(&dir.join("vt.sock")).unwrap();
        // SAFETY: owner retains the live lock fd throughout this check.
        let flags = unsafe { libc::fcntl(owner._lock.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        drop(listener);
        drop(owner);
        fs::remove_dir_all(dir).unwrap();
    }
}
