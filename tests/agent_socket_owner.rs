#![cfg(unix)]

#[path = "../src/server_macos/socket_owner.rs"]
mod socket_owner;

use socket_owner::SocketOwner;
use std::fs;
use std::io;
use std::os::unix::fs::{symlink, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vt-socket-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn socket(&self) -> PathBuf {
        self.0.join("vt.sock")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn identity(path: &std::path::Path) -> (u64, u64) {
    let metadata = fs::symlink_metadata(path).unwrap();
    (metadata.dev(), metadata.ino())
}

fn bind_error(path: &std::path::Path) -> io::Error {
    SocketOwner::bind(path).err().expect("binding should fail")
}

#[test]
fn second_owner_cannot_replace_socket_or_remove_it_on_failure() {
    let dir = TestDir::new();
    let path = dir.socket();
    let (_owner, _listener) = SocketOwner::bind(&path).unwrap();
    let original = identity(&path);
    assert_eq!(bind_error(&path).kind(), io::ErrorKind::AddrInUse);
    assert_eq!(identity(&path), original);
    assert!(UnixStream::connect(&path).is_ok());
}

#[test]
fn stale_socket_is_replaced_and_persistent_lock_is_reused() {
    let dir = TestDir::new();
    let path = dir.socket();
    drop(UnixListener::bind(&path).unwrap());
    let (owner, listener) = SocketOwner::bind(&path).unwrap();
    let lock = dir.0.join("vt.sock.lock");
    let lock_id = identity(&lock);
    assert_eq!(fs::metadata(&lock).unwrap().mode() & 0o777, 0o600);
    drop(listener);
    drop(owner);
    assert!(!path.exists());
    let (_next, _listener) = SocketOwner::bind(&path).unwrap();
    assert_eq!(identity(&lock), lock_id);
}

#[test]
fn live_legacy_listener_is_not_unlinked() {
    let dir = TestDir::new();
    let path = dir.socket();
    let _legacy = UnixListener::bind(&path).unwrap();
    let original = identity(&path);
    assert_eq!(bind_error(&path).kind(), io::ErrorKind::AddrInUse);
    assert_eq!(identity(&path), original);
}

#[test]
fn cleanup_and_drop_preserve_a_replacement_socket() {
    let dir = TestDir::new();
    let path = dir.socket();
    let (owner, _listener) = SocketOwner::bind(&path).unwrap();
    fs::remove_file(&path).unwrap();
    let _replacement = UnixListener::bind(&path).unwrap();
    let replacement = identity(&path);
    owner.cleanup().unwrap();
    drop(owner);
    assert_eq!(identity(&path), replacement);
    assert!(UnixStream::connect(&path).is_ok());
}

#[test]
fn non_socket_and_symlink_paths_are_preserved() {
    let dir = TestDir::new();
    let path = dir.socket();
    fs::write(&path, "not a socket").unwrap();
    assert_eq!(bind_error(&path).kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read_to_string(&path).unwrap(), "not a socket");
    fs::remove_file(&path).unwrap();
    let target = dir.0.join("target");
    fs::write(&target, "unchanged").unwrap();
    symlink(&target, &path).unwrap();
    assert_eq!(bind_error(&path).kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read_to_string(&target).unwrap(), "unchanged");
    assert!(fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn symlink_and_hardlinked_locks_are_refused() {
    let dir = TestDir::new();
    let lock = dir.0.join("vt.sock.lock");
    let target = dir.0.join("target");
    fs::write(&target, "unchanged").unwrap();
    symlink(&target, &lock).unwrap();
    assert!(SocketOwner::bind(&dir.socket()).is_err());
    fs::remove_file(&lock).unwrap();
    fs::hard_link(&target, &lock).unwrap();
    assert_eq!(
        bind_error(&dir.socket()).kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(fs::read_to_string(&target).unwrap(), "unchanged");
}

#[test]
fn spawned_child_does_not_retain_ownership_after_exec() {
    let dir = TestDir::new();
    let path = dir.socket();
    let (owner, listener) = SocketOwner::bind(&path).unwrap();
    let mut child = Command::new("/bin/sh")
        .args(["-c", "exec sleep 30"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    drop(listener);
    drop(owner);
    let next = SocketOwner::bind(&path);
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        next.is_ok(),
        "child inherited socket ownership: {:?}",
        next.err()
    );
}
