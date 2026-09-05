#![cfg(unix)]

#[path = "../src/server_macos/ssh_agent/scopes/paths.rs"]
mod paths;

use std::path::Path;

#[test]
fn git_root_prefers_nearest_directory_or_worktree_marker() {
    let root = std::env::temp_dir().join(format!(
        "vt-scope-paths-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let inner = root.join("inner");
    let leaf = inner.join("leaf");
    std::fs::create_dir_all(&leaf).unwrap();
    std::fs::create_dir(root.join(".git")).unwrap();
    assert_eq!(paths::find_git_root(&leaf), Some(root.clone()));
    std::fs::write(inner.join(".git"), "gitdir: elsewhere").unwrap();
    assert_eq!(paths::find_git_root(&leaf), Some(inner));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn workspace_root_does_not_pool_home_or_its_ancestors() {
    let home = Path::new("/Users/test");
    let project = home.join("project");
    assert!(!paths::workspace_root_acceptable(
        home,
        &project,
        Some(home)
    ));
    assert!(!paths::workspace_root_acceptable(
        Path::new("/Users"),
        &project,
        Some(home)
    ));
    assert!(paths::workspace_root_acceptable(
        &project,
        &project,
        Some(home)
    ));
    assert!(paths::workspace_root_acceptable(
        Path::new("/opt/project"),
        Path::new("/opt/project/sub"),
        Some(home)
    ));
    assert!(paths::workspace_root_acceptable(home, &project, None));
}

#[test]
fn cwd_fallback_excludes_shared_roots_but_accepts_their_children() {
    let home = Path::new("/Users/test");
    for shared in [
        "/",
        "/Users",
        "/Users/test",
        "/tmp",
        "/private/tmp",
        "/var/tmp",
        "/private/var/tmp",
        "/Volumes",
    ] {
        assert!(
            !paths::cwd_root_acceptable(Path::new(shared), Some(home)),
            "{shared}"
        );
    }
    for specific in [
        "/Users/test/notes",
        "/tmp/job",
        "/private/var/folders/test/T/job",
    ] {
        assert!(
            paths::cwd_root_acceptable(Path::new(specific), Some(home)),
            "{specific}"
        );
    }
    assert!(!paths::cwd_root_acceptable(Path::new("/tmp"), None));
    assert!(paths::cwd_root_acceptable(Path::new("/opt/job"), None));
}

#[test]
fn ssh_peer_detection_matches_only_the_executable_basename() {
    for executable in ["ssh", "/usr/bin/ssh", "/opt/homebrew/bin/ssh"] {
        assert!(paths::is_ssh_client_path(executable));
    }
    for executable in ["", "sshd", "/usr/bin/ssh-agent", "/usr/bin/notssh"] {
        assert!(!paths::is_ssh_client_path(executable));
    }
}
