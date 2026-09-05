//! Filesystem path policy for activity scopes, independent of macOS process APIs.

use std::path::PathBuf;

/// Ascend from `start` to the nearest directory containing a `.git` entry
/// (dir or file — worktrees use a file). Depth-capped as a syscall bound on
/// pathological trees.
pub(super) fn find_git_root(start: &std::path::Path) -> Option<PathBuf> {
    let mut dir = start;
    for _ in 0..64 {
        if dir.join(".git").exists() {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
    None
}

/// A `.git` root is an acceptable workspace boundary only when it does not
/// pool unrelated work into one bucket:
///
/// - a dotfiles repository AT `$HOME` (`git init ~`, yadm) would make every
///   caller anywhere under the home directory share one grant scope — the
///   exact broad bucket the `cwd_fallback_acceptable` exclusions exist to
///   prevent;
/// - symmetrically, when the cwd lives under `$HOME`, a root found ABOVE
///   `$HOME` (e.g. a stray `/Users/.git`) is rejected rather than pooling
///   every user directory.
///
/// Both degrade to the narrower cwd fallback (or Fresh), never to a wider
/// scope.
pub(super) fn workspace_root_acceptable(
    root: &std::path::Path,
    cwd: &std::path::Path,
    home: Option<&std::path::Path>,
) -> bool {
    let Some(home) = home else { return true };
    if root == home {
        return false;
    }
    if cwd.starts_with(home) && !root.starts_with(home) {
        return false;
    }
    true
}

/// A cwd with no `.git` ancestor may serve as its own grant scope, but only
/// when it is not a directory that many unrelated activities share: `$HOME`
/// and its ancestors (`/`, `/Users`) are the launch cwd of practically every
/// interactive process, and the shared temp roots pool ephemeral work.
/// Subdirectories of these (e.g. `/private/tmp/scratch`) remain acceptable —
/// they name one activity. `cwd` must already be canonical (F_GETPATH), so
/// `/tmp` arrives as `/private/tmp`. The macOS resolver separately excludes the
/// kernel-derived per-user temporary directory after this shared-root check.
pub(super) fn cwd_root_acceptable(cwd: &std::path::Path, home: Option<&std::path::Path>) -> bool {
    if let Some(home) = home {
        if cwd == home || home.starts_with(cwd) {
            return false;
        }
    }
    const SHARED_ROOTS: &[&str] = &[
        "/tmp",
        "/private/tmp",
        "/var/tmp",
        "/private/var/tmp",
        "/Volumes",
    ];
    if SHARED_ROOTS.iter().any(|r| cwd == std::path::Path::new(r)) {
        return false;
    }
    true
}

/// True when `path` (the peer's canonical executable path from
/// `proc_pidpath`) is an OpenSSH client binary, matched by basename so any
/// install location (system, homebrew, nix) qualifies. A renamed copy evades
/// the match — acceptable: it lands in the unbound-non-ssh workspace arm,
/// which stays within the documented same-UID concession
/// (docs/authorization-scopes-v2.md §3.3).
pub(super) fn is_ssh_client_path(path: &str) -> bool {
    path.rsplit('/').next() == Some("ssh")
}
