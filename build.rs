//! Build-time version stamping.
//!
//! The user-facing version is CalVer-style, sourced from the git tag rather than
//! `Cargo.toml`'s SemVer (which stays a valid placeholder cargo requires). The
//! single source of truth is `git describe`:
//!   * on a release tag  → the exact tag, e.g. `v20260702-bc6f49c`
//!   * N commits later   → `v20260702-bc6f49c-<N>-g<hash>`
//!   * dirty worktree    → `…-dirty`
//!   * no tags / no git  → short hash, else `unknown`
//!
//! CI note: `actions/checkout` does a shallow clone that may not have the tag
//! object locally, so `git describe` can fail there. The release workflow sets
//! `VT_VERSION_OVERRIDE=${{ github.ref_name }}`, which takes precedence — so a
//! released binary always reports exactly its release tag.

use std::env;
use std::process::Command;

fn main() {
    // Re-stamp when the commit, tags, staged index, or the CI override changes.
    // `.git/packed-refs` matters: git packs tags there (this repo already has
    // most tags packed), so watching only `.git/refs` would miss a fetched tag.
    // Known limitation: `git describe --dirty` also flags UNSTAGED tracked edits,
    // but those don't touch `.git/index`, so the baked `-dirty` suffix can lag
    // until the next commit/stage/rebuild. Release builds are unaffected (they
    // use VT_VERSION_OVERRIDE and CI checks out clean).
    println!("cargo:rerun-if-env-changed=VT_VERSION_OVERRIDE");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
    println!("cargo:rerun-if-changed=.git/packed-refs");
    println!("cargo:rerun-if-changed=.git/index");

    let version = env::var("VT_VERSION_OVERRIDE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| git(&["describe", "--tags", "--always", "--dirty"]))
        .unwrap_or_else(|| "unknown".to_string());

    let sha = git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let date = git(&[
        "show",
        "-s",
        "--format=%cd",
        "--date=format:%Y-%m-%d",
        "HEAD",
    ])
    .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=VT_VERSION={version}");
    println!("cargo:rustc-env=VT_GIT_SHA={sha}");
    println!("cargo:rustc-env=VT_COMMIT_DATE={date}");
}

/// Run a git command, returning its trimmed stdout, or `None` on failure/empty.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}
