//! `vt hook` — let AI coding agents use vt-protected secrets transparently.
//!
//! Agents (Claude Code, Cursor, …) expose a *PreToolUse* hook: before a shell
//! command runs, the agent hands the proposed command to an external program
//! and lets it **allow / deny / rewrite** the command. `vt hook` is that
//! program. It consults a whitelist (`[[rules]]` in the dedicated, syncable
//! `~/.config/vt/agent.toml`) and, for a matched command whose env vars hold
//! `vt://` ciphertext, rewrites it to run under `vt inject` so the child sees
//! plaintext. Those values may come from the process environment OR be supplied
//! centrally in the same file (`[env.default]` / per-PWD `[env.dirs."…"]`), so
//! the agent need not export anything.
//!
//! Three outcomes per command:
//!   * **accept** — emit nothing; the command runs unchanged. This is the
//!     default for any command not in the whitelist.
//!   * **block**  — emit a `deny` decision (rule has `block = true`).
//!   * **inject** — rewrite to `vt inject --only-env <vars> -- bash -c '<cmd>'`
//!     (rule matched AND ≥1 of its `env_vars` is a `vt://` value).
//!
//! Why a *rewrite* and not an exec-gateway: Claude Code's PreToolUse hook can
//! return `hookSpecificOutput.updatedInput.command`, so the decision and the
//! transformation happen in one place with no shell wrapping to deploy.
//!
//! ## Security notes
//! * **Scoped injection.** The rewrite passes `--only-env` listing *only* the
//!   rule's vt:// vars, so a matched command never gets handed unrelated
//!   secrets from the environment (confused-deputy guard).
//! * **Recursion guard.** A command whose leading program is `vt` is always
//!   accepted unchanged, so a re-fired hook can't wrap `vt inject …` again.
//! * **Matching is by argv[0] basename only** — no globs, no substrings, no
//!   regex. `bash -c "…"` is opaque: the secret-bearing program inside a shell
//!   string is invisible to the hook (documented limitation).

use anyhow::{Context, Result};
use serde_json::json;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::config::{self, HookConfig, HookRule};
use crate::HookCommands;

/// What the hook decided to do with a command.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Run unchanged (no JSON emitted).
    Allow,
    /// Refuse the command; carries the reason shown to the agent.
    Deny(String),
    /// Replace the command with this string (already shell-quoted).
    Rewrite(String),
}

/// Multi-call entry: vt was invoked via a `vt hook install-shims` symlink named
/// `<invoked>` (e.g. `gh`). Behaves exactly like `vt hook exec -- <invoked>
/// <args>`. Called from `main()` before clap, since `argv[0]` isn't `vt`.
/// Returns an exit code (the success paths `exec()` and never return).
pub fn shim_main(invoked: &str, args: &[std::ffi::OsString]) -> i32 {
    let cfg = config::load_agent_config();
    let vt_bin = vt_binary();
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(invoked.to_string());
    argv.extend(args.iter().map(|s| s.to_string_lossy().into_owned()));
    match run_exec(&cfg, &vt_bin, &argv) {
        Ok(()) => 0, // unreachable on success (run_exec exec()s), guard anyway
        Err(e) => {
            eprintln!("{e:#}");
            1
        }
    }
}

/// Entry point for the `vt hook` subcommand. Synchronous: the hook only decides
/// and rewrites — the actual decryption happens later, when the agent runs the
/// rewritten `vt inject …` command as a separate process.
pub fn run(cmd: &HookCommands) -> Result<()> {
    let cfg = config::load_agent_config();
    let vt_bin = vt_binary();
    match cmd {
        HookCommands::Claude => run_claude(&cfg, &vt_bin),
        HookCommands::Check { command } => {
            let joined = command.join(" ");
            let cwd = current_dir();
            match evaluate(&joined, &cwd, &cfg, env_lookup, &vt_bin) {
                Action::Allow => println!("ACCEPT  (runs unchanged)"),
                Action::Deny(r) => println!("BLOCK   {}", r),
                Action::Rewrite(c) => println!("REWRITE {}", c),
            }
            Ok(())
        }
        HookCommands::Exec { argv } => run_exec(&cfg, &vt_bin, argv),
        HookCommands::InstallShims { dir } => install_shims(&cfg, &vt_bin, dir.as_deref()),
    }
}

/// Read a Claude Code PreToolUse event from stdin and emit the decision JSON.
///
/// Lenient by design: any shape we don't understand (non-Bash tool, missing
/// command, unparseable JSON) results in *accept* — the hook must never wedge
/// the agent. Errors go to stderr; stdout carries only the decision JSON.
fn run_claude(cfg: &HookConfig, vt_bin: &str) -> Result<()> {
    let event: serde_json::Value = match serde_json::from_reader(std::io::stdin().lock()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vt hook: could not parse PreToolUse JSON: {e}");
            return Ok(()); // accept
        }
    };

    // Only gate the shell tool; everything else runs unchanged.
    if event.get("tool_name").and_then(|v| v.as_str()) != Some("Bash") {
        return Ok(());
    }
    let command = event
        .get("tool_input")
        .and_then(|ti| ti.get("command"))
        .and_then(|c| c.as_str())
        .unwrap_or("");
    // Claude Code includes the workspace cwd in the event; fall back to this
    // process's own cwd. Used to select per-directory env-value overrides.
    let cwd = event
        .get("cwd")
        .and_then(|c| c.as_str())
        .map(String::from)
        .unwrap_or_else(current_dir);

    match evaluate(command, &cwd, cfg, env_lookup, vt_bin) {
        Action::Allow => {}
        Action::Deny(reason) => emit(&json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        })),
        Action::Rewrite(new_command) => emit(&json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecisionReason": "vt hook: inject vt:// secrets",
                "updatedInput": { "command": new_command },
            }
        })),
    }
    Ok(())
}

fn emit(v: &serde_json::Value) {
    println!("{v}");
}

/// Default env reader used in production.
fn env_lookup(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// This process's working directory as a string (empty on failure).
fn current_dir() -> String {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// What to do for a matched command. Two distinct sets:
///   * `set_vars` — config-sourced (name, value) pairs (BOTH plaintext and
///     vt:// ciphertext) that the caller hasn't exported, so the hook supplies
///     them. Process-env-sourced values are omitted (already in the env).
///   * `only_env` — the subset of vars whose value is vt:// ciphertext, passed
///     to `vt inject --only-env` to be decrypted. Empty ⇒ nothing to decrypt,
///     so the command just runs with `set_vars` applied (no `vt inject`).
#[derive(Debug, PartialEq, Eq)]
pub struct InjectPlan {
    pub set_vars: Vec<(String, String)>,
    pub only_env: Vec<String>,
    /// `--reason` recorded in the vt audit row.
    pub reason: String,
}

impl InjectPlan {
    /// True when at least one var resolves to vt:// ciphertext (so we must run
    /// `vt inject`); false ⇒ only plaintext values to set.
    fn needs_inject(&self) -> bool {
        !self.only_env.is_empty()
    }
}

/// Structured decision, independent of how it is rendered (PreToolUse rewrite
/// vs exec-gateway). The `vt` recursion guard is applied by callers.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
    Inject(InjectPlan),
}

/// Pure decision core — `get_env` and `cwd` are injected so the logic is
/// unit-testable without touching the real environment. `cwd` is the working
/// directory of the command (used to pick per-directory env-value overrides).
///
/// Precedence for each named var: the process environment > `[env.dirs.
/// "<cwd-prefix>"]` > `[env.default]` (env always wins; config is a fallback).
/// Block rules win over inject rules.
pub fn decide(
    prog: &str,
    args: &[String],
    cwd: &str,
    cfg: &HookConfig,
    get_env: &impl Fn(&str) -> Option<String>,
) -> Decision {
    // Block takes precedence over inject, regardless of rule order: a more
    // specific deny (e.g. `gh auth token`) must win over a broad inject rule
    // for the same program (e.g. all of `gh`). So scan deny rules first.
    if let Some(rule) = cfg.rules.iter().find(|r| r.block && rule_matches(r, prog, args)) {
        return Decision::Deny(
            rule.reason
                .clone()
                .unwrap_or_else(|| format!("command '{prog}' is blocked by policy")),
        );
    }

    let rule = match cfg.rules.iter().find(|r| !r.block && rule_matches(r, prog, args)) {
        Some(r) => r,
        None => return Decision::Allow, // default policy: accept
    };

    let dir_vars = dir_override(&cfg.env.dirs, cwd);
    let mut plan = InjectPlan {
        set_vars: Vec::new(),
        only_env: Vec::new(),
        reason: rule
            .reason
            .clone()
            .unwrap_or_else(|| format!("vt hook: {prog}")),
    };
    for name in &rule.env_vars {
        // Precedence: the process env WINS; the agent config is a fallback for
        // vars the caller didn't set — matching vt's config.toml convention
        // ("env vars are primary and always win; the file is fallback"). This
        // also makes shim + PreToolUse compose without double-injecting: once
        // one layer decrypts a var to plaintext in the env, the next layer sees
        // plaintext (not vt://) and won't re-inject it.
        let (val, from_config) = match get_env(name) {
            Some(v) => (v, false),
            None => match dir_vars
                .and_then(|m| m.get(name))
                .or_else(|| cfg.env.default.get(name))
            {
                Some(v) => (v.clone(), true),
                None => continue,
            },
        };
        // Same detector `vt inject --only-env` uses, so the hook and inject
        // agree on what counts as a secret (value *containing* a vt:// URL).
        let is_secret = crate::core::has_vt_url(&val);
        // Config-sourced values (plaintext OR vt://) are supplied by the hook;
        // process-env values are already present, so nothing to prepend.
        if from_config {
            plan.set_vars.push((name.clone(), val));
        }
        if is_secret {
            plan.only_env.push(name.clone());
        }
    }

    if plan.set_vars.is_empty() && plan.only_env.is_empty() {
        Decision::Allow // nothing to supply or decrypt → run unchanged
    } else {
        Decision::Inject(plan)
    }
}

/// Render a decision for the Claude Code PreToolUse path: a single shell string
/// the agent will execute. The original command is wrapped in `bash -c '…'`
/// because `vt inject` execs argv directly (no shell); wrapping preserves
/// arbitrary shell semantics (pipes, redirects, &&). Every embedded piece is
/// single-quoted, so the outer shell hands the original to `bash -c` verbatim.
pub fn evaluate(
    command: &str,
    cwd: &str,
    cfg: &HookConfig,
    get_env: impl Fn(&str) -> Option<String>,
    vt_bin: &str,
) -> Action {
    // A Bash-tool command is an arbitrary shell snippet, so a target program
    // can sit after a `|`, `&&`, `;`, etc. Evaluate EACH top-level segment:
    //   * any segment that is a block rule ⇒ refuse the whole command
    //     (otherwise `true && gh auth token` would bypass a `gh auth token` deny);
    //   * union the env vars from every inject segment (a compound like
    //     `gh … && glab …` needs both), and wrap the WHOLE command in one
    //     `bash -c` so every segment sees the injected env.
    let mut only_env: Vec<String> = Vec::new();
    let mut set_vars: Vec<(String, String)> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();
    for seg in split_segments(command) {
        let (prog, args) = match effective_invocation(&tokenize(&seg)) {
            Some(p) => p,
            None => continue,
        };
        if prog == "vt" || prog == basename(vt_bin) {
            continue; // recursion guard (also a renamed VT_HOOK_BIN)
        }
        match decide(&prog, &args, cwd, cfg, &get_env) {
            Decision::Allow => {}
            Decision::Deny(reason) => return Action::Deny(reason), // block wins
            Decision::Inject(plan) => {
                for n in plan.only_env {
                    if !only_env.contains(&n) {
                        only_env.push(n);
                    }
                }
                for (k, v) in plan.set_vars {
                    if !set_vars.iter().any(|(ek, _)| *ek == k) {
                        set_vars.push((k, v));
                    }
                }
                if !reasons.contains(&plan.reason) {
                    reasons.push(plan.reason);
                }
            }
        }
    }

    if set_vars.is_empty() && only_env.is_empty() {
        return Action::Allow;
    }

    // Set all config-sourced values (plaintext + vt://) as leading shell
    // assignments. vt:// ones are additionally decrypted by `vt inject` via
    // --only-env; plaintext ones just pass through. Only values are quoted —
    // `k` is an env-var NAME (a TOML key), which contains no shell metachars.
    let mut prepend = String::new();
    for (k, v) in &set_vars {
        prepend.push_str(&format!("{}={} ", k, shell_quote(v)));
    }
    let rewrite = if only_env.is_empty() {
        // Only plaintext values to supply — no secret, so no vt inject.
        format!("{}bash -c {}", prepend, shell_quote(command))
    } else {
        format!(
            "{}{} inject --only-env {} --reason {} -- bash -c {}",
            prepend,
            shell_quote(vt_bin),
            shell_quote(&only_env.join(",")),
            shell_quote(&reasons.join("; ")),
            shell_quote(command),
        )
    };
    Action::Rewrite(rewrite)
}

/// Exec-gateway: evaluate a clean argv and exec the result. No shell quoting or
/// `bash -c` is needed here — `vt inject` execs argv directly, and we already
/// have a real argv. The command is resolved to an absolute path (skipping the
/// shim dir) so re-execing can never re-enter a PATH shim.
fn run_exec(cfg: &HookConfig, vt_bin: &str, argv: &[String]) -> Result<()> {
    let arg0 = argv.first().context("vt hook exec: missing command")?;
    let rest = &argv[1..];

    // Loop breaker: exec chains inherit VT_HOOK_DEPTH. A shim that resolves back
    // to itself (misconfigured PATH) would exec forever; bail with a clear error
    // instead of hanging. Legit nesting (mise shim → vt hook exec → real mise)
    // is depth 1–2; the cap is well above that.
    const MAX_DEPTH: u32 = 10;
    let depth: u32 = std::env::var("VT_HOOK_DEPTH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if depth >= MAX_DEPTH {
        anyhow::bail!(
            "vt hook exec: recursion limit ({MAX_DEPTH}) hit for `{arg0}` — a shim is \
             resolving to itself. Check that the shim dir on PATH matches its real \
             path and re-run `vt hook install-shims`."
        );
    }
    std::env::set_var("VT_HOOK_DEPTH", (depth + 1).to_string());

    // Find the program + its args for matching; the original argv is still
    // what gets exec'd.
    let (prog, args) = effective_invocation(argv)
        .unwrap_or_else(|| (basename(arg0), rest.to_vec()));

    // Recursion guard: a bare `vt …` (or renamed VT_HOOK_BIN) runs as-is.
    if prog == "vt" || prog == basename(vt_bin) {
        return exec_real(arg0, rest);
    }

    let cwd = current_dir();
    match decide(&prog, &args, &cwd, cfg, &env_lookup) {
        Decision::Allow => {
            let real = resolve_real(arg0);
            exec_real(&real, rest)
        }
        Decision::Deny(reason) => {
            eprintln!("vt hook: {reason}");
            std::process::exit(126);
        }
        Decision::Inject(plan) => {
            // Config-sourced values (plaintext + vt://) aren't exported by the
            // caller — set them so the child (and the `vt inject` scan) finds
            // them. exec inherits this modified env.
            for (k, v) in &plan.set_vars {
                std::env::set_var(k, v);
            }
            let real = resolve_real(arg0);
            if !plan.needs_inject() {
                // Only plaintext values to supply — exec the command directly.
                return exec_real(&real, rest);
            }
            let mut vt_args = vec![
                "inject".to_string(),
                "--only-env".to_string(),
                plan.only_env.join(","),
                "--reason".to_string(),
                plan.reason,
                "--".to_string(),
                real,
            ];
            vt_args.extend(rest.iter().cloned());
            exec_real(vt_bin, &vt_args)
        }
    }
}

/// `exec()` the given program (never returns on success).
fn exec_real(prog: &str, args: &[String]) -> Result<()> {
    let err = exec::Command::new(prog).args(args).exec();
    Err(anyhow::anyhow!("vt hook exec: failed to run {}: {}", prog, err))
}

/// Resolve a bare command name to an absolute path via `$PATH`, skipping any
/// candidate that is our own binary (a `vt hook install-shims` symlink points
/// back at `vt`). This is how re-execing never re-enters a shim — and it is
/// robust to symlinked PATH entries (`/home/me` → `/essd/me`) because it
/// compares the *resolved target*, not the directory string. A name already
/// containing `/` is returned unchanged; unresolvable → returned as-is (let
/// `exec` fail with ENOENT).
fn resolve_real(arg0: &str) -> String {
    if arg0.contains('/') {
        return arg0.to_string();
    }
    let self_exe = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok());
    let paths: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    resolve_in_paths(arg0, &paths, self_exe.as_deref()).unwrap_or_else(|| arg0.to_string())
}

/// First `dir/arg0` on `paths` that is executable and is NOT `self_exe` (our own
/// binary, i.e. a vt shim symlink). Canonicalizing the candidate resolves the
/// symlink to the real vt binary, so shims are detected regardless of path form.
fn resolve_in_paths(arg0: &str, paths: &[PathBuf], self_exe: Option<&Path>) -> Option<String> {
    for dir in paths {
        let cand = dir.join(arg0);
        if !is_executable(&cand) {
            continue;
        }
        let is_self = match self_exe {
            Some(me) => std::fs::canonicalize(&cand).map(|c| c == me).unwrap_or(false),
            None => false,
        };
        if is_self {
            continue; // this candidate is a vt shim → skip past it
        }
        return Some(cand.to_string_lossy().into_owned());
    }
    None
}

fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

/// The set of command basenames to shim: every rule's `command`. `vt` is never
/// shimmed.
fn shim_names(cfg: &HookConfig) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = cfg.rules.iter().map(|r| basename(&r.command)).collect();
    names.remove("vt");
    names
}

/// Generate one PATH shim per name from `shim_names`. Each shim is a **symlink
/// to the vt binary** (busybox-style multi-call): when invoked as `gh`, vt sees
/// `argv[0] = "gh"` and dispatches to the exec-gateway for that command. No
/// shell wrapper, no baked paths — and `resolve_real` skips any candidate that
/// canonicalizes back to vt, so shims never resolve to themselves.
fn install_shims(cfg: &HookConfig, vt_bin: &str, dir: Option<&str>) -> Result<()> {
    let dir = match dir {
        Some(d) => PathBuf::from(d),
        None => dirs::home_dir()
            .context("no home directory")?
            .join(".local")
            .join("share")
            .join("vt")
            .join("shims"),
    };
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating shim dir {}", dir.display()))?;
    let dir_abs = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
    // Absolute target so the symlink resolves regardless of CWD.
    let target = std::fs::canonicalize(vt_bin).unwrap_or_else(|_| PathBuf::from(vt_bin));

    let names = shim_names(cfg);
    if names.is_empty() {
        println!("no commands in agent config — nothing to shim");
        return Ok(());
    }

    for name in &names {
        let path = dir.join(name);
        // Replace any existing shim (script or symlink) idempotently.
        let _ = std::fs::remove_file(&path);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &path)
            .with_context(|| format!("linking {} -> {}", path.display(), target.display()))?;
        #[cfg(not(unix))]
        std::fs::copy(&target, &path).with_context(|| format!("writing {}", path.display()))?;
    }

    println!(
        "installed {} shim(s) in {} (symlinks to {}): {}",
        names.len(),
        dir_abs.display(),
        target.display(),
        names.iter().map(String::as_str).collect::<Vec<_>>().join(", ")
    );
    println!(
        "add to the FRONT of your PATH (e.g. in ~/.zshrc):\n  export PATH=\"{}:$PATH\"",
        dir_abs.display()
    );
    Ok(())
}

/// Pick the per-directory override map whose path key is the longest prefix of
/// `cwd` (exact match or a parent directory). Trailing slashes are ignored.
fn dir_override<'a>(
    dirs: &'a std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
    cwd: &str,
) -> Option<&'a std::collections::BTreeMap<String, String>> {
    let cwd_n = cwd.trim_end_matches('/');
    dirs.iter()
        .filter(|(d, _)| {
            let dn = d.trim_end_matches('/');
            // exact dir, or cwd is `<dn>/<something>` (a real subdirectory).
            cwd_n == dn
                || (cwd_n.len() > dn.len()
                    && cwd_n.starts_with(dn)
                    && cwd_n.as_bytes()[dn.len()] == b'/')
        })
        .max_by_key(|(d, _)| d.trim_end_matches('/').len())
        .map(|(_, m)| m)
}

/// A rule matches when ALL of these hold:
///   * its `command` basename equals the command's program basename,
///   * its `args` are a positional prefix of the command's arguments, and
///   * if `args_any` is non-empty, the command's args contain at least one of
///     those tokens (anywhere).
///
/// So `command = "gh"` (no args) matches every `gh …`; `args = ["auth","token"]`
/// matches only `gh auth token …`; adding `args_any = ["-t","--show-token"]`
/// further narrows to invocations carrying one of those flags. Exact, case-
/// sensitive, basename-only on the program.
fn rule_matches(rule: &HookRule, prog: &str, args: &[String]) -> bool {
    basename(&rule.command) == prog
        && args_prefix_matches(&rule.args, args)
        && (rule.args_any.is_empty() || rule.args_any.iter().any(|a| args.iter().any(|g| g == a)))
}

/// True when `rule_args` is a positional prefix of `inv_args`. Empty rule args
/// match anything.
fn args_prefix_matches(rule_args: &[String], inv_args: &[String]) -> bool {
    rule_args.len() <= inv_args.len()
        && rule_args
            .iter()
            .zip(inv_args)
            .all(|(want, got)| want == got)
}

/// The vt binary to invoke in rewrites. Prefer `$VT_HOOK_BIN`, then this
/// process's own absolute path (guarantees the same binary), else bare `vt`.
fn vt_binary() -> String {
    if let Ok(p) = std::env::var("VT_HOOK_BIN") {
        if !p.trim().is_empty() {
            return p;
        }
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| "vt".to_string())
}

/// Parse a shell command string into `(program_basename, args)` (test helper).
#[cfg(test)]
fn parse_invocation(command: &str) -> Option<(String, Vec<String>)> {
    effective_invocation(&tokenize(command))
}

/// Find the *effective* program and its args from a token sequence: skip any
/// leading `NAME=value` assignments, then take the next token as the program.
/// `args` are the tokens after the program — so `gh auth token` yields
/// `("gh", ["auth","token"])`. The command itself is still executed verbatim
/// by the caller.
fn effective_invocation(tokens: &[String]) -> Option<(String, Vec<String>)> {
    let mut i = 0;
    while i < tokens.len() && is_assignment(&tokens[i]) {
        i += 1;
    }
    let prog = tokens.get(i)?;
    Some((basename(prog), tokens[i + 1..].to_vec()))
}

/// True for a leading `NAME=value` shell assignment (name is a valid shell id).
fn is_assignment(tok: &str) -> bool {
    let Some(eq) = tok.find('=') else {
        return false;
    };
    if eq == 0 {
        return false;
    }
    let name = &tok[..eq];
    name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Basename: the segment after the final '/'. Surrounding quotes are stripped.
fn basename(s: &str) -> String {
    let s = s.trim_matches(|c| c == '\'' || c == '"');
    match s.rsplit('/').next() {
        Some(b) if !b.is_empty() => b.to_string(),
        _ => s.to_string(),
    }
}

/// Minimal POSIX-ish tokenizer: splits on unquoted whitespace, honoring single
/// and double quotes (no escape processing — sufficient to find argv[0]).
fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut started = false;
    for c in s.chars() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                started = true;
            }
            '"' if !in_single => {
                in_double = !in_double;
                started = true;
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if started {
                    out.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            c => {
                cur.push(c);
                started = true;
            }
        }
    }
    if started {
        out.push(cur);
    }
    out
}

/// Split a shell snippet into top-level command segments at `|`, `||`, `&&`,
/// `;`, and newlines, so a target program after an operator is still seen.
/// Quotes (`'`/`"`), backticks, backslash escapes, and `(`/`$(` nesting are
/// respected so operators inside them don't split. A single `&` is NOT a
/// separator (avoids breaking redirects like `2>&1` and `>&2`); background
/// `cmd &` and command-substitution/subshell interiors are left in one segment
/// (documented limitation). Empty segments are dropped.
fn split_segments(s: &str) -> Vec<String> {
    let mut segs = Vec::new();
    let mut cur = String::new();
    let mut single = false;
    let mut double = false;
    let mut backtick = false;
    let mut depth: i32 = 0; // ( ... ) / $( ... ) nesting, tracked only when unquoted
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        // Quote/backtick swallow modes are checked FIRST and never touch `depth`,
        // so a paren inside quotes/backticks can't leak the nesting counter (a
        // stuck depth would hide a later segment and bypass a block rule).
        if single {
            cur.push(c);
            if c == '\'' {
                single = false;
            }
            continue;
        }
        if double {
            cur.push(c);
            if c == '\\' {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            } else if c == '"' {
                double = false;
            }
            continue;
        }
        if backtick {
            cur.push(c);
            if c == '`' {
                backtick = false;
            }
            continue;
        }
        match c {
            '\\' => {
                cur.push(c);
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '\'' => {
                single = true;
                cur.push(c);
            }
            '"' => {
                double = true;
                cur.push(c);
            }
            '`' => {
                backtick = true;
                cur.push(c);
            }
            '(' => {
                depth += 1;
                cur.push(c);
            }
            ')' => {
                if depth > 0 {
                    depth -= 1;
                }
                cur.push(c);
            }
            // Operators split only at top level (outside any `( … )` group).
            '|' if depth == 0 => {
                if chars.peek() == Some(&'|') {
                    chars.next(); // ||
                }
                segs.push(std::mem::take(&mut cur));
            }
            '&' if depth == 0 && chars.peek() == Some(&'&') => {
                chars.next(); // &&
                segs.push(std::mem::take(&mut cur));
            }
            ';' | '\n' if depth == 0 => segs.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    segs.push(cur);
    segs.into_iter()
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

/// Wrap a string as a single shell token using single quotes, escaping any
/// embedded single quote as `'\''`. Always safe to paste into a command line.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }
    fn cfg(rules: Vec<HookRule>) -> HookConfig {
        HookConfig { rules, ..Default::default() }
    }
    fn rule(command: &str, env_vars: &[&str], block: bool) -> HookRule {
        HookRule {
            command: command.to_string(),
            env_vars: strs(env_vars),
            block,
            ..Default::default()
        }
    }
    fn rule_args(command: &str, args: &[&str], block: bool) -> HookRule {
        HookRule {
            command: command.to_string(),
            args: strs(args),
            block,
            ..Default::default()
        }
    }
    fn rule_args_any(command: &str, args: &[&str], args_any: &[&str]) -> HookRule {
        HookRule {
            command: command.to_string(),
            args: strs(args),
            args_any: strs(args_any),
            block: true,
            ..Default::default()
        }
    }
    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }
    // env helpers
    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn tokenize_handles_quotes_and_assignments() {
        assert_eq!(tokenize("python train.py"), vec!["python", "train.py"]);
        assert_eq!(
            tokenize("FOO=bar  python   a.py"),
            vec!["FOO=bar", "python", "a.py"]
        );
        assert_eq!(tokenize("'my prog' arg"), vec!["my prog", "arg"]);
    }

    #[test]
    fn parse_invocation_skips_assignments_and_basenames() {
        assert_eq!(
            parse_invocation("python a.py"),
            Some(("python".into(), argv("a.py")))
        );
        assert_eq!(
            parse_invocation("X=1 Y=2 /usr/bin/python a.py"),
            Some(("python".into(), argv("a.py")))
        );
        assert_eq!(parse_invocation("./node x"), Some(("node".into(), argv("x"))));
        assert_eq!(
            parse_invocation("gh auth token"),
            Some(("gh".into(), argv("auth token")))
        );
        assert_eq!(parse_invocation(""), None);
    }

    #[test]
    fn is_assignment_rules() {
        assert!(is_assignment("FOO=bar"));
        assert!(is_assignment("_x=1"));
        assert!(!is_assignment("=bad"));
        assert!(!is_assignment("python")); // no '='
        assert!(!is_assignment("1FOO=bar")); // bad name
        assert!(!is_assignment("a-b=c")); // dash not allowed in name
    }

    #[test]
    fn unmatched_command_is_accepted() {
        let c = cfg(vec![rule("gh", &["GH_TOKEN"], false)]);
        assert_eq!(evaluate("ls -la", "", &c, no_env, "vt"), Action::Allow);
    }

    #[test]
    fn vt_command_is_never_rewrapped() {
        let c = cfg(vec![rule("vt", &["X"], false)]);
        let env = |_: &str| Some("vt://abc".to_string());
        assert_eq!(
            evaluate("vt inject -- bash -c 'gh pr list'", "", &c, env, "vt"),
            Action::Allow
        );
    }

    #[test]
    fn block_rule_denies() {
        let c = cfg(vec![rule("rm", &[], true)]);
        match evaluate("rm -rf /", "", &c, no_env, "vt") {
            Action::Deny(_) => {}
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn matched_without_vt_env_is_accepted() {
        // gh is whitelisted but GH_TOKEN is plain (not vt://) → nothing to do.
        let c = cfg(vec![rule("gh", &["GH_TOKEN"], false)]);
        let env = |_: &str| Some("ghp_plaintext".to_string());
        assert_eq!(evaluate("gh pr list", "", &c, env, "vt"), Action::Allow);
    }

    #[test]
    fn matched_with_vt_env_rewrites_scoped() {
        let c = cfg(vec![rule("gh", &["GH_TOKEN", "GITHUB_TOKEN"], false)]);
        // Only GH_TOKEN is vt://; GITHUB_TOKEN is absent.
        let env = |name: &str| match name {
            "GH_TOKEN" => Some("vt://0abc".to_string()),
            _ => None,
        };
        match evaluate("gh pr create", "", &c, env, "vt") {
            Action::Rewrite(cmd) => {
                assert!(cmd.contains("inject --only-env 'GH_TOKEN'"), "{cmd}");
                assert!(!cmd.contains("GITHUB_TOKEN"), "{cmd}");
                assert!(cmd.contains("-- bash -c 'gh pr create'"), "{cmd}");
            }
            other => panic!("expected rewrite, got {other:?}"),
        }
    }

    /// Prove `shell_quote` produces a token that a real shell decodes back to
    /// the EXACT input — for any byte soup. This is the property the rewrite
    /// relies on: the outer shell must hand the original command to `bash -c`
    /// verbatim (one argv), regardless of quotes/`$`/backticks/newlines.
    #[test]
    fn shell_quote_roundtrips_through_real_sh() {
        let nasties = [
            r#"gh pr create --title "it's a test""#,
            r#"echo 'single' "double" `back` $VAR ${X} $(cmd)"#,
            "weird\nnewline\ttab",
            r#"mix '"' "'" \ \\ \" \'"#,
            r#"empty quotes '' "" and trailing \"#,
            "no-specials-here",
        ];
        for s in nasties {
            let quoted = shell_quote(s);
            // `printf %s <quoted>` must emit exactly `s` (no trailing newline).
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("printf %s {quoted}"))
                .output()
                .expect("run /bin/sh");
            assert!(out.status.success(), "sh failed for {s:?}");
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                s,
                "round-trip mismatch for input {s:?} (quoted: {quoted})"
            );
        }
    }

    #[test]
    fn rewrite_escapes_single_quotes_in_command() {
        let c = cfg(vec![rule("sh", &["TOK"], false)]);
        let env = |_: &str| Some("vt://x".to_string());
        match evaluate("sh -c 'echo hi'", "", &c, env, "vt") {
            Action::Rewrite(cmd) => {
                // embedded single quotes survive as '\'' sequences
                assert!(cmd.contains(r"'\''"), "{cmd}");
            }
            other => panic!("expected rewrite, got {other:?}"),
        }
    }

    #[test]
    fn rule_matches_by_basename() {
        let r = rule("/usr/bin/python", &["K"], false);
        assert!(rule_matches(&r, "python", &[]));
        assert!(!rule_matches(&r, "python3", &[]));
    }

    #[test]
    fn args_prefix_matching() {
        let r = rule_args("gh", &["auth", "token"], true);
        assert!(rule_matches(&r, "gh", &argv("auth token")));
        assert!(rule_matches(&r, "gh", &argv("auth token --hostname x"))); // prefix
        assert!(!rule_matches(&r, "gh", &argv("auth status")));
        assert!(!rule_matches(&r, "gh", &argv("pr list")));
        assert!(!rule_matches(&r, "gh", &[])); // too short
    }

    #[test]
    fn shim_names_include_rule_commands_never_vt() {
        let c = cfg(vec![
            rule("gh", &["GH_TOKEN"], false),
            rule("glab", &["GITLAB_TOKEN"], false),
            rule("vt", &["X"], false),
        ]);
        let names = shim_names(&c);
        assert!(names.contains("gh"));
        assert!(names.contains("glab"));
        assert!(!names.contains("vt")); // vt is never shimmed
    }

    #[test]
    fn resolve_in_paths_skips_vt_shim_symlink() {
        // The shim is a symlink to the vt binary; resolve_real must skip any
        // candidate that canonicalizes to vt (self), and return the real tool.
        // This is robust even when the shim dir is on PATH via a symlink, since
        // we compare the resolved target, not the directory path.
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("vt-hook-rt-{}", std::process::id()));
        let bindir = base.join("bin");
        let shim = base.join("shim");
        let real = base.join("real");
        for d in [&bindir, &shim, &real] {
            std::fs::create_dir_all(d).unwrap();
        }
        // fake vt binary
        let vt = bindir.join("vt");
        std::fs::write(&vt, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&vt, std::fs::Permissions::from_mode(0o755)).unwrap();
        let vt_canon = std::fs::canonicalize(&vt).unwrap();
        // shim/gh -> vt (a vt shim); real/gh = a distinct real tool
        std::os::unix::fs::symlink(&vt, shim.join("gh")).unwrap();
        let real_gh = real.join("gh");
        std::fs::write(&real_gh, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&real_gh, std::fs::Permissions::from_mode(0o755)).unwrap();

        // shim dir on PATH via a symlink; self = vt binary.
        let link = std::env::temp_dir().join(format!("vt-hook-link-{}", std::process::id()));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&base, &link).unwrap();
        let paths = vec![link.join("shim"), real.clone()];

        // With self set → the shim (symlink to vt) is skipped, real gh wins.
        let got = resolve_in_paths("gh", &paths, Some(&vt_canon)).unwrap();
        assert_eq!(got, real_gh.to_string_lossy(), "vt shim symlink must be skipped");
        // Without self → first candidate wins (the shim), proving self is the guard.
        let got2 = resolve_in_paths("gh", &paths, None).unwrap();
        assert_eq!(got2, link.join("shim").join("gh").to_string_lossy());
        // Missing command → None.
        assert!(resolve_in_paths("nope", &paths, Some(&vt_canon)).is_none());

        std::fs::remove_file(&link).ok();
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn decide_returns_structured_inject_plan() {
        let env = EnvConfig {
            default: map(&[("GH_TOKEN", "vt://0cfg")]),
            dirs: BTreeMap::new(),
        };
        let c = cfg_env(vec![rule("gh", &["GH_TOKEN"], false)], env);
        match decide("gh", &argv("pr list"), "/x", &c, &no_env) {
            Decision::Inject(plan) => {
                assert_eq!(plan.only_env, vec!["GH_TOKEN".to_string()]);
                assert_eq!(plan.set_vars, vec![("GH_TOKEN".to_string(), "vt://0cfg".to_string())]);
                assert!(plan.needs_inject());
            }
            other => panic!("expected inject, got {other:?}"),
        }
        // block rule -> Deny
        let cb = cfg(vec![rule_args("gh", &["auth", "token"], true)]);
        assert!(matches!(
            decide("gh", &argv("auth token"), "/x", &cb, &no_env),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn mixed_plaintext_and_secret_config_values_all_set() {
        // logcli-style: two vt:// + two plaintext values from config.
        let env = EnvConfig {
            default: map(&[
                ("LOKI_ADDR", "vt://0addr"),
                ("LOKI_PASSWORD", "vt://0pw"),
                ("LOKI_ORG_ID", "f2pool"),
                ("LOKI_USERNAME", "loki-readonly"),
            ]),
            dirs: BTreeMap::new(),
        };
        let c = cfg_env(
            vec![rule(
                "logcli",
                &["LOKI_ADDR", "LOKI_ORG_ID", "LOKI_USERNAME", "LOKI_PASSWORD"],
                false,
            )],
            env,
        );
        match decide(
            "logcli",
            &argv("query '{app=\"x\"}'"),
            "/x",
            &c,
            &no_env,
        ) {
            Decision::Inject(plan) => {
                // all four supplied
                assert_eq!(plan.set_vars.len(), 4, "{:?}", plan.set_vars);
                // only the two vt:// ones decrypted
                assert_eq!(plan.only_env, vec!["LOKI_ADDR".to_string(), "LOKI_PASSWORD".to_string()]);
            }
            other => panic!("expected inject, got {other:?}"),
        }
        // Full rewrite render: sets all four, --only-env only the secrets.
        match evaluate("logcli query x", "/x", &c, no_env, "vt") {
            Action::Rewrite(cmd) => {
                assert!(cmd.contains("LOKI_ORG_ID='f2pool'"), "{cmd}");
                assert!(cmd.contains("LOKI_USERNAME='loki-readonly'"), "{cmd}");
                assert!(cmd.contains("--only-env 'LOKI_ADDR,LOKI_PASSWORD'"), "{cmd}");
            }
            other => panic!("expected rewrite, got {other:?}"),
        }
    }

    #[test]
    fn plaintext_only_config_runs_without_vt_inject() {
        let env = EnvConfig {
            default: map(&[("LOKI_ORG_ID", "f2pool")]),
            dirs: BTreeMap::new(),
        };
        let c = cfg_env(vec![rule("logcli", &["LOKI_ORG_ID"], false)], env);
        match evaluate("logcli query x", "/x", &c, no_env, "vt") {
            Action::Rewrite(cmd) => {
                assert!(cmd.starts_with("LOKI_ORG_ID='f2pool' bash -c "), "{cmd}");
                assert!(!cmd.contains("inject"), "should not call vt inject: {cmd}");
            }
            other => panic!("expected rewrite, got {other:?}"),
        }
    }

    #[test]
    fn args_any_matches_flag_anywhere() {
        // Block `glab auth status` only when -t/--show-token is present.
        let r = rule_args_any("glab", &["auth", "status"], &["-t", "--show-token"]);
        assert!(rule_matches(&r, "glab", &argv("auth status -t")));
        assert!(rule_matches(&r, "glab", &argv("auth status --show-token")));
        assert!(rule_matches(
            &r,
            "glab",
            &argv("auth status --hostname x -t") // flag not adjacent
        ));
        assert!(!rule_matches(&r, "glab", &argv("auth status"))); // no token flag
        assert!(!rule_matches(&r, "glab", &argv("auth login -t"))); // wrong subcommand
    }

    #[test]
    fn glab_show_token_blocked_but_plain_status_injected() {
        let c = cfg(vec![
            rule("glab", &["GITLAB_TOKEN"], false),
            rule_args_any("glab", &["auth", "status"], &["-t", "--show-token"]),
        ]);
        let env = |_: &str| Some("vt://0tok".to_string());
        match evaluate("glab auth status --show-token", "", &c, env, "vt") {
            Action::Deny(_) => {}
            other => panic!("expected deny, got {other:?}"),
        }
        match evaluate("glab auth status", "", &c, env, "vt") {
            Action::Rewrite(cmd) => assert!(cmd.contains("--only-env 'GITLAB_TOKEN'"), "{cmd}"),
            other => panic!("expected rewrite, got {other:?}"),
        }
    }

    #[test]
    fn effective_invocation_skips_assignments_no_launcher_peeling() {
        let inv = |s: &str| effective_invocation(&tokenize(s));
        assert_eq!(inv("gh pr list"), Some(("gh".into(), argv("pr list"))));
        assert_eq!(inv("FOO=bar gh pr"), Some(("gh".into(), argv("pr"))));
        assert_eq!(inv("/usr/bin/gh pr"), Some(("gh".into(), argv("pr"))));
        // no launcher peeling: the leading program is taken as-is.
        assert_eq!(inv("mise exec gh"), Some(("mise".into(), argv("exec gh"))));
        assert_eq!(inv("env FOO=bar gh pr"), Some(("env".into(), argv("FOO=bar gh pr"))));
    }

    #[test]
    fn split_segments_respects_quotes_redirects_and_operators() {
        assert_eq!(split_segments("gh pr list | grep x"), vec!["gh pr list", "grep x"]);
        assert_eq!(split_segments("cd /r && gh pr create"), vec!["cd /r", "gh pr create"]);
        assert_eq!(split_segments("a; b ; c"), vec!["a", "b", "c"]);
        assert_eq!(split_segments("a || b"), vec!["a", "b"]);
        // quoted operators don't split
        assert_eq!(split_segments("gh x --title 'a && b'"), vec!["gh x --title 'a && b'"]);
        assert_eq!(split_segments("gh x --title \"a | b\""), vec!["gh x --title \"a | b\""]);
        // single & (redirect 2>&1) does NOT split
        assert_eq!(split_segments("echo x 2>&1"), vec!["echo x 2>&1"]);
        // $(...) interior kept together (documented limitation)
        assert_eq!(split_segments("echo $(gh pr view | cat)"), vec!["echo $(gh pr view | cat)"]);
        // a `(` inside a quote/backtick must NOT leak `depth` and hide a later
        // segment (that would bypass a block rule on the tail).
        assert_eq!(split_segments("`( echo hi`; rm x"), vec!["`( echo hi`", "rm x"]);
        assert_eq!(split_segments("echo \"(\" ; rm x"), vec!["echo \"(\"", "rm x"]);
        assert_eq!(split_segments("echo '(' ; rm x"), vec!["echo '('", "rm x"]);
    }

    #[test]
    fn compound_command_detects_target_after_operator() {
        let env = EnvConfig {
            default: map(&[
                ("GH_TOKEN", "vt://0gh"),
                ("GITLAB_TOKEN", "vt://0gl"),
                ("GITLAB_HOST", "vt://0h"),
            ]),
            dirs: BTreeMap::new(),
        };
        let c = cfg_env(
            vec![
                rule("gh", &["GH_TOKEN"], false),
                rule_args("gh", &["auth", "token"], true),
                rule("glab", &["GITLAB_TOKEN", "GITLAB_HOST"], false),
            ],
            env,
        );
        // target after `&&` is now detected; whole command wrapped in bash -c
        match evaluate("cd /repo && gh pr create", "/x", &c, no_env, "vt") {
            Action::Rewrite(cmd) => {
                assert!(cmd.contains("--only-env 'GH_TOKEN'"), "{cmd}");
                assert!(cmd.contains("-- bash -c 'cd /repo && gh pr create'"), "{cmd}");
            }
            o => panic!("expected rewrite, got {o:?}"),
        }
        // block after `&&` is enforced — no bypass
        assert!(matches!(
            evaluate("true && gh auth token", "/x", &c, no_env, "vt"),
            Action::Deny(_)
        ));
        // two targets in one compound → union of env vars, one rewrite
        match evaluate("gh pr list && glab mr list", "/x", &c, no_env, "vt") {
            Action::Rewrite(cmd) => {
                assert!(cmd.contains("--only-env 'GH_TOKEN,GITLAB_TOKEN,GITLAB_HOST'"), "{cmd}");
            }
            o => panic!("expected rewrite, got {o:?}"),
        }
        // pipe with target first: whole pipeline wrapped so it all gets the env
        match evaluate("gh pr list | grep foo", "/x", &c, no_env, "vt") {
            Action::Rewrite(cmd) => {
                assert!(cmd.contains("-- bash -c 'gh pr list | grep foo'"), "{cmd}")
            }
            o => panic!("expected rewrite, got {o:?}"),
        }
    }

    #[test]
    fn block_subcommand_wins_over_inject_regardless_of_order() {
        // inject rule for all of `gh`, plus a deny for `gh auth token`.
        let c = cfg(vec![
            rule("gh", &["GH_TOKEN"], false),
            rule_args("gh", &["auth", "token"], true),
        ]);
        let env = |_: &str| Some("vt://0abc".to_string());
        // subcommand is blocked even though the inject rule also matches gh
        match evaluate("gh auth token", "", &c, env, "vt") {
            Action::Deny(_) => {}
            other => panic!("expected deny for `gh auth token`, got {other:?}"),
        }
        // a different gh subcommand still gets injected
        match evaluate("gh pr create", "", &c, env, "vt") {
            Action::Rewrite(cmd) => assert!(cmd.contains("--only-env 'GH_TOKEN'"), "{cmd}"),
            other => panic!("expected rewrite for `gh pr create`, got {other:?}"),
        }
    }

    // --- env-value config (defaults + per-PWD overrides) -------------------

    use crate::config::EnvConfig;
    use std::collections::BTreeMap;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    fn cfg_env(rules: Vec<HookRule>, env: EnvConfig) -> HookConfig {
        HookConfig { rules, env, ..Default::default() }
    }

    #[test]
    fn dir_override_picks_longest_prefix() {
        let mut dirs = BTreeMap::new();
        dirs.insert("/home/me/work".to_string(), map(&[("K", "broad")]));
        dirs.insert(
            "/home/me/work/projA".to_string(),
            map(&[("K", "specific")]),
        );
        assert_eq!(
            dir_override(&dirs, "/home/me/work/projA/sub").unwrap().get("K"),
            Some(&"specific".to_string())
        );
        assert_eq!(
            dir_override(&dirs, "/home/me/work/other").unwrap().get("K"),
            Some(&"broad".to_string())
        );
        assert!(dir_override(&dirs, "/tmp").is_none());
        // exact match with trailing slash normalizes
        assert!(dir_override(&dirs, "/home/me/work/").is_some());
    }

    #[test]
    fn default_value_injected_in_all_pwds_and_prepended() {
        // No process env at all — the value comes purely from config.
        let env = EnvConfig {
            default: map(&[("GH_TOKEN", "vt://0def")]),
            dirs: BTreeMap::new(),
        };
        let c = cfg_env(vec![rule("gh", &["GH_TOKEN"], false)], env);
        match evaluate("gh pr list", "/anywhere", &c, no_env, "vt") {
            Action::Rewrite(cmd) => {
                assert!(cmd.starts_with("GH_TOKEN='vt://0def' "), "{cmd}");
                assert!(cmd.contains("--only-env 'GH_TOKEN'"), "{cmd}");
            }
            other => panic!("expected rewrite, got {other:?}"),
        }
    }

    #[test]
    fn dir_value_overrides_default_by_pwd() {
        let mut dirs = BTreeMap::new();
        dirs.insert("/work/projA".to_string(), map(&[("GH_TOKEN", "vt://0A")]));
        let env = EnvConfig {
            default: map(&[("GH_TOKEN", "vt://0def")]),
            dirs,
        };
        let c = cfg_env(vec![rule("gh", &["GH_TOKEN"], false)], env);
        // inside projA -> projA value
        match evaluate("gh pr list", "/work/projA/src", &c, no_env, "vt") {
            Action::Rewrite(cmd) => assert!(cmd.starts_with("GH_TOKEN='vt://0A' "), "{cmd}"),
            other => panic!("expected rewrite, got {other:?}"),
        }
        // elsewhere -> default value
        match evaluate("gh pr list", "/work/projB", &c, no_env, "vt") {
            Action::Rewrite(cmd) => assert!(cmd.starts_with("GH_TOKEN='vt://0def' "), "{cmd}"),
            other => panic!("expected rewrite, got {other:?}"),
        }
    }

    #[test]
    fn process_env_wins_over_config_and_is_not_prepended() {
        // env-first: an exported vt:// value takes precedence over the config
        // default, and (being env-sourced) is not prepended as an assignment.
        let env = EnvConfig {
            default: map(&[("GH_TOKEN", "vt://0cfg")]),
            dirs: BTreeMap::new(),
        };
        let c = cfg_env(vec![rule("gh", &["GH_TOKEN"], false)], env);
        let proc_env = |_: &str| Some("vt://0env".to_string());
        match evaluate("gh pr list", "/x", &c, proc_env, "vt") {
            Action::Rewrite(cmd) => {
                assert!(cmd.contains("--only-env 'GH_TOKEN'"), "{cmd}");
                assert!(!cmd.contains("vt://0cfg"), "config should not win: {cmd}");
                assert!(!cmd.contains("GH_TOKEN='"), "env-sourced not prepended: {cmd}");
            }
            other => panic!("expected rewrite, got {other:?}"),
        }
    }

    #[test]
    fn already_plaintext_env_is_not_reinjected() {
        // The composition guard: once a var is plaintext in the env (e.g. a
        // prior inject decrypted it), env-first means we don't re-inject.
        let env = EnvConfig {
            default: map(&[("GH_TOKEN", "vt://0cfg")]),
            dirs: BTreeMap::new(),
        };
        let c = cfg_env(vec![rule("gh", &["GH_TOKEN"], false)], env);
        let proc_env = |_: &str| Some("ghp_plaintext".to_string());
        assert_eq!(evaluate("gh pr list", "/x", &c, proc_env, "vt"), Action::Allow);
    }

    #[test]
    fn env_sourced_value_is_not_prepended() {
        // Var only in the process env (not config) → used but not prepended
        // (it is already in the environment vt inject will scan).
        let c = cfg(vec![rule("gh", &["GH_TOKEN"], false)]);
        let proc_env = |_: &str| Some("vt://0env".to_string());
        match evaluate("gh pr list", "/x", &c, proc_env, "vt") {
            Action::Rewrite(cmd) => {
                assert!(cmd.starts_with("'vt'"), "should not prepend an assignment: {cmd}");
                assert!(cmd.contains("--only-env 'GH_TOKEN'"), "{cmd}");
            }
            other => panic!("expected rewrite, got {other:?}"),
        }
    }
}
