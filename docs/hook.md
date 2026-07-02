# `vt hook` — transparent secrets for AI coding agents

## Goal

Let an AI coding agent (Claude Code, …) use `vt://`-protected secrets **without
knowing they are protected**. The agent keeps `OPENAI_API_KEY=vt://0…` in its
environment; when it runs a command that needs the secret, `vt` transparently
decrypts it (via the phone/Touch ID ceremony, or the DEK cache within a TTL),
and the child process sees plaintext. Commands that don't need a secret are
never touched — and never trigger a phone prompt.

## How it works

Agents expose a **PreToolUse** hook: before running a shell command they hand
the proposed command to an external program that can **accept / block /
rewrite** it. Claude Code can take back a rewritten command via
`hookSpecificOutput.updatedInput.command`. `vt hook claude` is that program.

```
agent wants to run:   gh pr create --title x      (env: GH_TOKEN=vt://0…)
        │
        ▼  PreToolUse JSON on stdin
   vt hook claude   ── consults [[rules]] in agent.toml
        │
        ▼  decision JSON on stdout
   updatedInput.command =
     vt inject --only-env GH_TOKEN --reason 'vt hook: gh' -- bash -c 'gh pr create --title x'
        │
        ▼  agent runs the rewritten command
   vt inject  ── decrypts GH_TOKEN (and ONLY GH_TOKEN), execs bash -c '…'
        │
        ▼
   gh sees GH_TOKEN=<plaintext>
```

The rewrite wraps the original in `bash -c '…'` because `vt inject` execs argv
directly (no shell): wrapping preserves pipes, redirects, and `&&`.

### Three outcomes

| Situation | Outcome |
|---|---|
| No rule matches the command's program | **accept** — runs unchanged (default policy) |
| Matched rule has `block = true` | **block** — `permissionDecision: deny` |
| Matched rule + ≥1 of its `env_vars` is a `vt://` value | **rewrite** to `vt inject --only-env … -- bash -c '<cmd>'` |
| Matched rule but no named env var is `vt://` | **accept** — nothing to decrypt |

## Configuration

Hook rules live in a **dedicated file**, `~/.config/vt/agent.toml` (override with
`$VT_AGENT_CONFIG`) — *not* in `config.toml`. The reason: `config.toml` holds
secrets (`VT_AUTH`, `VT_PASSKEY_TOKEN`, …) and must never be synced to a repo,
whereas hook rules carry no secrets (only command and env-var *names*) and are
meant to be shared — symlink `agent.toml` into a dotfiles repo, or point
`$VT_AGENT_CONFIG` at a checked-in copy. Top-level `[[rules]]`:

```toml
[[rules]]
command  = "gh"                          # matched against argv[0] basename
env_vars = ["GH_TOKEN", "GITHUB_TOKEN"]  # decrypted only when vt://-valued

[[rules]]
command = "gh"
args    = ["auth", "token"]               # subcommand-level deny
block   = true
reason  = "refusing `gh auth token`: it would reveal the injected GH_TOKEN"
```

- `command` is matched by **basename** of the command's leading program, so
  `gh`, `/usr/bin/gh`, and `./gh` all match `command = "gh"`. Leading
  `NAME=value` shell assignments are skipped when finding the program.
- `args` (optional) is a **positional prefix** of the tokens after the program,
  letting a rule target a subcommand: `command = "gh", args = ["auth","token"]`
  matches `gh auth token …` but not `gh auth status`. Empty = match any
  invocation of `command`.
- `args_any` (optional) is a **contains-any** guard: when set, the invocation's
  args must include at least one of these tokens (anywhere). Use it for a flag
  with no fixed position or short/long aliases — e.g. block
  `glab auth status --show-token`/`-t` (which prints the token) while leaving a
  plain `glab auth status` alone:

  ```toml
  [[rules]]
  command  = "glab"
  args     = ["auth", "status"]
  args_any = ["-t", "--show-token"]
  block    = true
  ```
- **Block beats inject.** When both a broad inject rule (`gh`) and a specific
  deny (`gh auth token`) match, the deny wins regardless of rule order — so you
  can inject `GH_TOKEN` for all of `gh` yet still forbid the one subcommand that
  would print it.
- `env_vars` are the names this rule authorizes for decryption. The rewrite
  passes them via `--only-env`, so a matched command receives **only** these
  secrets, never other `vt://` vars in the environment.
- `block = true` refuses the command outright.
- `reason` is optional; it is shown to the agent on block and recorded in the
  vt audit row on inject.

Leading `NAME=value` assignments are skipped when finding the program, so
`FOO=bar gh pr list` still matches the `gh` rule.

### Supplying env-var values (`[env]`)

Instead of requiring the agent to export secrets, the same file can carry the
**values** so the hook supplies them to matched commands. A rule must still
*name* the var in `env_vars`; `[env]` provides its value. Values are normally
`vt://` ciphertext (decrypted on use). A default applies in every working
directory; per-directory overrides let different projects get different values:

```toml
[[rules]]
command  = "gh"
env_vars = ["GH_TOKEN"]

[env.default]                            # applies in all PWDs
GH_TOKEN = "vt://0defaultCiphertext…"

[env.dirs."/home/me/work/projA"]         # override when CWD is under projA
GH_TOKEN = "vt://0projACiphertext…"
```

Resolution precedence for each named var (**env always wins; config is a
fallback** — matching vt's config.toml convention):

1. the **process environment** (what the caller exported).
2. `[env.dirs."<path>"]` — the **longest** path key that is a prefix of the
   command's CWD (the PreToolUse event's `cwd`, else the hook process's CWD).
3. `[env.default]`.

Because env wins, `[env.dirs]`/`[env.default]` only apply to vars you have NOT
exported (the intended usage — let the config supply them). Env-first also makes
the shim and PreToolUse layers compose safely: once one layer decrypts a var to
plaintext in the environment, the next sees plaintext and won't re-inject it.

Config-sourced values are prepended to the rewrite as `NAME='vt://…'`
assignments (so they need not be exported); a value found only in the process
environment is used as-is (already present for `vt inject` to scan). A command
is rewritten only if at least one named var resolves to a `vt://` value;
otherwise it runs unchanged.

## Wiring it into Claude Code

Add a PreToolUse hook for the Bash tool (Claude Code settings):

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [ { "type": "command", "command": "vt hook claude" } ] }
    ]
  }
}
```

Dry-run what a command would do, without an agent:

```bash
vt hook check gh pr create --title x      # ACCEPT / BLOCK / REWRITE <cmd>
```

## Wiring it into a shell (exec-gateway + shims)

Shells have **no native pre-exec hook that can rewrite a command** — `preexec`
(zsh / bash-preexec) and the bash `DEBUG` trap can only observe or abort, and
zsh's `accept-line` widget can rewrite but only for *interactive* input. So
instead of a hook, `vt` ships an **exec-gateway** plus **PATH shims** that work
everywhere (interactive, scripts, and non-interactive agent shells):

```bash
vt hook exec -- gh pr list     # evaluate argv, then exec it / exec under vt inject / refuse (exit 126)
```

`vt hook exec` shares the same rules and `decide()` core as the PreToolUse path,
but operates on a real argv — so there is no shell quoting and no `bash -c`
wrapper; `vt inject` execs the argv directly.

Generate one shim per command named in `agent.toml` and put them first on PATH:

```bash
vt hook install-shims                 # writes ~/.local/share/vt/shims/{gh,glab,…}
export PATH="$HOME/.local/share/vt/shims:$PATH"
```

Each shim is a **symlink to the `vt` binary** (busybox-style multi-call): when
invoked as `gh`, vt sees `argv[0] = "gh"` and behaves like `vt hook exec -- gh …`
— no shell wrapper, no extra `/bin/sh` process. When it re-execs the real tool,
`resolve_real` skips any PATH candidate that canonicalizes back to the `vt`
binary, so a shim can never resolve to itself (robust even when the shim dir is
on PATH via a symlink like `/home/me` → `/essd/me`); a `VT_HOOK_DEPTH` guard is
the backstop. Now a bare `gh pr list` — typed, scripted, or run by an agent —
transparently gets its secret, and `gh auth token` is refused. Re-run
`install-shims` after editing the rules. (For a single interactive shell you can
instead alias: `alias gh='vt hook exec -- gh'`.)

## Security properties & limits

- **Scoped injection (`--only-env`).** A rule that names `GH_TOKEN` does *not*
  also leak `ANTHROPIC_API_KEY` or `DATABASE_URL` into the command. This closes
  the confused-deputy gap where `vt inject` alone decrypts *every* `vt://` env
  var. Use direct `vt inject` (no `--only-env`) only when you intend "give this
  command all my secrets".
- **Whitelist scopes approvals.** Without it, any command with a `vt://` var in
  its environment would trigger a phone approval (even `ls`). Rules limit which
  commands may trigger a decryption ceremony.
- **Recursion guard.** A command whose leading program is `vt` is always
  accepted unchanged, so a re-fired hook never wraps `vt inject …` again.
- **Default-accept.** Unlisted commands run untouched. The hook is purely
  additive; it is *not* a sandbox. Use `block = true` rules for explicit denies.
- **Matching is argv[0]-basename only** — no globs, substrings, or regex.
- **Compound commands are segmented.** A Bash-tool command is an arbitrary
  shell snippet, so the hook splits it at top-level `|`, `||`, `&&`, `;`, and
  newlines and evaluates each segment. So `cd /repo && gh pr create` injects,
  `cat x | gh pr view` injects, and `true && gh auth token` is still **blocked**
  (no bypass). A compound with several targets (`gh … && glab …`) injects the
  union of their env vars, and the whole command runs in one `bash -c` so every
  segment sees them. Quotes, backslash escapes, and `(`/`$(` nesting are
  respected (so `--title "a && b"` and `2>&1` don't mis-split). Remaining blind
  spots: a target **inside** `$(…)`, backticks, or a `(subshell)`, and a
  background `cmd &` tail, are not separately analyzed.
- **`bash -c "…"` is opaque.** If the agent runs `bash -c "OPENAI_API_KEY=vt://… python x"`,
  the hook sees `bash`, not `python`, and the inline assignment is not a process
  env var — so it won't match a `python` rule. Instruct the agent to invoke
  programs directly (and export secrets as real env vars) rather than burying
  them in a shell string.
- **Blast radius after decryption** is the same as `vt inject`: the child (and
  its subprocesses) sees plaintext in its environment. Keep DEK-cache TTLs short
  and audit every access.
