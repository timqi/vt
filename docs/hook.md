# `vt hook` — PATH shims for `vt://` secrets

## Goal

Let a tool use a `vt://`-protected secret **without knowing it is protected**,
and without the secret being exported in plaintext anywhere. A bare
`gh pr create` — typed, scripted, or run by an AI agent — gets `GH_TOKEN`
decrypted for exactly that process; commands that need no secret are never
touched and never trigger an approval prompt.

## How it works

`vt hook install-shims` writes one shim per command named in
`~/.config/vt/agent.toml` and prints the PATH line to add:

```bash
vt hook install-shims                 # writes ~/.local/share/vt/shims/{gh,glab,…}
export PATH="$HOME/.local/share/vt/shims:$PATH"
```

Each shim is a **symlink to the `vt` binary** (busybox-style multi-call): when
invoked as `gh`, vt sees `argv[0] = "gh"` and runs the exec-gateway for that
command — no shell wrapper, no extra `/bin/sh` process. The same gateway is
available directly:

```bash
vt hook exec -- gh pr list            # exec unchanged / exec under vt inject / refuse (exit 126)
```

```
you run:   gh pr create --title x          (via the shim on PATH)
     │
     ▼  argv[0] = gh  → rules in agent.toml
 decide()
     │
     ▼  exec
 vt inject --only-env GH_TOKEN --reason 'vt hook: gh' -- /usr/bin/gh pr create --title x
     │
     ▼
 gh sees GH_TOKEN=<plaintext>
```

Re-run `install-shims` after editing the rules. For a single interactive shell
an alias works instead: `alias gh='vt hook exec -- gh'`.

### Three outcomes

| Situation | Outcome |
|---|---|
| No rule matches the command's program | **accept** — execs unchanged (default policy) |
| Matched rule has `block = true` | **block** — refused, exit 126 |
| Matched rule + ≥1 of its `env_vars` resolves to a `vt://` value | **inject** — exec under `vt inject --only-env …` |
| Matched rule but no named env var is `vt://` | **accept** — nothing to decrypt (config-supplied plaintext values are still set) |

## Configuration

Rules live in a **dedicated file**, `~/.config/vt/agent.toml` (override with
`$VT_AGENT_CONFIG`) — *not* in `config.toml`. The reason: `config.toml` holds
secrets (`VT_AUTH`, `VT_PASSKEY_TOKEN`, …) and must never be synced to a repo,
whereas these rules carry no plaintext (command and env-var *names* plus
`vt://` ciphertext) and are meant to be shared — symlink `agent.toml` into a
dotfiles repo, or point `$VT_AGENT_CONFIG` at a checked-in copy. Top-level
`[[rules]]`:

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

- `command` is matched by **basename** of the invoked program, so `gh`,
  `/usr/bin/gh`, and `./gh` all match `command = "gh"`.
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
- `env_vars` are the names this rule authorizes for decryption. They are passed
  via `--only-env`, so a matched command receives **only** these secrets, never
  other `vt://` vars in the environment.
- `block = true` refuses the command outright.
- `reason` is optional; it is printed on block and recorded in the vt audit row
  on inject.

### Supplying env-var values (`[env]`)

Instead of exporting secrets, the same file can carry the **values** so the shim
supplies them to matched commands. A rule must still *name* the var in
`env_vars`; `[env]` provides its value. Values are normally `vt://` ciphertext
(decrypted on use). A default applies in every working directory;
per-directory overrides let different projects get different values:

```toml
[[rules]]
command  = "gh"
env_vars = ["GH_TOKEN"]

[env.default]                            # applies in all PWDs
GH_TOKEN = "vt://0defaultCiphertext…"

[env.dirs."/home/me/work/projA"]         # override when CWD is under projA
GH_TOKEN = "vt://0projACiphertext…"
```

Resolution precedence for each named var (**this config wins over the process
env** — a stray ambient value can't override a per-project config value):

1. `[env.dirs."<path>"]` — the **longest** path key that is a prefix of the
   command's CWD. A leading `~` / `~/` in the key is expanded to the user's home
   directory.
2. `[env.default]`.
3. the **process environment** (what the caller exported) — used only when the
   config supplies nothing for the var.

Accepted tradeoff of config-first: nested shims don't compose without
double-injecting — once an outer layer decrypts a var to plaintext in the
environment, an inner layer still re-reads the config `vt://` value and
decrypts it a second time (a silent DEK-cache hit when caching is on, otherwise
an extra approval).

Config-sourced values (plaintext and `vt://` alike) are set in the environment
the gateway execs into, so they need not be exported; a value found only in the
process environment is used as-is (already present for `vt inject` to scan).
`vt inject` runs only if at least one named var resolves to a `vt://` value.

## Security properties & limits

- **Scoped injection (`--only-env`).** A rule that names `GH_TOKEN` does *not*
  also leak `ANTHROPIC_API_KEY` or `DATABASE_URL` into the command. This closes
  the confused-deputy gap where `vt inject` alone decrypts *every* `vt://` env
  var. Use direct `vt inject` (no `--only-env`) only when you intend "give this
  command all my secrets".
- **Whitelist scopes approvals.** Without it, any command with a `vt://` var in
  its environment would trigger an approval (even `ls`). Rules limit which
  commands may trigger a decryption ceremony.
- **Recursion guards.** A bare `vt` execs unchanged; when re-execing the real
  tool, `resolve_real` skips any PATH candidate that canonicalizes back to the
  `vt` binary, so a shim can never resolve to itself (robust even when the shim
  dir is on PATH via a symlink like `/home/me` → `/essd/me`). A
  `VT_HOOK_DEPTH` cap is the backstop, and "every candidate is a shim" is a hard
  error rather than a loop.
- **Default-accept.** Unlisted commands run untouched. The gateway is purely
  additive; it is *not* a sandbox. Use `block = true` rules for explicit denies.
- **Matching is argv[0]-basename** plus positional/contains-any arg tokens — no
  globs, substrings, or regex.
- **Residual gaps.** A shim is bypassed by an absolute-path invocation
  (`/usr/bin/gh`) or a PATH that doesn't put the shim dir first. A program named
  inside `bash -c "…"` still hits its own shim at exec time, but the rules never
  see the shell string itself.
- **Blast radius after decryption** is the same as `vt inject`: the child (and
  its subprocesses) sees plaintext in its environment. Keep DEK-cache TTLs short
  and audit every access.
