#!/bin/bash
set -euo pipefail

# Setup PAM for `vt auth` as a sudo authentication factor.
#
# Two approval paths, tried in the same order vt itself routes:
#   1. SSH agent (macOS Touch ID) over a forwarded agent — needs VT_AUTH.
#   2. Phone passkey (Cloudflare Worker) — needs VT_PASSKEY_URL + VT_PASSKEY_TOKEN.
# A host may configure either or both. On a plain Linux server with no forwarded
# macOS agent, only the worker path applies (leave VT_AUTH unset).
#
# Values are resolved with the SAME precedence vt uses: environment variable
# wins, else the invoking user's ~/.config/vt/config.toml (override with
# VT_CONFIG). So `sudo ./setup-pam.sh` normally needs no arguments.
#
# Run as root (via sudo) on the target Linux server.

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (use sudo)" >&2
    exit 1
fi

# --- Resolve the invoking user's vt config -------------------------------
# sudo runs us as root, so ~ is /root. The config lives in the real user's
# home; recover it from $SUDO_USER. VT_CONFIG (if exported) always wins.
# getent can exit non-zero (SUDO_USER set but no passwd entry) — guard it so
# `set -e` doesn't abort the script, and fall back to $HOME when empty.
USER_HOME=""
if [ -n "${SUDO_USER:-}" ]; then
    USER_HOME="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6 || true)"
fi
[ -z "$USER_HOME" ] && USER_HOME="${HOME:-/root}"

if [ -n "${VT_CONFIG:-}" ]; then
    CFG="$VT_CONFIG"
else
    CFG="$USER_HOME/.config/vt/config.toml"
fi

# read_cfg KEY -> value from the flat TOML, empty if absent. Uses awk (not sed)
# to match vt's own parser closely: honours both "double" and 'single' quoted
# TOML strings and strips trailing inline `# comments`, so a common hand-edit
# (single-quoting or same-line-commenting a token) doesn't silently corrupt the
# embedded secret. Anchored at line start so keys inside comments don't match,
# and the `=`/whitespace boundary prevents prefix collisions (VT_AUTH vs VT_*).
read_cfg() {
    [ -r "$CFG" ] || return 0
    awk -v key="$1" '
        $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            sub(/^[^=]*=[[:space:]]*/, "")
            q = substr($0, 1, 1)
            if (q == "\"" || q == "\x27") {         # "double" or '\''single'\'' string
                rest = substr($0, 2)
                i = index(rest, q)
                if (i > 0) print substr(rest, 1, i - 1)
            } else {                                 # bare value: drop inline comment + trailing ws
                sub(/[[:space:]]+#.*$/, "")
                sub(/[[:space:]]+$/, "")
                print
            }
            exit
        }
    ' "$CFG"
}

if [ -r "$CFG" ]; then
    echo "Reading vt config from $CFG"
    # Secrets live here — warn (don't fail) if group/other can read it.
    perm=$(stat -c '%a' "$CFG" 2>/dev/null || echo "")
    case "$perm" in
        *[1-7][0-7] | *[0-7][1-7]) echo "  warning: $CFG is group/other-readable; chmod 600 recommended" >&2 ;;
    esac
fi

# env wins, else fall back to the config file (mirrors vt's own precedence).
VT_AUTH="${VT_AUTH:-$(read_cfg VT_AUTH)}"
VT_PASSKEY_URL="${VT_PASSKEY_URL:-$(read_cfg VT_PASSKEY_URL)}"
VT_PASSKEY_TOKEN="${VT_PASSKEY_TOKEN:-$(read_cfg VT_PASSKEY_TOKEN)}"

if [ -z "$VT_AUTH" ] && [ -z "$VT_PASSKEY_URL" ]; then
    echo "Error: no auth path configured." >&2
    echo "  Set VT_AUTH (SSH agent path) and/or VT_PASSKEY_URL + VT_PASSKEY_TOKEN" >&2
    echo "  (worker path) in the environment or in $CFG." >&2
    exit 1
fi
if [ -n "$VT_PASSKEY_URL" ] && [ -z "$VT_PASSKEY_TOKEN" ]; then
    echo "Error: VT_PASSKEY_URL set but VT_PASSKEY_TOKEN missing." >&2
    exit 1
fi

# Report which path(s) will be wired in.
paths=""
[ -n "$VT_AUTH" ] && paths="SSH-agent (Touch ID)"
[ -n "$VT_PASSKEY_URL" ] && paths="${paths:+$paths + }phone passkey (worker)"
echo "Configuring paths: $paths"

SCRIPT_PATH="/usr/local/bin/vt-sudo-auth.sh"
PAM_FILE="/etc/pam.d/sudo"
VT_ROOT_BIN="/usr/local/bin/vt"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Find the vt binary to install ---------------------------------------
# sudo replaces PATH with secure_path, so `command -v vt` alone misses the
# usual ~/.local/bin install. Probe the known locations too, list what was
# found and let the operator confirm which one becomes the root-owned copy.
# VT_BIN in the environment pins the choice and skips the prompt.
CANDIDATES=()
add_candidate() {
    local p="$1" real seen
    [ -n "$p" ] || return 0
    [ -f "$p" ] && [ -x "$p" ] || return 0
    real="$(readlink -f "$p" 2>/dev/null || echo "$p")"
    for seen in ${CANDIDATES[@]+"${CANDIDATES[@]}"}; do
        [ "$(readlink -f "$seen" 2>/dev/null || echo "$seen")" = "$real" ] && return 0
    done
    CANDIDATES+=("$p")
}

# Describe a candidate without trusting it: stat only, plus a version string
# obtained as the invoking user when possible. It is about to be executed as
# root, but not before the operator has picked it.
describe_candidate() {
    local p="$1" owner mtime ver=""
    owner="$(stat -c '%U' "$p" 2>/dev/null || echo '?')"
    mtime="$(stat -c '%y' "$p" 2>/dev/null | cut -d. -f1 || echo '?')"
    if [ -n "${SUDO_USER:-}" ] && command -v runuser >/dev/null 2>&1; then
        ver="$(runuser -u "$SUDO_USER" -- "$p" --version 2>/dev/null | head -1 || true)"
    else
        ver="$("$p" --version 2>/dev/null | head -1 || true)"
    fi
    printf '%s\n      owner=%s  mtime=%s  %s\n' "$p" "$owner" "$mtime" "${ver:-version unavailable}"
}

if [ -n "${VT_BIN:-}" ]; then
    if [ ! -f "$VT_BIN" ] || [ ! -x "$VT_BIN" ]; then
        echo "Error: VT_BIN=$VT_BIN is not an executable file" >&2
        exit 1
    fi
    echo "Using VT_BIN=$VT_BIN (from environment)"
else
    add_candidate "$USER_HOME/.local/bin/vt"
    add_candidate "$USER_HOME/bin/vt"
    add_candidate "$SELF_DIR/target/release/vt"
    add_candidate "$SELF_DIR/target/x86_64-unknown-linux-musl/release/vt"
    add_candidate "$(command -v vt 2>/dev/null || true)"
    add_candidate "$VT_ROOT_BIN"
    add_candidate "/usr/bin/vt"

    if [ "${#CANDIDATES[@]}" -eq 0 ]; then
        echo "Error: no vt binary found." >&2
        echo "  Looked in: \$PATH, $USER_HOME/.local/bin, $USER_HOME/bin," >&2
        echo "             $SELF_DIR/target/*/vt, /usr/local/bin, /usr/bin" >&2
        echo "  Build it ('just install') or point at it: sudo VT_BIN=/path/to/vt $0" >&2
        exit 1
    fi

    echo ""
    echo "Found vt binary/binaries:"
    i=0
    for c in "${CANDIDATES[@]}"; do
        i=$((i + 1))
        printf '  %d) %s\n' "$i" "$(describe_candidate "$c")"
    done

    choice=1
    if [ "${#CANDIDATES[@]}" -gt 1 ]; then
        # Read from the terminal, not stdin: pam/pipe invocations have no tty.
        # Test it by opening, not with -r: under setsid /dev/tty passes the
        # permission check and then fails to open. No tty -> take candidate 1.
        # (brace group so the failed open's message goes to /dev/null too --
        # `exec 3< /dev/tty 2>/dev/null` applies the redirections in order and
        # would still print it; fd 3 survives the group either way.)
        if { exec 3< /dev/tty; } 2>/dev/null; then
            printf 'Install which one to %s? [1-%d, default 1] ' "$VT_ROOT_BIN" "${#CANDIDATES[@]}"
            read -r reply <&3 || reply=""
            exec 3<&-
            [ -n "$reply" ] && choice="$reply"
            case "$choice" in
                '' | *[!0-9]*) echo "Error: not a number: $choice" >&2; exit 1 ;;
            esac
            if [ "$choice" -lt 1 ] || [ "$choice" -gt "${#CANDIDATES[@]}" ]; then
                echo "Error: out of range: $choice" >&2
                exit 1
            fi
        else
            echo "  (no terminal for a prompt; using 1 — set VT_BIN to override)"
        fi
    fi
    VT_BIN="${CANDIDATES[$((choice - 1))]}"
    echo "Selected $VT_BIN"
fi

# --- Install vt into a root-owned location -------------------------------
# PAM runs the helper as root, so the binary it calls must not be writable by
# the user being authenticated: a vt in ~/.local/bin would let any process
# running as that user replace it and be executed as root. Copy it to
# /usr/local/bin (root:root 755, and already in sudo's secure_path) and point
# the helper there. /usr/bin is dpkg's namespace; don't squat in it.
# Written to a temp name and rename()d so re-running while an earlier copy is
# executing can't fail with ETXTBSY or leave a half-written binary in place.
if [ "$VT_BIN" -ef "$VT_ROOT_BIN" ]; then
    echo "Using $VT_ROOT_BIN (already root-owned)"
else
    install -o root -g root -m 755 "$VT_BIN" "$VT_ROOT_BIN.new"
    mv -f "$VT_ROOT_BIN.new" "$VT_ROOT_BIN"
    echo "Installed $VT_BIN -> $VT_ROOT_BIN (root:root, 755)"
    echo "  Note: this is a COPY. Re-run this script after upgrading vt."
fi
VT_BIN="$VT_ROOT_BIN"

# --- Generate the PAM helper script --------------------------------------
# Secrets are embedded via single-quote-safe printf (no sed placeholder
# substitution — robust against &, /, backslashes in the token). env vars
# always win over any config file, so hard-coding them here is deterministic.
shq() { printf "%s" "$1" | sed "s/'/'\\\\''/g"; }

{
    echo '#!/bin/bash'
    echo '# Generated by setup-pam.sh — vt auth as a sudo factor. Keep root-only.'
    printf "export VT_AUTH='%s'\n" "$(shq "$VT_AUTH")"
    printf "export VT_PASSKEY_URL='%s'\n" "$(shq "$VT_PASSKEY_URL")"
    printf "export VT_PASSKEY_TOKEN='%s'\n" "$(shq "$VT_PASSKEY_TOKEN")"
    cat << 'BODY'

# Agent path (macOS Touch ID over a forwarded SSH agent). Skipped when VT_AUTH
# is empty. pam_exec doesn't inherit the user's env, so recover SSH_AUTH_SOCK
# from the invoking shell via /proc: user shell -> sudo -> pam_exec -> here.
if [ -z "${SSH_AUTH_SOCK:-}" ] && [ -n "$VT_AUTH" ]; then
    USER_PID=$(awk '/^PPid:/{print $2}' /proc/$PPID/status 2>/dev/null)
    if [ -n "$USER_PID" ]; then
        SSH_AUTH_SOCK=$(tr '\0' '\n' < /proc/$USER_PID/environ 2>/dev/null | sed -n 's/^SSH_AUTH_SOCK=//p')
        [ -n "$SSH_AUTH_SOCK" ] && export SSH_AUTH_SOCK
    fi
fi

# What sudo was asked to run. pam_exec is forked by sudo itself, so $PPID is
# the sudo process and its cmdline is `sudo <command>`. Display only: argv
# comes from the caller, and vt renders --reason as a client-claimed line
# after the agent's own truth lines. Empty when /proc is unreadable.
#
# Two bounds before it becomes an argument. `VAR=value` assignments are
# blanked: `sudo TOKEN=… cmd` is common and the reason is pushed to phones and
# kept in worker audit rows. Other argv secrets (`-pSECRET`) still show — see
# docs/sudo.md. The 100-char cut keeps a long command from overflowing the
# execve argument limit (which would fail the helper and silently drop the
# whole factor back to the password stack) and matches the prompt's own cap.
SUDO_CMD=$(tr '\0' ' ' < /proc/$PPID/cmdline 2>/dev/null |
    sed -E 's/([A-Za-z_][A-Za-z0-9_]*)=[^[:space:]]*/\1=…/g; s/[[:space:]]+$//')
SUDO_CMD=${SUDO_CMD:0:100}

# Refuse cleanly if neither path is usable (don't hang on a blank prompt).
if [ -z "$VT_AUTH" ] && [ -z "$VT_PASSKEY_URL" ]; then exit 1; fi

# vt routes agent-first (if VT_AUTH set + socket reachable), then falls back to
# the phone-passkey worker path. stderr is intentionally NOT silenced: pam_exec
# leaves stderr attached to the terminal, so the "approve on your phone: <url>"
# line reaches the user — the only feedback when no push channel is configured.
# timeout is 60s: a phone approval needs human reaction time (vs instant Touch
# ID). Tradeoff: sudo hangs up to 60s before falling back to the password stack.
BODY
    printf 'timeout 60 %s auth --reason "sudo ${PAM_SERVICE:-sudo} by ${PAM_USER:-unknown}${SUDO_CMD:+ — $SUDO_CMD}"\n' "$VT_BIN"
} > "$SCRIPT_PATH"

chmod 700 "$SCRIPT_PATH"
chown root:root "$SCRIPT_PATH"
echo "Created $SCRIPT_PATH (root:root, 700)"

# --- Wire into /etc/pam.d/sudo -------------------------------------------
PAM_LINE="auth    sufficient    pam_exec.so seteuid quiet $SCRIPT_PATH"
if grep -qF "vt-sudo-auth.sh" "$PAM_FILE" 2>/dev/null; then
    echo "PAM already configured in $PAM_FILE, skipping"
else
    # Insert before the first auth / @include line.
    sed -i "0,/^@include\|^auth/{s||$PAM_LINE\n&|}" "$PAM_FILE"
    echo "Updated $PAM_FILE"
fi

echo ""
echo "Done."
echo "  Agent path:  ssh -A user@this-host, then 'sudo whoami' -> Touch ID"
echo "  Worker path: 'sudo whoami' -> approve on your phone (URL shown on the terminal)"
echo "  After upgrading vt, re-run this script to refresh $VT_ROOT_BIN."
echo "  Tip: enable a push channel (Pushover/Slack/Feishu) so approvals reach your phone directly."
