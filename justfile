set shell := ["bash", "-uc"]

# List available recipes
default:
    @just --list

# Install Linux build toolchain (musl + gnu targets)
init-linux:
    sudo apt update -y
    sudo apt install -y musl-tools build-essential pkg-config
    rustup target add x86_64-unknown-linux-musl
    rustup target add x86_64-unknown-linux-gnu

# Release build
build:
    cargo build --locked --release --bin vt

# CC lets `ring` (via rustls) compile its C/asm for musl. Do NOT override the
# LINKER to musl-gcc: rustc's self-contained musl linking already bundles the
# correct musl CRT + rust-lld; adding musl-gcc injects gcc's own Scrt1.o, the
# binary then double-inits the C runtime and segfaults on TLS before main.
#
# Static Linux build via musl → target/x86_64-unknown-linux-musl/release/vt
build-musl:
    CC_x86_64_unknown_linux_musl=musl-gcc cargo build --locked --release --bin vt --target x86_64-unknown-linux-musl

# Build and install vt to ~/.local/bin
install:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "$(uname -s)" = "Linux" ]; then
      just build-musl
      BIN=target/x86_64-unknown-linux-musl/release/vt
    else
      just build
      BIN=target/release/vt
    fi
    mkdir -p ~/.local/bin
    rm -f ~/.local/bin/vt
    cp "$BIN" ~/.local/bin/vt
    echo "installed: ~/.local/bin/vt ($(du -h ~/.local/bin/vt | cut -f1))"

# Assemble VT.app (macOS): Rust binary + Swift menu-bar shell + icns.
# Ad-hoc signed by default; export VT_CODESIGN_ID for a stable identity
# (reduces Keychain re-authorization — see docs/app-bundle.md#install-and-signing).
# VT_APP_BIN: reuse a prebuilt `vt` instead of `just build` (CI passes the
# target-specific release binary to avoid a second compile).
app:
    #!/usr/bin/env bash
    set -euo pipefail
    [ "$(uname -s)" = "Darwin" ] || { echo "error: VT.app builds on macOS only" >&2; exit 1; }
    if [ -n "${VT_APP_BIN:-}" ]; then
      BIN="$VT_APP_BIN"
    else
      just build
      BIN=target/release/vt
    fi
    APP=build/VT.app
    rm -rf "$APP"
    mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
    VERSION="$("$BIN" version 2>/dev/null | awk 'NR==1{print $2}')"
    sed "s/VT_BUNDLE_VERSION/${VERSION:-0.0.0}/g" app/Info.plist > "$APP/Contents/Info.plist"
    # Shell binary is "VTApp" (NOT "VT"): APFS is case-insensitive by
    # default, so "VT" would collide with the "vt" CLI beside it.
    swiftc -O -o "$APP/Contents/MacOS/VTApp" app/VTShell.swift
    cp "$BIN" "$APP/Contents/MacOS/vt"
    # AppIcon.icns from the Worker PWA icon (single source of truth).
    ICONSET=build/AppIcon.iconset
    rm -rf "$ICONSET" && mkdir -p "$ICONSET"
    SRC=cf-worker/pwa/icon-512.png
    for SZ in 16 32 64 128 256 512; do
      sips -z $SZ $SZ "$SRC" --out "$ICONSET/icon_${SZ}x${SZ}.png" >/dev/null
      DBL=$((SZ * 2))
      sips -z $DBL $DBL "$SRC" --out "$ICONSET/icon_${SZ}x${SZ}@2x.png" >/dev/null
    done
    iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
    rm -rf "$ICONSET"
    codesign --force --deep -s "${VT_CODESIGN_ID:--}" "$APP"
    echo "built: $APP (version ${VERSION:-unknown}, signed: ${VT_CODESIGN_ID:-ad-hoc})"

# Install VT.app to /Applications and symlink the CLI to ~/.local/bin/vt
install-app: app
    #!/usr/bin/env bash
    set -euo pipefail
    # A running VT.app and its managed agent are stopped before the copy and
    # reopened after it, so the new build serves immediately (grants drop).
    # An agent started outside the bundle is left alone.
    AGENT='/Applications/VT.app/Contents/MacOS/vt ssh agent'
    RUNNING=0
    if pgrep -xq VTApp || pgrep -fq "$AGENT"; then
      RUNNING=1
      osascript -e 'quit app id "dev.rustyvault.vt"' >/dev/null 2>&1 || true
      pkill -f "$AGENT" || true
      for _ in $(seq 50); do pgrep -fq "$AGENT" || break; sleep 0.1; done
      if pgrep -fq "$AGENT"; then echo "error: old agent did not exit" >&2; exit 1; fi
    fi
    rm -rf /Applications/VT.app
    cp -R build/VT.app /Applications/VT.app
    mkdir -p ~/.local/bin
    rm -f ~/.local/bin/vt
    ln -s /Applications/VT.app/Contents/MacOS/vt ~/.local/bin/vt
    echo "installed: /Applications/VT.app; CLI: ~/.local/bin/vt -> bundle"
    if [ "$RUNNING" = 1 ]; then
      open -a /Applications/VT.app
      echo "restarted: VT.app and managed agent"
    fi

# Type-check for host + linux-gnu targets
check:
    cargo check
    cargo check --target x86_64-unknown-linux-gnu

# Print the AGENTS.md budget table with live line counts
size:
    #!/usr/bin/env bash
    set -euo pipefail
    # Non-blank, non-comment lines (`//`, `/* */`); every `#[cfg(test)]` item is
    # skipped to its closing brace at the attribute's indentation (rustfmt puts
    # it there), so a test-only fn early in a file hides nothing after it.
    count() {
        local total=0 n
        for f in "$@"; do
            n=$(awk '
                block { if (index($0, "*/")) block = 0; next }
                skip {
                    if (first) { first = 0; if ($0 ~ /[;}][[:space:]]*$/) skip = 0; next }
                    if ($0 ~ ("^" ind "}")) skip = 0
                    next
                }
                /^[[:space:]]*#\[cfg\(test\)\]/ { match($0, /^[[:space:]]*/); ind = substr($0, 1, RLENGTH); skip = 1; first = 1; next }
                /^[[:space:]]*\/\*/ { if (!index($0, "*/")) block = 1; next }
                !/^[[:space:]]*(\/\/|$)/ { c++ }
                END { print c + 0 }' "$f")
            total=$((total + n))
        done
        echo "$total"
    }
    files() { fd -e rs -e ts -E '*.test.ts' . "$@"; }
    row() { printf '%-22s %6s %6s\n' "$1" "$2" "$3"; }
    row Area Lines Ceiling
    row 'src/core/'          "$(count src/core.rs $(files src/core))"   1700
    row 'src/client/'        "$(count src/client.rs $(files src/client))" 1800
    row 'src/server_macos/'  "$(count $(files src/server_macos))" 4500
    row 'root src/*.rs'      "$(count $(ls src/*.rs | grep -v -e /core.rs -e /client.rs) $(files src/config))" 2700
    row 'cf-worker/src/'     "$(count $(files cf-worker/src))"       4100
    echo
    echo 'Modules over 750:'
    for f in $(files src cf-worker/src); do
        n=$(count "$f"); [ "$n" -gt 750 ] && row "  $f" "$n" 750 || true
    done

# Type-check the macOS tree from Linux: a stub `cc` lets ring's C build "succeed"
# (empty objects; check only, never link). Needs `rustup target add aarch64-apple-darwin`.
check-darwin:
    #!/usr/bin/env bash
    set -euo pipefail
    dir=$(mktemp -d); trap 'rm -rf "$dir"' EXIT
    cat > "$dir/cc" <<'SH'
    #!/bin/bash
    for a in "$@"; do case "$a" in -E|*detect_compiler_family*) echo clang; exit 0;; '-?') exit 1;; esac; done
    out=""; while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; -o*) out="${1#-o}"; shift;; *) shift;; esac; done
    [ -n "$out" ] && : > "$out"; exit 0
    SH
    chmod +x "$dir/cc"
    CC_aarch64_apple_darwin="$dir/cc" cargo check --target aarch64-apple-darwin --all-targets

# Run the Rust unit + integration tests
test:
    cargo test --all-targets

# On Linux this cannot see `src/server_macos/**`; CI's macos-latest leg can.
# Lint gates: clippy warning-free + rustfmt a no-op
lint:
    cargo clippy --all-targets -- -D warnings
    cargo fmt --check

# Type-check + unit-test the Cloudflare worker. Installs deps on first run.
#
# `--include=dev` is not optional: a shell with NODE_ENV=production makes npm
# skip devDependencies, so `npm ci` would install neither typescript nor vitest
# and both gates below would be running on nothing. The guard tests for the
# binaries rather than the directory for the same reason — a partial install
# leaves node_modules/ present but unusable. `node_modules/.bin/tsc` rather than
# `npx tsc`: with typescript missing, npx silently fetches the unrelated
# `tsc@2.0.4` package from the registry and "passes".
[working-directory: 'cf-worker']
check-worker:
    #!/usr/bin/env bash
    set -euo pipefail
    # npm writes node_modules/.package-lock.json on install, so an older stamp
    # (or a missing binary) means the tree does not match package-lock.json —
    # e.g. a branch that added a devDependency was just merged in.
    if [ ! -x node_modules/.bin/tsc ] || [ ! -x node_modules/.bin/vitest ] \
       || [ package-lock.json -nt node_modules/.package-lock.json ]; then
      npm ci --include=dev
    fi
    node_modules/.bin/tsc --noEmit
    npm test

# Everything the CI gates run, in one shot (Rust + worker)
ci: check lint test check-worker

# Stamp <YYYYMMDD>-<git short hash> into ASSET_VER (cf-worker/src/index.ts).
# Run after changing anything shipped from cf-worker/pwa/ (css / js / the page
# shells) so browsers refetch it instead of a stale far-future-cached copy;
# then `just deploy-worker`. Replaces hand-editing the constant.
bump-assets:
    #!/usr/bin/env bash
    set -euo pipefail
    ver="$(date +%Y%m%d)-$(git rev-parse --short HEAD)"
    file=cf-worker/src/index.ts
    sed "s/^const ASSET_VER = '.*';\$/const ASSET_VER = '${ver}';/" "$file" > "$file.new"
    mv "$file.new" "$file"
    # Fail loudly rather than silently no-op if the constant ever moves/renames.
    grep -q "^const ASSET_VER = '${ver}';\$" "$file"
    echo "ASSET_VER = ${ver}"

# Deploy the Cloudflare worker (requires wrangler on PATH)
[working-directory: 'cf-worker']
deploy-worker:
    wrangler deploy

# The GitHub `Release` workflow builds the bare `vt` (macOS arm64 + Linux
# amd64) plus an ad-hoc-signed VT.app tarball (macOS), and publishes.
# The short hash makes same-day releases unique and matches `vt version` output.
#
# Cut a CalVer release: tag `vYYYYMMDD-<shorthash>` and push it
release:
    #!/usr/bin/env bash
    set -eu
    # The tag must point at a committed, reproducible state.
    if [ -n "$(git status --porcelain)" ]; then
      echo "error: working tree not clean — commit or stash first" >&2
      git status --short >&2
      exit 1
    fi
    git fetch --tags --quiet
    TAG="v$(date +%Y%m%d)-$(git rev-parse --short HEAD)"
    if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1; then
      echo "error: tag $TAG already exists (nothing new to release)" >&2
      exit 1
    fi
    git tag -a "$TAG" -m "release $TAG"
    git push origin "$TAG"
    echo "pushed $TAG — GitHub Release workflow will build & publish"
    echo "watch: gh run watch   |   https://github.com/timqi/vt/actions"

# SSH into the Vagrant test VM
ssh:
    ssh -A -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -i .vagrant/machines/default/libvirt/private_key \
      vagrant@192.168.121.242

run-test-cli:
    docker build -t vt-test .
    docker run -it --rm --name vt-host -e VT_PASSKEY_URL=https://test-vt.timqi.com -e VT_PASSKEY_TOKEN='vt1.NJN73mOXhMgqLYKt.4XF7zi_8nzjr3EFEJTV97MR9TUHOO6qfN2abAc3jat0' vt-test bash
