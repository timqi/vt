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
    cargo build --release --bin vt

# CC lets `ring` (via rustls) compile its C/asm for musl. Do NOT override the
# LINKER to musl-gcc: rustc's self-contained musl linking already bundles the
# correct musl CRT + rust-lld; adding musl-gcc injects gcc's own Scrt1.o, the
# binary then double-inits the C runtime and segfaults on TLS before main.
#
# Static Linux build via musl → target/x86_64-unknown-linux-musl/release/vt
build-musl:
    CC_x86_64_unknown_linux_musl=musl-gcc cargo build --release --bin vt --target x86_64-unknown-linux-musl

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

# Type-check for host + linux-gnu targets
check:
    cargo check
    cargo check --target x86_64-unknown-linux-gnu

# Run the Rust unit + integration tests
test:
    cargo test --all-targets

# Type-check + unit-test the Cloudflare worker. Installs deps on first run.
[working-directory: 'cf-worker']
check-worker:
    #!/usr/bin/env bash
    set -euo pipefail
    [ -d node_modules ] || npm ci
    npx tsc --noEmit
    npm test

# Everything the CI gates run, in one shot (Rust + worker)
ci: check test check-worker

# Deploy the Cloudflare worker (requires wrangler on PATH)
[working-directory: 'cf-worker']
deploy-worker:
    wrangler deploy

# The GitHub `Release` workflow builds macOS arm64 + Linux amd64 and publishes.
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
