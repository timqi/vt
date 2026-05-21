.PHONY: build build-musl install init-linux check deploy-worker ssh

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
  INSTALL_DEP := build-musl
  BIN_SRC     := target/x86_64-unknown-linux-musl/release/vt
else
  INSTALL_DEP := build
  BIN_SRC     := target/release/vt
endif

init-linux:
	sudo apt update -y
	sudo apt install -y musl-tools build-essential pkg-config
	rustup target add x86_64-unknown-linux-musl
	rustup target add x86_64-unknown-linux-gnu

build:
	cargo build --release --bin vt

# Fully static Linux build via musl. Output: target/x86_64-unknown-linux-musl/release/vt
# Requires: rustup target add x86_64-unknown-linux-musl, and musl-gcc on PATH.
build-musl:
	CC_x86_64_unknown_linux_musl=musl-gcc \
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
	cargo build --release --bin vt --target x86_64-unknown-linux-musl

install: $(INSTALL_DEP)
	mkdir -p ~/.local/bin
	rm ~/.local/bin/vt
	cp $(BIN_SRC) ~/.local/bin/vt
	@echo "installed: ~/.local/bin/vt ($$(du -h ~/.local/bin/vt | cut -f1))"

check:
	cargo check
	cargo check --target x86_64-unknown-linux-gnu

deploy-worker:
	cd cf-worker && wrangler deploy

ssh:
	ssh -A -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
		-i .vagrant/machines/default/libvirt/private_key \
		vagrant@192.168.121.242
