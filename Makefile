.PHONY: build install check deploy-worker

build:
	cargo build --release --bin vt

install: build
	mkdir -p ~/.local/bin
	cp target/release/vt ~/.local/bin/vt

check:
	cargo check
	cargo check --target x86_64-unknown-linux-gnu

deploy-worker:
	cd cf-worker && wrangler deploy

ssh:
	ssh -A -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
		-i .vagrant/machines/default/libvirt/private_key \
		vagrant@192.168.121.242
