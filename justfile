build:
    cargo build --release --bin vt
    codesign --force --sign "qiqi dev" target/release/vt

install: build
    mkdir -p ~/.local/bin
    rm ~/.local/bin/vt
    cp target/release/vt ~/.local/bin/vt

restart: install
    msv restart vt

ssh:
    ssh -A -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -i .vagrant/machines/default/libvirt/private_key \
        vagrant@192.168.121.242
