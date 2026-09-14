FROM rust:1-bookworm AS build
RUN apt-get update -qq && apt-get install -y -qq musl-tools && rustup target add x86_64-unknown-linux-musl
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY tests ./tests
RUN CC_x86_64_unknown_linux_musl=musl-gcc cargo build --locked --release --bin vt --target x86_64-unknown-linux-musl

FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq git ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/vt /usr/local/bin/vt
RUN useradd -m tester
USER tester
WORKDIR /home/tester

