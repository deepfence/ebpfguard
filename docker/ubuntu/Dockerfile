FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    libclang-dev \
    linux-tools-$(uname -r) \
    && rm -rf /var/lib/apt/lists/*

RUN curl https://sh.rustup.rs --proto '=https' --tlsv1.2 -sSf | sh -s -- -y
RUN $HOME/.cargo/bin/rustup toolchain install nightly --component rust-src
RUN $HOME/.cargo/bin/rustup component add miri --toolchain nightly
RUN $HOME/.cargo/bin/cargo install bpf-linker --git https://github.com/noboruma/bpf-linker
RUN $HOME/.cargo/bin/cargo install bindgen-cli
