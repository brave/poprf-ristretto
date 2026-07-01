FROM rust:1.96.0-slim-bookworm@sha256:4732ca96fd086cb9be682050c3f0176288eebaac2b80aa2bcefccfaf198e1950

ARG WASM_PACK_VERSION=0.15.0
ARG NODE_VERSION=24.15.0
ARG NODE_SHA256=44836872d9aec49f1e6b52a9a922872db9a2b02d235a616a5681b6a85fec8d89

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl make jq \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.gz" \
    && echo "${NODE_SHA256} node-v${NODE_VERSION}-linux-x64.tar.gz" | sha256sum -c - \
    && tar -xzf "node-v${NODE_VERSION}-linux-x64.tar.gz" -C /usr/local --strip-components=1 --no-same-owner \
    && rm "node-v${NODE_VERSION}-linux-x64.tar.gz"

RUN rustup target add wasm32-unknown-unknown \
    && cargo install wasm-pack --version "${WASM_PACK_VERSION}" --locked \
    && chmod -R a+rwX /usr/local/cargo /usr/local/rustup

WORKDIR /work
