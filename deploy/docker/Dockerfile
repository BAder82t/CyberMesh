# syntax=docker/dockerfile:1
# CyberMesh node image. Multi-stage: build with the pinned Rust toolchain, run as an
# unprivileged user on a slim base. FEATURES lets the demo enable the adversary simulation;
# production images must be built without it (the default).
FROM rust:1.98.1-slim-bookworm AS build
ARG FEATURES=""
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p cybermesh-cli ${FEATURES:+--features $FEATURES} \
 && strip target/release/cybermesh

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin cybermesh \
 && mkdir -p /demo && chown 10001:10001 /demo
COPY --from=build /src/target/release/cybermesh /usr/local/bin/cybermesh
COPY --chown=10001:10001 datasets /opt/cybermesh/datasets
USER 10001:10001
WORKDIR /demo
ENTRYPOINT ["/usr/local/bin/cybermesh"]
