# syntax=docker/dockerfile:1
# CyberMesh node image. Multi-stage: build with the pinned Rust toolchain, run as an
# unprivileged user on a slim base. FEATURES lets the demo enable the adversary simulation;
# production images must be built without it (the default).
FROM rust:1.98.1-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS build
ARG FEATURES=""
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p cybermesh-cli ${FEATURES:+--features $FEATURES} \
 && strip target/release/cybermesh

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin cybermesh \
 && mkdir -p /demo && chown 10001:10001 /demo
COPY --from=build /src/target/release/cybermesh /usr/local/bin/cybermesh
COPY --chown=10001:10001 datasets /opt/cybermesh/datasets
USER 10001:10001
WORKDIR /demo
ENTRYPOINT ["/usr/local/bin/cybermesh"]
