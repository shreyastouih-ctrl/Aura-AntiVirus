# syntax=docker/dockerfile:1
#
# Multi-stage harness that builds auraav-cli and runs the SAFE synthetic
# detection test-suite. No live malware is ever downloaded or executed.
#
# Build (from the repository root):
#   docker build -f docker/Dockerfile -t auraav-test .
# Run:
#   docker run --rm auraav-test
# The container exits non-zero if any expected detection is missed.

FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# The Tauri workspace member needs WebKitGTK and is irrelevant to the CLI;
# drop it so the CLI builds in a plain Rust image.
RUN sed -i '/auraav-tauri/d' Cargo.toml
RUN cargo build --release -p auraav-cli

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends jq ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/target/release/auraav-cli /app/auraav
COPY data /app/data
COPY docker/corpus/generate.sh /app/generate.sh
COPY docker/run-tests.sh /app/run-tests.sh
RUN chmod +x /app/generate.sh /app/run-tests.sh
ENV AURAAV_DATA_DIR=/app/data \
    LOG_FILE=/tmp/auraav-scan.json
ENTRYPOINT ["/app/run-tests.sh"]
