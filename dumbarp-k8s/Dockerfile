# syntax=docker/dockerfile:1.7
# Multi-stage musl build for dumbarp-k8s (x86_64 only).
#
#   docker build -f dumbarp-k8s/Dockerfile -t dumbarp-k8s:dev .
#
# Build context must be the workspace root (so Cargo.lock + all member
# Cargo.toml files are visible to the resolver).

FROM rust:1-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release -p dumbarp-k8s && \
    mkdir -p /out && \
    cp target/release/dumbarp-k8s /out/dumbarp-k8s && \
    strip /out/dumbarp-k8s

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/dumbarp-k8s /usr/local/bin/dumbarp-k8s
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/dumbarp-k8s"]
