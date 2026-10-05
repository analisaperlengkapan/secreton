# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
# One image builds both halves: the native server binary and the WebAssembly
# bundle, via cargo-leptos. There is no second frontend image and no nginx —
# the server serves its own frontend, which is the point of the SSR move.
#
# protoc is vendored and there is no utoipa-swagger-ui downloading a zip
# mid-build, so the application's own build touches nothing but the crates
# registry. Two things in this stage still do: `cargo install cargo-leptos`
# compiles openssl-sys from source (openssl-src is in its tree), and
# cargo-leptos fetches the Tailwind CLI on first use because this project sets
# `tailwind-input-file`. Both happen while building the image, not while
# building the application — but calling the image "air-gapped" would be wrong.
#
# Debian's `binaryen` package is deliberately NOT installed. It supplies
# wasm-opt, which would save a download — but bookworm ships version 108, and
# that rejects the sign-extension instructions (`i32.extend8_s`) current rustc
# emits by default. Putting it on PATH makes cargo-leptos use it and the build
# fails at "error validating input", which is worse than the download.
#
# perl and make are what openssl-src needs. The slim image ships perl-base,
# which lacks FindBin, so OpenSSL's ./Configure aborts on line 15 and
# `cargo install cargo-leptos` fails outright — this image could not be built
# without them.
# `cargo install cargo-leptos` here compiles with the *base image's* rustc, not the
# one rust-toolchain.toml pins: the chef stage below never copies the source tree, so
# rustup has not yet seen the pin when this line runs. The two must therefore be kept
# in step with the minimum rustc cargo-leptos's dependency tree needs — current
# releases already require more than 1.94.1 (wasm_split_cli_support uses `if let`
# guards, stable only in newer compilers), and the failure surfaced as
# "error[E0658]: `if let` guards are experimental" while compiling cargo-leptos.
# The builder stage still compiles the application itself with the rust-toolchain.toml
# channel, which it downloads via rustup once the source is copied in.
FROM rust:1.99.0-slim-bookworm AS chef
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends perl make pkg-config cmake g++ \
 && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked \
 && cargo install cargo-leptos --locked \
 && rustup target add wasm32-unknown-unknown

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Cached layer: dependencies only. Invalidated by Cargo.lock, not by source edits.
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
# `cargo leptos build` accepts only `--release` — it has no `--locked`, so an
# earlier version of this line failed outright. The lockfile is still what gets
# built: it is committed and copied in above, and cargo uses a present
# Cargo.lock by default. What is lost is the *enforcement* that it needs no
# changes, so this restores it separately: `cargo metadata --locked` fails if
# resolving the graph would rewrite the lockfile, before anything is compiled.
RUN cargo metadata --locked --format-version 1 > /dev/null

# cargo-leptos downloads a wasm-bindgen-cli binary from GitHub releases unless one
# is already on PATH, and it must match the `wasm-bindgen` version in the lockfile
# exactly or the generated JS glue will not load the module. Installing it from
# crates.io at the locked version does both: the build stops reaching GitHub, and
# the version cannot drift from what the WASM was compiled against.
# wasm-opt, from crates.io rather than the binaryen release cargo-leptos would
# otherwise fetch from GitHub. The crate vendors binaryen and builds it, which is
# why cmake and g++ are in the stage above. Debian's packaged binaryen cannot be
# used instead — see the note there.
RUN cargo install wasm-opt --locked

RUN cargo install wasm-bindgen-cli --locked \
      --version "$(cargo metadata --locked --format-version 1 \
        | grep -o '"name":"wasm-bindgen","version":"[^"]*"' \
        | head -1 | sed 's/.*"version":"//;s/"//')"

RUN cargo leptos build --release

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
# Distroless: no shell, no package manager, nothing for an attacker who reaches
# code execution to pivot with. The previous image was debian-slim with curl and
# libssl-dev installed at runtime.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
WORKDIR /app

COPY --from=builder /app/target/release/secreton-server /usr/local/bin/secreton-server
COPY --from=builder /app/target/site /app/site

# `LEPTOS_SITE_ADDR` is what cargo-leptos' own server template reads. This binary
# does not: it has its own configuration, and with only that set the process bound
# the default 127.0.0.1:8080 — unreachable from outside the container, on a port
# EXPOSE does not name. The image started, logged four cheerful lines, and served
# nobody. `SECRETON__HTTP__BIND_ADDRESS` is the one the server actually reads.
#
# `LEPTOS_SITE_ROOT` is read by leptos_axum to locate the generated assets.
ENV LEPTOS_SITE_ROOT=/app/site \
    LEPTOS_SITE_ADDR=0.0.0.0:3000 \
    SECRETON__HTTP__BIND_ADDRESS=0.0.0.0:3000 \
    RUST_LOG=info

# One port. The previous deployment needed three: warp, axum at +10, and gRPC.
EXPOSE 3000

# Already `nonroot` (uid 65532) from the base image; stated explicitly so a
# future base change cannot silently promote the process to root.
USER nonroot:nonroot

# No HEALTHCHECK: distroless has no shell and no curl. Kubernetes should probe
# /health (liveness) and /health/ready (readiness) directly over HTTP.

ENTRYPOINT ["/usr/local/bin/secreton-server"]
