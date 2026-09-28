# Contributing to Secreton

Thanks for helping. Secreton is a secrets-management platform and pre-1.0 — the API and
storage shapes can still change, so a contribution that simplifies something is as welcome
as one that adds something.

> **Start with [`AGENTS.md`](AGENTS.md).** It is the single source of truth for the layout,
> the commands, and the invariants review enforces. This file covers the human workflow
> around it; where the two disagree, `AGENTS.md` wins.

## Before you start

Read the invariants in `AGENTS.md`. They are not style preferences — each one is there
because violating it caused a real defect here. The three that surprise people most:

- **Axum only, one listener.** The UI, the REST API and gRPC answer on one port from one
  router. If you find yourself adding a second `serve()` call, stop.
- **No build-time network access.** A build script that downloads an artifact breaks
  hermetic, offline and air-gapped builds. This is why `utoipa-swagger-ui` is not a
  dependency and `protoc` is vendored.
- **Audit before returning.** Any handler that reads, writes or deletes a secret emits an
  `AuditEvent` — including on the denial path, which is the path that matters.

## Setup

### Prerequisites

- Rust — rustup installs the pinned toolchain from `rust-toolchain.toml` (1.94.1) on first
  use. Do not pass `+nightly` to any command.
- [`cargo-leptos`](https://github.com/leptos-rs/cargo-leptos):
  `cargo install cargo-leptos --locked --version 0.3.7`. The pin is required on this
  toolchain — 0.3.8 and later resolve `wasm_split_cli_support` 0.2.3, which does not
  compile on 1.94.1 (E0658). See the Dockerfile.
- PostgreSQL and MySQL — only if you are working on the dynamic database-credentials
  engine. Everything else runs against in-memory storage with no external service.
- Node and `playwright-core` — only for regenerating screenshots. The version is pinned in
  the root `package.json`; see [Screenshots](#screenshots).

### Get it running

```bash
git clone https://github.com/analisaperlengkapan/secreton.git
cd secreton

export SECRETON__AUTH__JWT__SECRET="$(openssl rand -base64 48)"
cargo leptos serve
```

Then open <http://localhost:3000>. A fresh instance is sealed and has no accounts; the
quick-start in the [README](README.md#quick-start) initialises it, unseals it, and creates
a user you can sign in with. Storage defaults to in-memory, so there is nothing to set up
and nothing to clean up — but state is gone on restart.

## Layout

Ten crates, strictly layered: a crate may only depend on those above it.

| Crate | What it holds | May not contain |
|---|---|---|
| `crates/domain` | Shared types, the one `SecretonError`, the API envelope | Any I/O, any web framework — it must keep compiling for `wasm32-unknown-unknown` |
| `crates/crypto` | AEAD, KDF, signing, Shamir, the transit engine, the barrier | Storage, HTTP |
| `crates/storage` | One `StorageBackend` trait; memory, file, PostgreSQL, Redis, Raft | Business logic |
| `crates/auth` | Auth methods, identity, MFA, tokens, policy engine, governance | HTTP, axum layers |
| `crates/engines` | Secret engines, seal, audit, lifecycle, the `Services` graph | HTTP — no `axum`, no `Request`, no `StatusCode` |
| `crates/ui` | Leptos components, routes, server functions | Server-only dependencies |
| `crates/server` | Axum router, handlers, middleware, gRPC, the binary | Business logic — delegate to `engines` |
| `crates/client` | Typed HTTP client over `/api/v1` | — |
| `crates/cli`, `crates/agent` | Binaries built on `client` | Direct storage access |

The reason for the layer boundary is concrete: it is what lets the same service back a REST
handler, a gRPC method and a Leptos server function without a translation layer, and what
lets the UI share its request and response types with the backend so a mismatch is a
compile error rather than a runtime surprise.

## Checks

Run these before pushing. CI runs exactly this set, plus a feature matrix, an MSRV job, a
docs job and a Docker build.

```bash
cargo fmt --all
cargo clippy --workspace --locked --all-targets -- -D warnings
cargo test   --workspace --locked

# The UI must keep compiling for wasm. This is the guardrail that catches a
# server-only dependency leaking into crates/ui.
cargo check -p secreton-ui --locked --target wasm32-unknown-unknown \
    --no-default-features --features hydrate
```

Both feature combinations of the server must also build:

```bash
cargo check -p secreton-server --locked --no-default-features
cargo check -p secreton-server --locked --features grpc
```

`docker build -t secreton:local .` is worth running when you touch the frontend build. The
image is the only thing that exercises cargo-leptos end to end — the Tailwind run,
wasm-bindgen, wasm-opt and the feature set cargo-leptos builds with. Six separate defects
lived in that path while every cargo command passed.

## Testing

Unit tests live beside the code in `#[cfg(test)]`; integration tests go in that crate's
`tests/`. There is no root `tests/` directory — the root manifest is a virtual workspace,
so cargo never builds one, and roughly thirty files sat there for months being silently
ignored.

Two rules worth stating explicitly:

- **Name a test after the property, not the function.** `rolled_back_transaction_writes_are_discarded`,
  not `test_transaction`. The name is what tells the next person what regressed.
- **Never depend on the network.** If you need an endpoint that cannot be reached, use
  `192.0.2.1` (RFC 5737).

Cryptographic code gets property tests in `crates/crypto/tests/properties.rs`. The dynamic
database-credentials engine gets integration tests that connect to a live server and assert
the account exists after issuing and is gone after revoking — a generated username and
password returned without provisioning anything is not an implementation, and a caller
cannot tell the difference from a response body.

Tests that need a real service skip when its environment variable is unset, and CI sets all
three:

| Variable | Service | What it proves |
|---|---|---|
| `SECRETON_TEST_POSTGRES_URL` | PostgreSQL | Issued database credentials correspond to a real account; two replicas sharing one PostgreSQL admit exactly one `init`; `store_fenced` refuses a lost lease and leaves the winner's record untouched |
| `SECRETON_TEST_MYSQL_URL` | MySQL/MariaDB | The same for MySQL |
| `SECRETON_TEST_REDIS_URL` | Redis | `delete_by_path` reports and performs the delete; `compare_and_set` arbitrates; `store_fenced` refuses a stale attempt without repointing the path mapping; two replicas sharing one Redis admit exactly one `init` |

The Redis tests exist because "path-keyed operations are a no-op" was true of that backend
and could only be caught against the real server — a double cannot show whether the Lua
script does what the Rust around it assumes.

## Adding things

### A REST endpoint

Handler in `crates/server/src/handlers/`, exposed from that module's `routes()`. Business
logic goes in `crates/engines`, never in the handler. Add the `utoipa` annotation so it
appears in the OpenAPI document. Public (pre-auth) routes go in `public_routes()`;
everything else sits behind the auth layer by default.

Return errors through the shared envelope; do not leak internals. A 5xx body carries a
fixed string, with the detail going to the log correlated by `x-request-id` — connection
strings and file paths must never reach a response body.

### A UI page

Components in `crates/ui/src/components/`, pages in `crates/ui/src/pages/`, routed in
`app.rs`. Fetch data with a `#[server]` function, not a hand-written `fetch` — the server
function shares its types with the backend, so a mismatch is a compile error. Any page you
add must be reachable from `app.rs`; an unrouted page is dead code.

### A storage backend

Implement `StorageBackend` in `crates/storage/src/backends/`, behind a cargo feature, with
integration tests. A backend without tests does not go in — nineteen were deleted for
exactly this reason: they compiled, were selectable from config, and returned
`"Not implemented"` in production.

### A dependency

Add it to `[workspace.dependencies]` in the root manifest and reference it as
`foo.workspace = true`. Never pin a version in a member crate: that is how this repository
ended up with two versions of `axum` and `reqwest` in one tree.

## Screenshots

UI changes should show their result. The capture script signs in through the real form —
the session is in an `HttpOnly` cookie, so driving the form is the only way in — and fails
if any view is blank, errored, overflowing, or logging an unexpected console error.

Its one dependency is declared and pinned in the root [`package.json`](package.json), so a
capture is reproducible rather than dependent on whatever `NODE_PATH` happens to hold.
None of this is part of the Rust build.

```bash
npm ci                                      # installs the pinned playwright-core
npm run browser:install                     # once, fetches the matching Chromium
npm run screenshots:check                   # optional: prove the browser launches
cargo leptos serve                          # in one terminal
npm run screenshots                         # in another
```

`npm run browser:install` is a separate step on purpose: `npm install` should not reach the
network for a browser, and neither should anything in the Rust build. If you already have a
Chromium, skip it and set `CHROMIUM_PATH=/path/to/chromium`.

It writes `docs/screenshots/*.png`, which the README embeds. A screenshot that shows a
blank page or a raw error is worse than none, which is why the script asserts rather than
just capturing.

CI runs the same suite in the [`Screenshots`](.github/workflows/screenshots.yml) workflow:
it starts a server, creates an account with a password generated per run, captures every
view and fails on any assertion. The job never commits the images. If the capture changes a
*deterministic* view (login, login-error, not-found, mobile-login) it fails the job, because
a warning cannot establish that the committed images still depict the current UI. The
dashboard views embed the live secret count and move on their own, so their drift warns and
uploads the new images as an artifact for a human to judge. Regenerate and commit
deliberately with the commands above.

## Commits and pull requests

Conventional-commit titles (`feat:`, `fix:`, `refactor:`, …) with a capitalised subject.

Before opening a PR:

- [ ] `cargo fmt --all`
- [ ] `cargo clippy --workspace --locked --all-targets -- -D warnings`
- [ ] `cargo test --workspace --locked`
- [ ] The wasm check above
- [ ] You ran the app and exercised the change
- [ ] No new build-time network access
- [ ] No secret, token or key material in a log line, `Debug` impl or error message
- [ ] Secret-touching paths emit an audit event, including on denial

State in the description what you verified and what you did not. An unticked box is
information, not a failure — claiming verification you did not perform is the actual
problem.

## Reporting bugs and security issues

Open a GitHub issue for bugs; include what you expected, what happened, and the smallest
reproduction you have.

For a vulnerability, **do not open a public issue** — follow [SECURITY.md](SECURITY.md) and
report it privately. That file also documents the project's design commitments and its
known limitations, which is the honest place to look before concluding that something is a
bug.

## Community

Be decent to each other; the standards are in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Report unacceptable behaviour to the maintainer address in `Cargo.toml`.
