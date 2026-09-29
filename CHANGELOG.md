# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Full architectural rewrite. The workspace went from 23 crates and ~170k lines to 10 crates
and ~59k, and from not compiling at all to a green build with a full test suite.

### Fixed

- The Docker image builds and runs. It never had been built: `cargo install cargo-leptos`
  failed for want of perl, `cargo leptos build --locked` used a flag that does not exist,
  `style-file` pointed at a file that has never been in the repository, `secreton-server`
  had no `ssr` feature for cargo-leptos to build with, the Tailwind config was v3 syntax
  against the v4 CLI cargo-leptos fetches, and the runtime bound 127.0.0.1:8080 — so even
  once it built, the container served nobody.

- `cargo deny check` passes. It had never been run against this branch: the `bincode`
  direct dependency is permanently unmaintained (RUSTSEC-2025-0141), an ignore for
  `fxhash`/wasmtime referred to a dependency this repository no longer has, and the
  advisories for `rustls-pemfile` and `proc-macro-error2` were undeclared. Every remaining
  ignore now states why it is there and what would let it be removed.
- The in-memory cache encodes entries with `postcard` instead of `bincode`, and the
  encoding is covered by round-trip tests — including that corrupt bytes are rejected
  rather than decoded into a partial entry and returned as a cache hit.

- **The workspace could not be built.** `rust-version = "1.95"` exceeded every available
  toolchain, and with `--ignore-rust-version` the build still failed because
  `utoipa-swagger-ui`'s build script downloads a zip over the network at compile time.
- **Transactions silently discarded writes.** `begin_transaction()` on the in-memory
  backend returned a transaction whose `store`, `update` and `delete` were `Ok(())` no-ops;
  a caller that committed was told it had succeeded.
- **One failing webhook aborted secret expiry.** `trigger_lifecycle_hook` propagated errors
  with `?`, so an unreachable third-party endpoint left expired secrets live and skipped
  every hook after it.
- **Services were resolved by string from a `Box<dyn Any>` registry**, and the router
  resolved the admin service from a field holding the audit logger.
- **CORS defaulted to `allow_origin: ["*"]`** and the router applied `Any` for origins,
  methods and headers — on a secrets manager, out of the box.
- **Sessions were JWTs in `localStorage`**, readable by any injected script.
- **`/metrics` returned hardcoded zeros**, so a dashboard built on it looked healthy.
- **The liveness probe required a bearer token**, because the middleware's list of public
  paths had drifted from the router.
- **Rate limiting silently did nothing** whenever its `init_rate_limiting()` call was
  skipped, and identified clients by the first `X-Forwarded-For` entry, which any client
  can set.
- **5xx bodies could leak connection strings and file paths.**
- Two `try_into().unwrap()` calls panicked on short caller-supplied key material.
- Dynamic database credentials now work. The `postgres` and `mysql` features the engine
  branched on were never declared, so both paths compiled out and the endpoint answered
  "feature disabled" in every build; the MongoDB and Redis paths returned a generated
  username and password without creating any account. PostgreSQL and MySQL are now wired
  with real drivers and integration tests against live servers; MongoDB and Redis are gone.
- MySQL revocation now drops the account on every host it exists for. It dropped only
  `'user'@'%'`, so an account created under any other host survived revocation and stayed
  usable — the one outcome revocation exists to prevent. The host is also configurable
  per role now (`mysql_host`, default `%`) instead of hardcoded.
- Concurrent credential issuance for one role no longer fails with `tuple concurrently
  updated`, and PostgreSQL errors now carry the SQLSTATE and server message instead of
  the literal string "db error".
- Argon2id no longer panics when `parallelism` is absent from a parameter set.
- JWT `iat`/`exp` conversion is checked; a clock before 1970 used to wrap into a token
  that never expired.
- A malformed OIDC URL in configuration is an error rather than a startup panic.
- The cache and the agent's metrics registry use non-poisoning locks; one panicking
  holder no longer turns a cache into a process-wide outage.
- `cargo audit` and `cargo deny check advisories` pass. RUSTSEC-2026-0285 was
  published against `rustls` after this lockfile was written, and both jobs reported
  it against the committed `rustls` 0.23.43. The advisory's patched range starts at
  0.23.45, so no earlier release clears it. `rustls` is now 0.23.45; the same update
  moves `rustls-webpki` 0.103.13 → 0.103.15 and pulls `aws-lc-rs` 1.18.1 with
  `aws-lc-sys` 0.45.0. Nothing in the workspace pins either crate below the patched
  release, and no other package moves.
- The `Docker build` job passes. It failed in `cargo install cargo-leptos --locked`
  before reaching this workspace: unpinned, `cargo-leptos` resolved to 0.3.9, which
  requires `wasm_split_cli_support ^0.2.3`, and that crate's `reloc.rs` uses `if let`
  guards in match arms — still unstable on the pinned 1.94.1 toolchain, so the install
  aborted with E0658. `cargo-leptos` is now pinned to 0.3.7, whose published lockfile
  resolves the 0.2.2 release that compiles.
- The `Secret scanning` job passes. `gitleaks-action` v2 refuses to scan a repository
  owned by an organization without a `GITLEAKS_LICENSE` issued by gitleaks.io, and this
  repository belongs to one, so the job exited before reading a line of the tree on
  every run. The scanner binary is MIT-licensed and needs no key, so the workflow now
  runs it directly, pinned by version and verified by sha256. A pull request or a push
  scans only the commits under test; the nightly run scans the tree as it stands. The
  tree scan reports one finding — a `"transit-_key-1"` string literal in a
  key-rotation test, scored as a generic API key on entropy — which names a key rather
  than containing one. It is listed in `.gitleaksignore`.
- **A failure while initialising a new vault could make it permanently unusable.** `init`
  stored the initialization status before writing the root identity; if that write failed,
  the call returned an error before the unseal shares reached the operator, every later
  `init` was refused because the status looked set, and a restart discarded the in-memory
  root key. Initialization is now staged: a marker is written first and removed last, a
  failure rolls the partial state back, and the vault is re-initialisable without a restart
  or manual cleanup.
- **An initialization attempt that lost its cross-process lease could still overwrite the
  winner's root key.** Every durable write of the sequence was authorised by a preceding
  check against an in-process flag, so an attempt whose lease had expired and been taken
  over could pass that check and write afterwards — and on Redis the write repointed the
  path mapping, leaving the winner's returned shares unable to open the root key the path
  resolved to. Artifact writes now go through `StorageBackend::store_fenced`, which makes
  the write itself conditional on the lease record still carrying the attempt's token, in
  one step in the shared backend: PostgreSQL locks the lease row with `FOR SHARE` in the
  same statement that writes the artifact, Redis evaluates the fence in one Lua script, and
  the file backend holds an OS advisory lock across both. A backend that cannot enforce a
  fence returns `StorageError::Unsupported` and `init` treats that as a hard failure rather
  than falling back to an unconditional write.
- **The PostgreSQL fence was a snapshot read, so a takeover in flight did not stop a stale
  write.** `store_fenced` used `INSERT ... SELECT ... WHERE EXISTS (SELECT 1 FROM
  secreton_entries WHERE path = $13 AND metadata->>'storage_owner' = $14)`. Under READ
  COMMITTED that is an unlocked read of the statement's snapshot: a takeover that had
  executed its `UPDATE` but not yet committed was invisible, so the stale attempt still saw
  its own token, its write committed *after* the takeover, and the path then resolved to the
  loser's record — the winner's shares no longer opened the stored root key. The fence is now
  a CTE that selects the lease row `FOR SHARE`, so the fence read takes a row lock for the
  statement's duration; a concurrent takeover blocks it, and when the takeover commits the
  lock is re-evaluated against the new row version, so a token that is no longer the lease's
  owner matches nothing and the write affects zero rows.
- **A conditional or fenced Redis write made an expiring record immortal.** Both scripts
  `SET` the value and the path mapping with no deadline, so a caller that asked for an
  expiry got a record that Redis served forever while its own body still said `expires_at`
  had passed. The deadline is now applied inside the script, as an absolute Unix second so
  a retry after the "identity moved" signal cannot shorten the TTL by the elapsed time.
- **A superseded record appeared in `list` and inflated `count`.** Redis entry keys and
  file records are keyed by id, and `store` is last-writer-wins by id, so a rewrite carrying
  a fresh id for an existing path left the previous record behind — a deleted secret `list`
  still showed, and `count` grew on every update. Redis `list` now keeps only the record
  each path mapping currently names; the file backend orders candidates by `(updated_at,
  id)` and keeps the one a read resolves to, so `list`, `count` and `get_by_path` cannot
  disagree.
- **`MemoryBackend::get_by_id` and `delete_by_id` took their two locks in the opposite
  order to every writer**, so a reader holding `id_index` while waiting for `data` deadlocked
  against a writer holding `data` while waiting for `id_index`. `parking_lot` guards block
  the thread rather than yielding, so the cycle wedged the runtime. Both now take `data`
  before `id_index`, and `delete_by_id` holds both across the lookup, removal and index
  update so a concurrent writer cannot commit a new mapping for the id being deleted.
- **A conditional write could publish an identity taken from a stale read.** The Redis
  backend chose the record's `id` from a read that happened before its atomic script, and
  the script trusted it — including deleting whatever id the path happened to name at
  script time. A path replaced in that window had its live record deleted and its identity
  overwritten by one no longer current, so concurrent writers disagreed about the record a
  path resolved to. The script now carries the expected id as a second precondition, writes
  only while the mapping still names it, and signals the caller when it has moved so the
  payload is rebuilt from the identity that is current at the instant of the write.
- **Two concurrent file writes to one destination could collide on a temporary file.** The
  temporary file was named only after the destination (`<id>.json.tmp`), so two writers
  staging the same id shared one path: one renamed the other's bytes into place, or the
  publish failed because the file had already been moved away. Each write stages into its
  own uniquely named temporary file (`create_new`, so the kernel refuses a name that is
  taken) and publishes it with the atomic rename.
- **An expired initialization lease could never be taken over on PostgreSQL.** The
  owner-conditional replacement built `INSERT ... SELECT ... WHERE false ON CONFLICT ... DO
  UPDATE`; the insert arm can never produce a row, and an `ON CONFLICT` clause only fires
  when the insert actually conflicts, so the `DO UPDATE` arm was unreachable and replacing an
  existing row always affected zero rows. `SealService::acquire_init_lease` uses exactly this
  operation to take over a lease left behind by a dead process, so a PostgreSQL vault
  abandoned mid-initialization could never be recovered. It is now a single `UPDATE ... WHERE
  path = $1 AND metadata->>'storage_owner' = $11`, whose precondition and write are the same
  statement and which preserves the existing row's `id` and `created_at`; an absent path
  affects zero rows and fails closed.
- **Two replicas sharing a backend could both exchange one refresh token.** The single-use
  reservation that stops a refresh token being exchanged twice lived only in the process's
  in-memory token blacklist, so two instances behind a load balancer each saw an unused
  token and each minted a session — issuing two token pairs from one refresh. The
  reservation is now claimed atomically in the shared backend, at a path derived from the
  token's hash (never the token itself), with insert-if-absent before any fallible work; a
  failed exchange releases it owner-conditionally and a completed one leaves it as a
  permanent revocation. Backends that cannot coordinate across processes keep the in-memory
  reservation, which is their complete guarantee.
- **The refresh guard expired before a long-lived refresh token.** The reservation and the
  revocation that make a refresh token single-use were pinned to a fixed eight-day deadline,
  while the token's own lifetime comes from `auth.jwt.refresh_expiration`. An operator who
  configured more than eight days produced tokens that outlived both records, and a replay
  after the fixed window won the insert-if-absent race and was issued a fresh session — a
  reuse window that grew with the configured lifetime (CWE-613). Both deadlines are now
  derived from the token's own `exp`, so the guard lasts exactly as long as the token is
  valid and no longer; an already-invalid token cannot reach this path.
- **A transient storage failure during a refresh consumed the token.** When the shared
  reservation write failed, the reservation returned the error but left the in-memory slot it
  had just inserted, so every later attempt hit that slot and returned `InvalidToken` without
  retrying the recovered backend: a brief Redis or PostgreSQL blip logged the user out for
  the reservation's whole lifetime. The error path now releases the local slot exactly as the
  already-taken path does, so a retry after the fault succeeds while a genuine reuse is still
  refused.
- **The lifecycle sweep silently skipped expired secrets on the file backend.** The sweep
  asks storage to exclude reserved namespaces and orders by `expires_at` before applying its
  10,000-record cap. `FileBackend::list` honoured neither — its hand-rolled filter ignored
  `excluded_path_prefixes` and it had no `expires_at` sort — so the cap could be spent on
  `sys/` records and expired user secrets past the cutoff were never deleted. `list` and
  `count` now apply the full `QueryParams` contract before pagination.
- **A TLS connection could lose its `Secure` cookie and HSTS.** The middleware decided
  whether a request was secure from `request.uri().scheme_str()`, which is empty for an
  HTTP/1.1 request in origin-form — every browser request — so a process serving TLS
  classified its own connections as plain HTTP and emitted neither `Secure` nor HSTS. On
  HTTP/2 the scheme is a client-supplied `:scheme` pseudo-header, so the same read let a
  cleartext client forge `https`. The transport's TLS state is no longer read from the URI
  at all: an operator whose listener terminates TLS declares it with `http.https_only`, the
  only remaining source is a `X-Forwarded-Proto` from a trusted proxy, and a spoofed header
  from an untrusted client still turns nothing on.
- **`delete_by_path` on the file backend left the deleted secret readable.** It removed the
  first record its directory scan returned for a path, while `get_by_path` resolves the
  newest by `(updated_at, id)`; a rewrite under a fresh id left a superseded file that the
  after-delete read still resolved. Every record at the path is now removed under the same
  lock.
- **A committed Redis transaction was invisible by path and orphaned mappings on delete.**
  `RedisTransaction::commit` wrote only `secreton:entry:*`, never the `secreton:path:*`
  mapping that `get_by_path`, `exists`, `list` and `count` resolve through, so a record
  written in a transaction could not be read by path and a record deleted in one left a
  mapping pointing at a missing entry. Commit now writes, repoints and removes the mapping
  in the same server-side step as the body, and removes a mapping on delete only while it
  still names the deleted id.
- **The screenshot capture had a default password.** `SCREENSHOT_PASSWORD` fell back to a
  committed literal, so a run without the variable silently captured the signed-out views
  as if they were the authenticated ones. It now fails fast with a clear message; the CI
  workflow already sets the variable, generated per run.

### Removed

- `warp`. The process ran two HTTP stacks on two ports because warp is on hyper 0.14 and
  Axum on hyper 1.0; `cargo tree -i warp` now finds nothing and there is no duplicate axum.
- The root `tests/` tree (~30 files). The root manifest is a virtual workspace, so cargo
  never compiled any of it.
- Three orphan crates with no dependents (graphql, enterprise, infrastructure) and four
  stub-only ones (integrations, monitoring, performance, replication).
- 19 of 24 storage backends. Each was a 130–320 line sketch with no tests that returned
  `"Not implemented"` at runtime while being selectable from configuration.
- 8 of 12 authentication methods. None was reachable from a route; the Kubernetes one had
  never been compiled at all, and failed with thirty errors when its feature was enabled.
- All direct use of the `rsa` crate (RUSTSEC-2023-0071), which the manifest already
  claimed not to use. It remains in the tree transitively via `jsonwebtoken`'s provider;
  SECURITY.md documents why that code is unreachable, and a test pins it.
- `nginx/`, `Dockerfile.frontend`, `Trunk.toml`, the `cdn.tailwindcss.com` script, the
  second HTTP client in the WASM bundle, and the `+10` port offset.

### Added

- Leptos SSR with hydration, built by `cargo-leptos` into the same binary. Data flows
  through typed `#[server]` functions; the browser holds no token.
- gRPC on `tonic` 0.14 merged into the shared Axum router, with health checking,
  reflection, and the `AuthService::Login` the proto had always declared but never
  implemented.
- Configuration validated at startup: a missing or short JWT secret, a wildcard CORS
  origin, or a zero timeout stops the process rather than surfacing later.
- Property-based tests for the cryptographic primitives (AEAD round-trip, tamper
  detection, nonce reuse, Shamir quorum behaviour).
- `AGENTS.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CODEOWNERS`, issue and PR templates,
  and three ADRs recording the single-router, Leptos-SSR and gRPC decisions.
- Rebuilt CI: concurrency groups, a wasm guardrail job, a feature matrix, SHA-pinned
  third-party actions, and `--locked` everywhere. `Cargo.lock` is now committed.
- A single multi-stage `Dockerfile` producing a distroless, non-root image on one port.
- A root `package.json` pinning `playwright-core` for the screenshot capture. The tooling
  is opt-in and separate from the Rust build: `npm ci` installs the pinned dependency,
  `npm run browser:install` fetches the matching Chromium, and `npm run screenshots`
  captures. No `postinstall` hook reaches the network.

## [0.1.0] - 2026-05-20

Initial release.
