# Spesifikasi Teknis

**Versi:** 2.0
**Terakhir diperbarui:** 2026-09-21
**Status:** sesuai dengan kode di `main`

> Versi 1.0 dokumen ini mendeskripsikan 23 crate, framework Warp, dan port 8080. Tidak
> satupun dari itu ada di repositori ini. Dokumen ini ditulis ulang dari kode yang
> benar-benar dikompilasi; setiap angka di bawah dapat diverifikasi dengan perintah yang
> disebutkan.

---

## 1. Informasi Umum

### 1.1 Nama Aplikasi
Secreton

### 1.2 Deskripsi Singkat
Secrets management platform yang ditulis dengan Rust: aplikasi web
[Leptos](https://leptos.dev) dan API REST + gRPC, dilayani oleh **satu proses Axum pada
satu port**.

### 1.3 Versi Aplikasi
0.1.0 (pre-1.0, tahap awal). API dan skema penyimpanan dapat berubah tanpa jalur migrasi.

### 1.4 Lisensi
Apache-2.0

### 1.5 Toolchain
Rust 1.94.1, dikunci di `rust-toolchain.toml` bersama target
`wasm32-unknown-unknown`. Semua perintah build memakai `--locked`; `Cargo.lock` ada di
repositori.

---

## 2. Daftar Crate

Sepuluh crate, berlapis. Sebuah crate hanya boleh bergantung pada crate di atasnya dalam
tabel ini.

| No | Crate | Baris | Isi | Tidak boleh berisi |
|----|-------|------:|-----|--------------------|
| 1 | `secreton-domain` | 1.746 | Tipe bersama, satu `SecretonError`, envelope API | I/O, web framework — harus tetap kompilasi untuk `wasm32-unknown-unknown` |
| 2 | `secreton-crypto` | 7.877 | AEAD, KDF, signing, Shamir, transit engine, barrier penyimpanan | Storage, HTTP |
| 3 | `secreton-storage` | 4.422 | Satu trait `StorageBackend` | Logika bisnis |
| 4 | `secreton-auth` | 11.304 | Metode autentikasi, identity, MFA, token, policy engine, governance | HTTP, layer axum |
| 5 | `secreton-engines` | 21.148 | Secret engine, seal, audit, lifecycle, graph `Services` | HTTP — tanpa `axum`, tanpa `Request` |
| 6 | `secreton-ui` | 788 | Komponen, route, dan server function Leptos | Dependensi khusus server |
| 7 | `secreton-server` | 8.773 | Router Axum, handler, middleware, gRPC, binary | Logika bisnis — delegasikan ke `engines` |
| 8 | `secreton-client` | 354 | HTTP client bertipe di atas `/api/v1` | — |
| 9 | `secreton-cli` | 988 | Binary CLI di atas `client` | Akses storage langsung |
| 10 | `secreton-agent` | 1.884 | Binary agent (monitoring, health, templating) | Akses storage langsung |

Total sekitar 59.284 baris Rust di `crates/`.

---

## 3. Detail Crate

### 3.1 secreton-domain

**Lokasi:** `crates/domain/`

**Fungsi.** Kosakata bersama seluruh workspace: tipe error terpadu, envelope API, dan
value type yang disepakati crate lain.

**Batasan.** Crate ini sengaja **murni** — tanpa I/O, tanpa driver database, tanpa web
framework. Itulah yang membuatnya dapat dipakai oleh server Axum *dan* oleh UI Leptos yang
dikompilasi ke `wasm32-unknown-unknown`. Apa pun yang butuh socket, file handle, atau
runtime `tokio` berada di crate di atasnya.

**Public API:**
```rust
pub use api::{ApiResponse, PaginationParams, QueryParams};
pub use error::{Result, SecretonError};
pub use security::SecurityLevel;
pub use audit::AuditEvent;
pub enum ServiceHealth { Healthy, Degraded(String), Unhealthy(String) }
```

### 3.2 secreton-crypto

**Lokasi:** `crates/crypto/`

**Fungsi.** Primitif kriptografi dan protokol: AEAD (AES-256-GCM,
ChaCha20-Poly1305), KDF (Argon2id), hashing, signing (Ed25519, P-256/P-384), Shamir secret
sharing untuk alur unseal, transit engine (enkripsi sebagai layanan), dan barrier yang
dipakai storage untuk membungkus data.

**Batasan.** Tidak ada kunci RSA yang pernah dibuat atau diterima. `rsa` tetap ada di
dependency tree secara transitif melalui `jsonwebtoken`, tetapi tidak dapat dijangkau
karena validasi JWT hanya mengizinkan HS256; lihat [SECURITY.md](../../SECURITY.md) dan
test `only_hs256_tokens_are_accepted`.

**Testing.** Properti kriptografi diuji dengan property test di
`crates/crypto/tests/properties.rs`: AEAD round-trip, deteksi tampering, nonce reuse, dan
perilaku kuorum Shamir.

### 3.3 secreton-storage

**Lokasi:** `crates/storage/`

**Fungsi.** Satu trait `StorageBackend` dengan beberapa implementasi backend.

**Trait:**
```rust
pub trait StorageBackend: std::fmt::Debug + Send + Sync {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()>;
    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>>;
    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>>;
    async fn update(&self, entry: &SecretEntry) -> StorageResult<()>;
    async fn delete_by_path(&self, path: &str) -> StorageResult<bool>;
    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>>;
    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>>;
    async fn health_check(&self) -> StorageResult<HealthStatus>;
    // ...
}
```

**Backend yang tersedia:**

| Backend | Feature | Catatan |
|---------|---------|---------|
| `memory` | selalu aktif | Default; hilang saat restart |
| `file` | selalu aktif | Tanpa layanan eksternal |
| `postgres` | `postgres` (default) | Direkomendasikan |
| `redis` | `redis` (default) | |
| `raft` | `raft` (default) | **Eksperimental**: single-node saja |

`memory` dan `file` selalu aktif karena tidak memerlukan layanan eksternal, sehingga crate
dapat dipakai di test dan pada `cargo leptos serve` tanpa setup.

### 3.4 secreton-auth

**Lokasi:** `crates/auth/`

**Fungsi.** Metode autentikasi, identity, MFA, token, policy engine, dan governance.

**Metode autentikasi:** `method/userpass.rs`, `method/approle.rs`, `method/oidc.rs`.

**Policy.** Policy engine dengan grammar sendiri (`policies/policy_grammar.pest`),
evaluator, dan service.

**Token.** Siklus hidup token ada di `token/`: `core.rs`, `renewal.rs`, `revocation.rs`,
`service.rs`.

**MFA.** Modul `mfa/` mencakup delivery (SMS, email, push) dengan implementasi in-memory
untuk pengembangan. Ganti dengan provider nyata sebelum dipakai produksi.

**JWT.** Validasi memakai `Validation::new(Algorithm::HS256)`; allowlist ini yang menolak
setiap token RS*/PS* sebelum kunci dibentuk.

### 3.5 secreton-engines

**Lokasi:** `crates/engines/`

**Fungsi.** Logika bisnis platform. Tidak ada yang tahu soal HTTP di sini: setiap tipe
menerima dan mengembalikan nilai domain, sehingga service yang sama dapat mendukung
handler REST, method gRPC, dan server function Leptos tanpa layer penerjemah.

**Modul:** `audit_config`, `config`, `database`, `lifecycle`, `performance`, `pki`,
`services`, `ssh`, `telemetry`.

**Graph Services** (`services/mod.rs`) merangkai seluruh service dalam satu struct:
`config`, `storage`, `crypto`, `seal`, `audit`, `auth`, `policy`, `secret`, `admin`,
`database`, `pki`, `ssh`, `transit`, `totp_engine`, `performance`, `mfa`, `telemetry`,
`identity`, `lifecycle`.

**Feature.** `postgres` (default) dan `mysql` membatasi engine kredensial database dinamis.
Kedua feature ini sebelumnya muncul di atribut `#[cfg(feature = ...)]` tanpa pernah
dideklarasikan, sehingga seluruh jalur kode dikompilasi keluar dan endpoint menjawab
"feature disabled" di setiap build. Sekarang keduanya terdeklarasi dan memiliki integration
test yang terhubung ke server nyata.

### 3.6 secreton-ui

**Lokasi:** `crates/ui/`

**Fungsi.** Aplikasi Leptos 0.8. Satu crate dengan `crate-type = ["cdylib", "rlib"]` dan
feature `ssr`/`hydrate`, bukan tiga crate terpisah seperti template workspace resmi.

**Batasan.** Tidak boleh ada dependensi khusus server. Guardrail-nya adalah CI job:
```bash
cargo check -p secreton-ui --locked --target wasm32-unknown-unknown \
    --no-default-features --features hydrate
```
Perintah ini gagal jika dependensi khusus server bocor ke dalam UI.

### 3.7 secreton-server

**Lokasi:** `crates/server/`

**Fungsi.** Satu `axum::Router` yang melayani aplikasi Leptos, `/api/v1`, aset statis,
health, metrics, dan — di balik feature `grpc` — gRPC, semuanya pada satu listener.

**Feature.** `default = ["grpc", "ui"]`. Feature `ssr` forwards ke `ui`, karena
cargo-leptos mencari nama itu.

**Otoritas.** Handler hanya menerjemahkan HTTP; logika bisnis didelegasikan ke `engines`.

---

## 4. Tech Stack

### 4.1 Bahasa
| Bahasa | Versi | Penggunaan |
|--------|-------|------------|
| Rust | 1.94.1 (dikunci) | Seluruh logika aplikasi, kriptografi, server |

### 4.2 Framework & Library
| Nama | Versi | Fungsi |
|------|-------|--------|
| Tokio | — | Async runtime |
| Axum | — | Satu-satunya web framework, satu listener |
| Leptos | 0.8 | UI, SSR + hydration |
| `leptos_axum` | 0.8 | Integrasi Leptos dengan Axum |
| `tonic` | 0.14 | gRPC, digabung ke router Axum yang sama |
| Serde | — | Serialisasi/deserialisasi |
| Zeroize | — | Zeroing memori untuk data sensitif |

Warp sudah dihapus. Repositori ini sebelumnya menjalankan dua stack HTTP di dua port karena
warp memakai hyper 0.14 sementara Axum memakai hyper 1.0. `cargo tree -i warp` sekarang
tidak menemukan apa pun.

### 4.3 Build Tools
| Tool | Fungsi |
|------|--------|
| Cargo | Package manager dan build tool |
| `cargo-leptos` | Build server + WASM + Tailwind dalam satu proses |
| Docker | Containerization |

---

## 5. Struktur Proyek

```
secreton/
├── Cargo.toml              # Virtual workspace manifest
├── Cargo.lock              # Committed; semua perintah memakai --locked
├── rust-toolchain.toml     # Rust 1.94.1 + wasm32-unknown-unknown
├── secreton.toml           # Konfigurasi default (http, cors, auth, audit, storage, ...)
├── compose.yaml            # Server + PostgreSQL 17
├── Dockerfile              # Multi-stage, distroless, non-root, satu port
├── AGENTS.md               # Referensi kerja: layout, perintah, invariant
├── crates/                 # 10 crate anggota workspace
│   ├── domain/  crypto/  storage/  auth/  engines/
│   └── ui/  server/  client/  cli/  agent/
├── docs/
│   ├── adr/                # Architecture Decision Records
│   ├── architecture/       # Dokumen ini
│   └── screenshots/        # Tangkapan layar UI, dihasilkan oleh skrip
├── monitoring/             # prometheus.yml
├── scripts/                # generate_certs.sh, screenshots.mjs
└── .github/workflows/      # ci, security, codeql, pr-validation
```

Tidak ada direktori `tests/` di root. Root manifest adalah virtual workspace, sehingga
cargo tidak pernah mengompilasi test di sana; test terintegrasi berada di `tests/` milik
masing-masing crate.

---

## 6. Konfigurasi

### 6.1 Presedensi
`default < secreton.toml < environment` (`SECRETON__SECTION__KEY`).

### 6.2 File
| File | Fungsi |
|------|--------|
| `secreton.toml` | Konfigurasi yang dimaksudkan untuk di-commit; rahasia tidak di sini |
| `.env` | Rahasia lokal (gitignored), dicopy dari `.env.example` |
| `monitoring/prometheus.yml` | Konfigurasi scraping |

### 6.3 Environment Variables

| Variable | Deskripsi | Default |
|----------|-----------|---------|
| `SECRETON__AUTH__JWT__SECRET` | Signing secret JWT, minimum 32 byte. **Wajib** | — |
| `SECRETON__HTTP__BIND_ADDRESS` | Alamat bind | `127.0.0.1:3000` |
| `SECRETON__HTTP__TRUSTED_PROXIES` | Jumlah reverse proxy di depan proses | `0` |
| `SECRETON__STORAGE__BACKEND_TYPE` | `memory`/`file`/`postgres`/`redis`/`raft` | `memory` |
| `SECRETON_CONFIG` | Path file konfigurasi | `secreton.toml` |
| `SECRETON_BIND` | Override alamat bind | — |
| `SECRETON_LOG_JSON` | Log sebagai JSON | — |
| `RUST_LOG` | Level logging | `info` |

Tidak seperti versi 1.0 dokumen ini, tidak ada `SECRETON_SERVER__HOST`,
`SECRETON_DATABASE__URL`, atau `REDIS_URL`.

### 6.4 Validasi Startup
Konfigurasi divalidasi sebelum apa pun dijalankan. Secret JWT yang hilang atau terlalu
pendek, origin CORS wildcard, atau timeout nol **menghentikan proses**. Secret JWT tidak
pernah dibuat otomatis: secret yang dikarang saat boot membatalkan setiap token yang sudah
diterbitkan pada restart berikutnya.

---

## 7. Build & Run

### 7.1 Prasyarat
- Rust 1.94.1 (rustup akan memasangnya dari `rust-toolchain.toml`)
- `cargo-leptos`
- PostgreSQL 17 (opsional; hanya jika tidak memakai storage `memory`)

### 7.2 Build
```bash
cargo build --workspace --locked
cargo build --workspace --locked --release
```

### 7.3 Menjalankan
```bash
# UI, REST API dan gRPC pada satu port (3000)
cargo leptos serve

# Docker
docker compose up --build
```

Saat pertama kali dijalankan, instance dalam keadaan sealed dan tidak punya akun. Alur
inisialisasi (generate share, unseal, root token, buat user) ada di
[README](../../README.md#quick-start) dan diverifikasi terhadap server yang berjalan.

### 7.4 Endpoint
| Layanan | URL |
|---------|-----|
| UI | `http://localhost:3000/` |
| REST API | `http://localhost:3000/api/v1` |
| OpenAPI | `http://localhost:3000/api-docs/openapi.json` |
| Liveness | `http://localhost:3000/health` |
| Readiness | `http://localhost:3000/health/ready` |
| gRPC | h2c pada port yang sama |

Tidak ada Swagger UI bawaan: `utoipa-swagger-ui` menarik zip melalui jaringan saat compile,
yang melanggar syarat build hermetik. Dokumen OpenAPI disajikan sebagai JSON.

---

## 8. Testing

```bash
cargo test --workspace --locked
```

- Test unit berada di samping kode dalam `#[cfg(test)]`.
- Test integrasi berada di `tests/` milik crate terkait.
- Tidak ada network test: endpoint yang tidak dapat dijangkau memakai `192.0.2.1`
  (RFC 5737).
- Test diberi nama menurut properti, bukan fungsi:
  `rolled_back_transaction_writes_are_discarded`, bukan `test_transaction`.

Test integrasi PostgreSQL dan MySQL untuk engine kredensial database terhubung ke server
nyata, memverifikasi akun benar-benar ada setelah di-issue, dapat diautentikasi, membawa
grant dari role, dan hilang setelah di-revoke.
