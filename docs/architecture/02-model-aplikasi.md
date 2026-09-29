# Model Aplikasi

**Versi:** 2.0
**Terakhir diperbarui:** 2026-09-21
**Referensi:** [01-spesifikasi-teknis.md](01-spesifikasi-teknis.md)
**Status:** sesuai dengan kode di `main`

> Versi 1.0 dokumen ini menggambarkan tumpukan Nginx + PostgreSQL + Redis + Prometheus +
> Grafana, API GraphQL, WebSocket, dan integrasi AWS/GCP/Kubernetes/LDAP/RADIUS — tidak ada
> satupun yang diimplementasikan. Dokumen ini menjelaskan aplikasi yang sebenarnya ada.

---

## 1. Overview

### 1.1 Tujuan
Menjelaskan keterhubungan aplikasi dengan klien, layanan pendukung, data yang dihasilkan,
dan penerapan keamanannya.

### 1.2 Ruang Lingkup
Secreton sebagai satu proses yang menyajikan UI, REST API, dan gRPC pada satu port, dengan
storage yang dapat dikonfigurasi di belakang satu trait.

---

## 2. Keterhubungan dengan Layanan

### 2.1 Diagram Konteks

```
┌───────────────────────────────────────────────────────────────┐
│                          Klien                                │
│  ┌────────────┐  ┌────────────┐  ┌──────────┐  ┌───────────┐  │
│  │  Browser   │  │    CLI     │  │  Agent   │  │ Layanan   │  │
│  │            │  │            │  │          │  │ lain      │  │
│  │ cookie     │  │ Bearer     │  │ Bearer   │  │ Bearer    │  │
│  │ HttpOnly   │  │ token      │  │ token    │  │ token     │  │
│  └──────┬─────┘  └──────┬─────┘  └────┬─────┘  └─────┬─────┘  │
└─────────┼───────────────┼─────────────┼──────────────┼────────┘
          │               │             │              │
          └───────────────┴──────┬──────┴──────────────┘
                                 │  HTTP/1.1, HTTP/2 (h2c)
                                 ▼
┌───────────────────────────────────────────────────────────────┐
│                  Proses Secreton (satu port)                  │
│                                                               │
│  Router Axum tunggal                                          │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ middleware: request_id → security_headers → rate_limit  │  │
│  │             → cors → timeout → body_limit → compression │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ UI Leptos  │  │ REST /api/v1 │  │ gRPC (h2c, port sama)│   │
│  │ SSR+hydrate│  │              │  │ + health + reflection│   │
│  └─────┬──────┘  └──────┬───────┘  └──────────┬───────────┘   │
│        └────────────────┴─────────────────────┘               │
│                         ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  secreton-engines — logika bisnis, tanpa HTTP           │  │
│  │  seal · audit · secret · transit · pki · ssh · totp     │  │
│  │  database · policy · lifecycle · identity · mfa         │  │
│  └────────────────────────┬────────────────────────────────┘  │
│                           ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  crypto (barrier, AEAD)  ·  StorageBackend trait        │  │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────┬───────────────────────────────────┘
                            ▼
        ┌───────────────────────────────────────────┐
        │  Backend penyimpanan (pilih satu)         │
        │  memory · file · PostgreSQL · Redis · Raft│
        └───────────────────────────────────────────┘
```

### 2.2 Antarmuka yang Dilayani

| Antarmuka | Alamat | Status |
|-----------|--------|--------|
| Web UI | `http://localhost:3000/` | Ada |
| REST API | `http://localhost:3000/api/v1` | Ada |
| OpenAPI (JSON) | `http://localhost:3000/api-docs/openapi.json` | Ada |
| Liveness | `http://localhost:3000/health` | Ada |
| Readiness | `http://localhost:3000/health/ready` | Ada |
| Metrics | `http://localhost:3000/metrics` | Ada |
| gRPC | h2c pada port yang sama | Ada (`grpc` feature, default aktif) |
| CLI | `secreton-cli` | Ada |
| Agent | `secreton-agent` | Ada |

Tidak ada GraphQL, tidak ada WebSocket, tidak ada listener kedua, dan tidak ada port offset
`+10` seperti pada versi sebelumnya.

### 2.3 Integrasi Eksternal

| Sistem | Tipe | Catatan |
|--------|------|---------|
| PostgreSQL | Storage backend | Opsional; `memory` adalah default |
| Redis | Storage backend | Opsional |
| PostgreSQL / MySQL | Target engine kredensial database dinamis | Membuat akun nyata dan menghapusnya saat revoke |
| OIDC provider | Autentikasi manusia (SSO) | `method/oidc.rs` |
| Prometheus | Scrape `/metrics` | `monitoring/prometheus.yml` |

Yang **tidak** terintegrasi: AWS IAM/STS, GCP, Kubernetes, LDAP, Active Directory, RADIUS,
Grafana, SIEM.

---

## 3. Data yang Dihasilkan

### 3.1 Kategori

| Kategori | Deskripsi | Sensitivitas |
|----------|-----------|--------------|
| Secrets | Data sensitif terenkripsi, versi KV v2 | Tinggi |
| Kredensial dinamis | Akun yang dibuat di database target | Tinggi |
| Token & sesi | Token JWT, sesi browser | Tinggi |
| Audit log | Jejak peristiwa keamanan | Sedang |
| Konfigurasi | Pengaturan sistem | Sedang |
| Metrics & telemetry | Data performa | Rendah |

### 3.2 Aliran Data

```
Permintaan klien
      │
      ▼
[midware: request_id, security headers, rate limit, cors, timeout, body limit]
      │
      ▼
[gerbang seal]  ─── sealed ──▶ 503, "unseal dulu"
      │ terbuka
      ▼
[gerbang auth]  ─── tanpa kredensial ──▶ 401
      │ terautentikasi
      ▼
[handler] ──▶ [secreton-engines] ──▶ [barrier enkripsi] ──▶ [StorageBackend]
      │                  │
      │                  └──▶ [audit: setiap baca, tulis, hapus — termasuk jalur penolakan]
      ▼
Respons (envelope API)
```

### 3.3 Envelope API

Semua respons REST memakai satu envelope:

```json
{ "success": true,  "data": { }, "metadata": { } }
{ "success": false, "error": "…", "metadata": { "category": "authentication" } }
```

Bentuk ini dibagi `secreton-domain`, sehingga UI Leptos dan handler Axum tidak dapat
menyimpang satu sama lain — perbedaan tipe adalah compile error.

### 3.4 Aturan Penulisan Data

| Aturan | Implementasi |
|--------|--------------|
| Audit sebelum kembali | Setiap handler yang membaca, menulis, atau menghapus secret memancarkan `AuditEvent`, termasuk pada jalur penolakan |
| Rahasia di-zeroize | Material kunci dan plaintext di-zero saat drop, dan tidak pernah muncul di `Debug`, log, atau pesan error |
| Body 5xx tidak berkata apa pun | Error internal mengembalikan string tetap; detail masuk log, dikorelasikan oleh `x-request-id` |

---

## 4. Model Infrastruktur yang Didukung

### 4.1 Komponen

| Komponen | Teknologi | Wajib? |
|----------|-----------|--------|
| Application server | Rust 1.94.1 + Axum | Ya |
| UI | Leptos 0.8 (SSR + hydration) | Ya (`ui` feature) |
| gRPC | `tonic` 0.14 di router yang sama | Tidak (`grpc` feature) |
| Storage | `memory`/`file` | Salah satu dari ini cukup untuk menjalankan |
| Database | PostgreSQL 17 | Opsional |
| Cache/backend | Redis | Opsional |
| Metrics | Prometheus (scrape `/metrics`) | Opsional |

### 4.2 Topologi yang Diuji

```
docker compose up --build
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  compose.yaml (network internal)                    │
│                                                     │
│  ┌───────────────────────┐     ┌─────────────────┐  │
│  │ secreton              │     │ postgres:17     │  │
│  │ port 3000 dipublikasi │────▶│ hanya dari      │  │
│  │ read_only: true       │     │ jaringan compose│  │
│  │ cap_drop: [ALL]       │     │ (tidak ke host) │  │
│  └───────────────────────┘     └─────────────────┘  │
└─────────────────────────────────────────────────────┘
```

Hanya port aplikasi yang dipublikasikan ke host. Versi sebelumnya mengekspos 5432, 6379,
3000, dan 9090.

### 4.3 Deployment

`cargo leptos serve` menjalankan server, build WASM, dan Tailwind dalam satu proses. Image
Docker adalah multi-stage, distroless, non-root, dan mengekspos satu port (3000). Tidak ada
Nginx, tidak ada reverse proxy bawaan, tidak ada Dockerfile.frontend.

Jika ada reverse proxy di depan proses, set `SECRETON__HTTP__TRUSTED_PROXIES` sesuai jumlah
proxy nyata. Salah set terlalu tinggi memungkinkan klien memalsukan alamatnya dengan
menambahkan entri `X-Forwarded-For`, yang melemahkan rate limiting per klien.

---

## 5. Penerapan Keamanan

### 5.1 Autentikasi

| Metode | Untuk | Lokasi |
|--------|-------|--------|
| Username/password | Manusia | `auth/src/method/userpass.rs` |
| AppRole | Machine-to-machine | `auth/src/method/approle.rs` |
| OIDC | SSO manusia | `auth/src/method/oidc.rs` |
| MFA | Faktor kedua | `auth/src/mfa/` |

**Sesi browser adalah cookie**, bukan token di `localStorage`. Cookie bersifat
`httpOnly`, `Secure`, `SameSite=Lax`, sehingga skrip yang disuntikkan tidak dapat
membacanya. Klien programatik (CLI, agent, layanan lain) memakai
`Authorization: Bearer`.

### 5.2 Otorisasi

| Model | Implementasi |
|-------|--------------|
| RBAC | Role dan permission per user |
| Policy as code | Policy engine dengan grammar sendiri (`policy_grammar.pest`) |
| Token hierarchy | `token/core.rs`, `token/service.rs` |
| Renewal | `token/renewal.rs` |
| Revocation granular | `token/revocation.rs` |

### 5.3 Kriptografi

| Tipe | Algoritma |
|------|-----------|
| Data at rest | AES-256-GCM, ChaCha20-Poly1305 |
| Password hashing | Argon2id |
| Signing | Ed25519, P-256/P-384 |
| Unseal | Shamir secret sharing |
| RSA | **Tidak ada kunci RSA yang dibuat atau diterima** |

Root key hasil rekonstruksi hanya hidup di memori. Jika penerbitan token root gagal setelah
barrier terbuka, ulangi panggilan `unseal` dengan share yang benar: retry hanya menerbitkan
kredensial bila membuktikan kepemilikan share — `sys/unseal` adalah route publik, jadi flag
"pending" saja tidak boleh pernah cukup. Setelah restart, root key hilang dan vault harus
di-unseal kembali dengan share-nya (`crates/engines/src/services/seal.rs`).

Pesan kegagalan penerbitan itu tidak membawa detail internal. Jalur kegagalannya adalah
storage atau token service, dan teks errornya dapat memuat connection string, host, atau path
file; karena `sys/unseal` dapat dipanggil sebelum autentikasi, caller hanya menerima pesan
generik yang tetap memberi tahu bahwa vault terbuka dan cara memulihkan kredensial. Detail
lengkapnya masuk ke log dan ke record audit, bukan ke body respons.

Kredensial bootstrap tidak melewati pemeriksaan TOTP, dan itu memang disengaja. Root tidak
punya login password (`password_login_disabled` tersimpan di record-nya), sehingga satu-satunya
cara memperoleh kredensial root adalah merekonstruksi root key dari sejumlah share Shamir —
key material yang dipegang operator secara fisik, faktor yang lebih kuat daripada kode TOTP
yang dibangkitkan dari secret yang disimpan server itu sendiri. Token yang keluar membawa
`mfa_required: false` sehingga `enforce_mfa_pending` tidak membatasinya; enrollment TOTP tetap
dibuat dan `root_totp_uri` dikembalikan `init` supaya operator dapat memasang authenticator,
tetapi faktor yang menerbitkan kredensial bootstrap adalah bukti share, bukan kode TOTP.

`init` juga bertahap: state parsial di bawah `sys/init_staging` membuat vault tetap
terlihat belum terinisialisasi sampai semua artefak init tersimpan, dan kegagalan di
tengah jalan dibersihkan sehingga `init` berikutnya berhasil tanpa restart.

### 5.4 Header Keamanan

Diterapkan oleh middleware `security_headers` pada setiap respons. Detailnya ada di
`crates/server/src/middleware/security_headers.rs`. Policy CSP dibangun oleh middleware
tersebut, bukan diserahkan ke handler: hanya dokumen HTML yang membawa nonce milik renderer
(yang dikembalikan lewat header internal) yang mendapat policy bernonce; respons lain
ditimpa dengan `csp_without_nonce()` sehingga handler tidak dapat melemahkan policy.
Directive `frame-ancestors`, `object-src`, `base-uri`, dan `form-action` selalu ada.
Middleware juga menyelesaikan skema efektif permintaan dan menerbitkannya sebagai
`ResolvedScheme`; keputusan HSTS dan atribut `Secure` cookie membaca hasil yang sama.
Skema tidak pernah dibaca dari URI permintaan: `request.uri().scheme_str()` kosong untuk
request HTTP/1.1 origin-form (setiap request browser), sehingga koneksi TLS langsung akan
dinilai sebagai HTTP polos dan kehilangan `Secure` serta HSTS, sementara pada HTTP/2 skema
itu pseudo-header `:scheme` yang dapat dipalsukan klien. Operator mendeklarasikan listener
TLS-nya lewat `http.https_only`; selain itu hanya `X-Forwarded-Proto` dari proxy tepercaya
(`http.trusted_proxies`) yang dipertimbangkan, sehingga header palsu dari klien langsung
tidak menyalakan apa pun.

### 5.5 Audit

`AuditLogger` menerima `AuditEvent` dari setiap operasi yang menyentuh secret, termasuk
penolakan. Retensi diatur di `secreton.toml` (`[audit] retention_days`, default 2555 = 7
tahun), dengan `max_batch_size` untuk penulisan batch.

### 5.6 Batasan yang Diketahui

Didokumentasikan alih-alih disembunyikan:

- Backend Raft bersifat single-node dan eksperimental: tanpa perubahan keanggotaan
  cluster, tanpa pemilihan leader antar proses.
- Layanan pengiriman MFA (SMS, email, push) memakai implementasi in-memory untuk
  pengembangan.
- Identity store bersifat in-memory secara default.
- Secreton pra-1.0 dan belum layak untuk produksi.
