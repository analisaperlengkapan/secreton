# Model Infrastruktur

**Versi:** 2.0
**Terakhir diperbarui:** 2026-09-21
**Referensi:** [01-spesifikasi-teknis.md](01-spesifikasi-teknis.md), [02-model-aplikasi.md](02-model-aplikasi.md)
**Status:** sesuai dengan kode di `main`

> Versi 1.0 dokumen ini menggambarkan tumpukan Nginx di depan proses, Grafana, delapan port
> berbeda, dan aturan firewall antara layanan-layanan yang tidak ada. Dokumen ini
> menggantikannya dengan infrastruktur yang benar-benar dijalankan dan diuji.

---

## 1. Prinsip

Tiga hal membentuk seluruh model infrastruktur:

1. **Satu proses, satu port.** UI, REST API, dan gRPC dilayani oleh satu `axum::Router`
   pada port 3000. Tidak ada listener kedua, tidak ada reverse proxy bawaan, tidak ada
   offset port.
2. **Tanpa build-time network access.** Build script tidak boleh mengunduh apa pun. Ini
   alasan `utoipa-swagger-ui` tidak menjadi dependensi dan `protoc` di-vendor.
3. **Konfigurasi divalidasi saat startup.** Setting yang hilang atau salah format
   menghentikan proses, bukan muncul belakangan di request pertama pengguna.

---

## 2. Compute

### 2.1 Containerization

| Aspek | Detail |
|-------|--------|
| Base build | `rust:1.94.1-slim-bookworm` |
| Runtime | distroless, non-root (`uid 65532`) |
| Build | Multi-stage dengan `cargo-chef` + `cargo-leptos` |
| Alamat bind | `0.0.0.0:3000` (`SECRETON__HTTP__BIND_ADDRESS`) |
| User | `nonroot:nonroot`, dinyatakan eksplisit |
| HEALTHCHECK | Tidak ada — distroless tidak punya shell maupun curl; probe langsung ke `/health` |

Catatan penting dari Dockerfile: environment `LEPTOS_SITE_ADDR` dibaca oleh template server
bawaan cargo-leptos, **bukan** oleh binary ini. Dengan hanya variabel itu yang diset,
proses bind ke `127.0.0.1:8080` — tidak dapat dijangkau dari luar container, pada port yang
tidak disebut `EXPOSE`. Variabel yang benar-benar dibaca server adalah
`SECRETON__HTTP__BIND_ADDRESS`.

### 2.2 Spesifikasi Server

| Komponen | Minimum | Direkomendasikan |
|----------|---------|------------------|
| CPU | 1 core | 2+ core |
| Memori | 512 MB | 2 GB |
| Storage | 1 GB | 10 GB+ (jika memakai PostgreSQL) |
| Jaringan | 10 Mbps | 100 Mbps+ |

Storage `memory` dan `file` tidak memerlukan layanan eksternal, jadi instance dapat berjalan
tanpa database sama sekali.

### 2.3 Orkestrasi yang Diuji

```
compose.yaml
┌──────────────────────────────────────────────────────┐
│  network internal compose                            │
│                                                      │
│  ┌────────────────────────────┐   ┌───────────────┐  │
│  │ secreton                   │   │ postgres:17   │  │
│  │ build: Dockerfile          │   │ -alpine       │  │
│  │ ports: 3000:3000           │──▶│               │  │
│  │ read_only: true            │   │ healthcheck   │  │
│  │ cap_drop: [ALL]            │   │ pg_isready    │  │
│  │ no-new-privileges:true     │   │               │  │
│  │ volume: secreton.toml (ro) │   │ volume: data  │  │
│  └────────────────────────────┘   └───────────────┘  │
│           ▲                                          │
└───────────┼──────────────────────────────────────────┘
            │ hanya port 3000 yang dipublikasikan ke host
        host 3000
```

`SECRETON__AUTH__JWT__SECRET` dan `POSTGRES_PASSWORD` bersifat wajib dan diambil dari `.env`
(`:?` pada compose membuat proses gagal jika tidak diset). `SECRETON__HTTP__TRUSTED_PROXIES`
diset `"0"` karena compose tidak menempatkan proxy di depan aplikasi.

---

## 3. Jaringan

### 3.1 Topologi

```
Klien (browser / CLI / agent / layanan lain)
   │
   │  HTTP/1.1 atau HTTP/2 (h2c untuk gRPC)
   ▼
┌──────────────────────────────────────────────┐
│  Proses Secreton : 3000                     │
│                                              │
│  → GET /              UI Leptos (SSR+hydrate)│
│  → /api/v1/**         REST API               │
│  → /api-docs/openapi.json                    │
│  → /health, /health/ready, /metrics          │
│  → gRPC (h2c, direktori yang sama)           │
└───────────────┬──────────────────────────────┘
                │ hanya jika backend eksternal dipilih
                ▼
      ┌──────────────────────┐
      │ PostgreSQL / Redis   │
      │ (jaringan internal)  │
      └──────────────────────┘
```

Tidak ada Nginx, tidak ada TLS termination di dalam proses (konfigurasi `[tls]` ada tetapi
opsional), tidak ada port 8080, 8443, 5432 (dipublikasikan), 6379 (dipublikasikan), 9090,
9091, 80, atau 443 dalam konfigurasi bawaan.

### 3.2 Port

| Layanan | Port | Protokol | Arah | Keterangan |
|---------|------|----------|-------|------------|
| Secreton (UI + REST + gRPC + metrics) | 3000 | TCP | Inbound | Satu-satunya port yang dipublikasikan |
| PostgreSQL | 5432 | TCP | Internal (compose) | Hanya jika backend postgres dipilih |
| Redis | 6379 | TCP | Internal | Hanya jika backend redis dipilih |

### 3.3 Protokol

| Protokol | Versi | Penggunaan |
|----------|-------|------------|
| HTTP | 1.1 | REST API dan UI |
| HTTP/2 (h2c) | 2 | gRPC pada port yang sama |
| TCP | — | Koneksi PostgreSQL dan Redis |

Tidak ada WebSocket, tidak ada GraphQL, tidak ada UDP.

### 3.4 Alamat Klien dan Rate Limiting

Alamat klien diambil dari entri `X-Forwarded-For` ke-N dihitung dari kanan, di mana N adalah
`SECRETON__HTTP__TRUSTED_PROXIES`. Nilai nol berarti header diabaikan sepenuhnya dan alamat
peer socket yang dipakai — benar ketika proses diekspos langsung. Menyetel N lebih tinggi
daripada jumlah proxy nyata memungkinkan klien memalsukan alamatnya dengan menyisipkan
entri di depan, yang melemahkan rate limiting per klien.

### 3.5 DNS

Tidak ada catatan DNS yang diasumsikan oleh aplikasi. `secreton.local`,
`api.secreton.local`, `db.secreton.local`, dan `monitor.secreton.local` dari versi 1.0
tidak ada dalam kode maupun konfigurasi.

---

## 4. Keamanan Infrastruktur

### 4.1 Isolasi Container

| Kontrol | Nilai |
|---------|-------|
| User | `nonroot:nonroot` (uid 65532) |
| Filesystem | `read_only: true` |
| Capabilities | `cap_drop: [ALL]` |
| Privilege escalation | `no-new-privileges:true` |
| Port dipublikasikan | Hanya 3000 |
| Network database | Tidak dipublikasikan ke host |

### 4.2 Header Keamanan

Diterapkan oleh middleware `security_headers` pada setiap respons, bukan oleh reverse proxy.
Karena tidak ada Nginx dalam deployment bawaannya, header ini harus datang dari proses itu
sendiri. Header yang selalu ada mencakup `X-Frame-Options`, `X-Content-Type-Options`,
`Content-Security-Policy`, `Referrer-Policy`, dan `Permissions-Policy`; HSTS hanya
diterbitkan ketika skema efektif permintaan tervalidasi sebagai HTTPS. Skema tidak dibaca
dari URI permintaan — URI origin-form tidak membawa skema, dan pada HTTP/2 skema adalah
pseudo-header yang dapat dipalsukan klien. Sumbernya adalah deklarasi operator
`http.https_only` untuk listener yang men-terminate TLS, atau `X-Forwarded-Proto` yang
datang dari proxy tepercaya (`http.trusted_proxies`); header itu dari klien langsung
diabaikan.

### 4.3 Alur Autentikasi

```
Permintaan klien
      │
      ▼
[request_id]  ──▶ id unik ditempelkan ke setiap respons, termasuk 429
      │
      ▼
[security_headers]
      │
      ▼
[rate_limit]  ──▶ 429 jika kuota terlampaui (600 permintaan / 60 detik secara default)
      │
      ▼
[cors]  ──▶ allowlist; daftar kosong berarti same-origin saja
      │
      ▼
[gerbang seal]  ──▶ 503 jika barrier tertutup, dengan pesan yang bisa ditindaklanjuti
      │
      ▼
[gerbang auth]  ──▶ 401 tanpa kredensial
      │
      ▼
[handler] ──▶ [audit] ──▶ Respons
```

Urutan ini penting: `request_id` adalah layer terluar sehingga permintaan yang ditolak rate
limiting tetap punya id yang mengaitkan 429 dengan baris log.

### 4.4 TLS

Konfigurasi `[tls]` bersifat opsional. Jika tidak diset, proses melayani HTTP polos dan
terminasi TLS diharapkan dilakukan oleh komponen di depannya. Tidak ada sertifikat yang
dibuat otomatis.

### 4.5 Enkripsi Data

| Data | Perlakuan |
|------|-----------|
| Secrets | Dibungkus barrier AES-256-GCM sebelum mencapai backend |
| Password | Hash Argon2id |
| Sesi | JWT HS256, dikirim sebagai cookie `httpOnly` `Secure` `SameSite=Lax` |
| Kunci | Material kunci di-zeroize saat drop |

### 4.6 Monitoring

Prometheus menarik `/metrics` dari proses yang sama:
`secreton_sealed`, `secreton_secrets_total`, `secreton_uptime_seconds`. Tidak ada
`/metrics` pada port terpisah, dan PostgreSQL maupun Redis tidak diekspos sebagai target
Prometheus — keduanya tidak menyediakan endpoint Prometheus.

---

## 5. CI/CD

Lima workflow di `.github/workflows/`:

| Workflow | Isi |
|----------|-----|
| `ci.yml` | Job: fmt, clippy, test (dengan service PostgreSQL), WASM + Leptos build, feature matrix, MSRV, docs, docker build, lalu job `CI` agregat yang gagal jika ada job gagal atau dibatalkan |
| `security.yml` | Audit dependensi (`cargo-audit`, `cargo-deny`), pemindaian rahasia (gitleaks), dan pemindaian filesystem Trivy |
| `codeql-analysis.yml` | Analisis CodeQL |
| `pr-validation.yml` | Validasi pull request |
| `screenshots.yml` | Satu-satunya pemeriksaan yang mengeksekusi frontend yang dirender: membangun server + wasm, menjalankannya, membuat akun, lalu menjalankan `npm run screenshots` untuk menangkap dan memverifikasi keenam view |

`npm run screenshots:check` bukan pengujian frontend: perintah itu hanya preflight yang
membuktikan `playwright-core` dapat di-resolve dan Chromium dapat diluncurkan. Gate
frontend yang sebenarnya adalah langkah `npm run screenshots` di `screenshots.yml`, yang
berjalan setelah server dibangun dan siap. Job ini tidak pernah meng-commit PNG; ia
meng-upload `docs/screenshots/` sebagai artefak dan hanya memperingatkan saat gambar
berubah, karena dashboard memuat jumlah rahasia langsung.

Semua perintah cargo memakai `--locked`, sehingga `Cargo.lock` yang di-commit
mendeskripsikan artefak yang benar-benar dikirim.
