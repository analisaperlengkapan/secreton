# Secreton Agent

**Secreton Agent** adalah binary pendamping (sidecar) untuk server Secreton. Ia memantau
kesehatan sistem, menyajikan metrics untuk di-scrape, dan merender template konfigurasi
dari secret yang diambil dari server.

> **Status: sebagian belum lengkap.** Dokumen ini menuliskan dengan jelas apa yang sudah
> bekerja dan apa yang belum, karena versi sebelumnya dari file ini menjanjikan fitur yang
> tidak ada di kode (auto-auth AppRole/Kubernetes/AWS, sink token, process supervisor, dan
> format konfigurasi YAML). Jangan mengandalkan yang belum ada.

## Fitur

| Fitur | Status | Lokasi |
|-------|--------|--------|
| Health checking periodik terhadap server | Ada | `src/health.rs` |
| Metrics dan endpoint Prometheus | Ada | `src/metrics.rs` |
| Rendering template Handlebars dari secret | Ada (terbatas) | `src/templating.rs` |
| Renewal token di background | Ada | `src/auth.rs` |
| Auto-auth (AppRole, Kubernetes, AWS IAM, Azure MSI) | **Tidak ada** | — |
| Sink token ke file | **Tidak ada** | — |
| Process supervisor (exec aplikasi utama) | **Tidak ada** | — |
| Template `{{ with secret ... }}` gaya Consul/Vault | **Tidak ada** — memakai sintaks Handlebars | — |

## Cara Kerja

1. **Startup** — agent memuat konfigurasi (file TOML, lalu environment, lalu default).
2. **Auth** — jika `vault` dikonfigurasi, agent memuat token dari konfigurasi, file, atau
   environment, lalu menjalankan loop renewal setiap 300 detik.
3. **Health** — pemeriksaan kesehatan periodik terhadap server Secreton.
4. **Metrics** — metrics disajikan pada port Prometheus yang dikonfigurasi.
5. **Template** — secret diambil dari server dan dirender ke file tujuan; interval refresh
   mengikuti `refresh_interval_seconds` terkecil di antara template (default 300 detik).

## Struktur

Crate `secreton-agent`:

| File | Isi |
|------|-----|
| `src/main.rs` | Entry point; memanggil `run_agent()` |
| `src/config.rs` | `AgentConfig` dan sub-konfigurasi (TOML) |
| `src/lib.rs` | `SecretonAgent`, `run_agent()` |
| `src/auth.rs` | `AuthHandler`: pemuatan token dan loop renewal |
| `src/health.rs` | `HealthChecker`, `HealthCheckResult`, `HealthSummary` |
| `src/metrics.rs` | Metrics dan server Prometheus (Axum) |
| `src/templating.rs` | `TemplateManager` berbasis Handlebars |

## Cara Menjalankan

### Build

```bash
cargo build --release --locked -p secreton-agent
```

### Run

```bash
./target/release/secreton-agent
```

Tidak ada flag `--config`. `run_agent()` memuat konfigurasi secara berurutan:

1. Variabel environment (`AgentConfig::load_from_env`)
2. Default, jika environment tidak lengkap

`AgentConfig::load()` yang mencari `agent.toml` di beberapa lokasi ada di kode, tetapi
`run_agent()` **tidak** memanggilnya — jadi hari ini jalur file tidak dipakai oleh binary.
Untuk memakai file, panggil `load()`/`load_from_file()` dari kode Anda sendiri.

### Variabel Environment

| Variable | Fungsi |
|----------|--------|
| `SECRETON_AGENT_ID` | ID agent |
| `SECRETON_AGENT_NAME` | Nama agent |
| `SECRETON_LOG_LEVEL` | Level logging |

## Konfigurasi

Formatnya **TOML**, dibaca dengan `toml::from_str` ke `AgentConfig`. Ini bukan YAML, dan
contoh `agent.yaml` pada versi sebelumnya dari dokumen ini tidak akan terparse.

Contoh `agent.toml` yang sesuai dengan struct yang ada:

```toml
agent_id = "agent-1"
name = "Secreton Agent"

[monitoring]
enabled = true
interval_seconds = 60

[health]
agent_enabled = true
check_interval_seconds = 60
timeout_seconds = 30

[metrics]
enabled = true
prometheus_port = 9100
collection_interval_seconds = 30

[security]
verify_tls = true
strict_file_permissions = true

[alerting]
enabled = false
# webhook_url = "https://..."

[logging]
level = "info"
json = false

# Opsional. Tanpa bagian ini, agent tidak melakukan panggilan terautentikasi
# dan loop renewal tidak berjalan.
[vault]
server_url = "http://localhost:3000"
# token = "..."            # atau
# token_file = "/tmp/secreton-token"

# Opsional. Setiap entri memakai sintaks Handlebars, bukan gaya Vault:
#   {{ secrets.["secret/data/db"].password }}
[[templates]]
source = "/etc/myapp/config.tpl"
destination = "/etc/myapp/config.json"
refresh_interval_seconds = 300
# command = "systemctl reload myapp"   # dijalankan setelah render
```

`vault` dan `templates` bersifat opsional (`#[serde(default)]` pada field itu). Semua bagian
lain **wajib ada** di file: `AgentConfig` tidak memakai `#[serde(default)]` dan field-nya
bukan `Option`, jadi file yang menghilangkan `[health]` atau `[logging]` akan gagal
terparse. Sebaliknya, di dalam `[monitoring]`, `[alerting]`, `[security]`, `[metrics]`, dan
`[logging]`, field yang tidak disebut memakai nilai default-nya.

## Batasan

- **Template memakai Handlebars.** Helper gaya Vault `{{ with secret "..." }}` tidak
  didukung. Karena helper Handlebars bersifat sinkron dan pengambilan secret bersifat
  asinkron, `TemplateManager` terlebih dahulu memindai template untuk path secret, mengambil
  semuanya, lalu merender dengan konteks yang sudah terisi.
- **Tidak ada auto-auth.** Satu-satunya cara masuk adalah token yang sudah ada di
  konfigurasi, file, atau environment. Tidak ada login AppRole, Service Account Kubernetes,
  AWS IAM, atau Azure MSI.
- **Tidak ada sink atau supervisor.** Agent tidak menulis token ke file sink dan tidak
  menjalankan aplikasi utama dengan environment berisi secret.
- **Konfigurasi dari file tidak dipakai oleh binary** — lihat bagian Run di atas.
- Dokumentasi ini sebelumnya menyebut re-export dari `secreton_monitoring`; crate itu tidak
  ada di workspace.
