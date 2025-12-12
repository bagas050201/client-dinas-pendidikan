# Client Dinas Pendidikan - SSO Only

Website client untuk Dinas Pendidikan Provinsi DKI Jakarta dengan autentikasi **Single Sign-On (SSO) Keycloak**.

## 🔐 Autentikasi

Aplikasi ini **hanya mendukung SSO Keycloak**. Tidak ada login email/password tradisional.

### Fitur
- ✅ Login via SSO Keycloak dengan PKCE
- ✅ Dashboard dengan informasi user dari SSO
- ✅ Profil pengguna (Read-Only, data dari SSO)
- ✅ Session management
- ✅ Auto-logout sync dengan SSO

## Tech Stack

- **Backend**: Go (Golang)
- **SSO**: Keycloak dengan OAuth 2.0 / OIDC + PKCE
- **Database**: PostgreSQL (via Supabase untuk session storage)
- **Deployment**: Vercel Serverless Functions

## 📁 Struktur Folder

```
client-dinas-pendidikan/
├── api/                          # Vercel serverless functions
│   ├── main_handler.go           # Core routing dan handlers (4700+ lines)
│   ├── keycloak_helpers.go       # Helper SSO Keycloak (modular, copy-paste ready)
│   ├── profile_handler.go        # Handler halaman profile
│   ├── logo.png                  # Logo (embedded)
│   └── static/
│       └── sso-handler.js        # SSO JavaScript handler
│
├── docs/                         # Dokumentasi
│   └── SSO_INTEGRATION_GUIDE.md  # 📚 Panduan integrasi SSO (Go, JS, PHP, Python, Node.js)
│
├── pkg/helpers/                  # Utility functions
│   └── utils.go
│
├── .env                          # Environment variables
├── dev.go                        # Development server
├── go.mod, go.sum
├── README.md
└── vercel.json                   # Vercel config
```

## 📚 Untuk Developer Website Client Lain

Jika Anda ingin mengintegrasikan SSO Keycloak ke website client Anda:

👉 **Baca: [docs/SSO_INTEGRATION_GUIDE.md](docs/SSO_INTEGRATION_GUIDE.md)**

Panduan mencakup:
- ✅ **Quickstart** - Integrasi dalam 5 menit
- ✅ **Konsep SSO & PKCE** - Penjelasan visual dengan diagram
- ✅ **Go (Golang)** - Full code siap copy-paste
- ✅ **JavaScript (Browser)** - Class SSOClient
- ✅ **PHP (Laravel)** - Service & Controller
- ✅ **Python (Flask)** - Module & routes
- ✅ **Node.js (Express)** - Full implementation
- ✅ **Troubleshooting** - Error umum dan solusi

### File Referensi

| File | Deskripsi |
|------|-----------|
| `api/keycloak_helpers.go` | Helper SSO yang bisa di-copy ke project Go lain |
| `docs/SSO_INTEGRATION_GUIDE.md` | Panduan lengkap untuk semua bahasa |

## Setup

### Prerequisites
- Go 1.20+
- Keycloak Server yang sudah dikonfigurasi
- PostgreSQL database

### Environment Variables

Buat file `.env`:

```bash
# SSO Keycloak Configuration
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=dinas-pendidikan
KEYCLOAK_CLIENT_ID=client-dinas
KEYCLOAK_REDIRECT_URI=http://localhost:8070/callback

# PostgreSQL Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5433
POSTGRES_DB=dinas_pendidikan
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres123

# Supabase (untuk session storage)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key

# Server
PORT=8070
```

### Development

```bash
# Install dependencies
go mod download

# Run development server
go run dev.go
```

Server berjalan di `http://localhost:8070`

## Routes

| Route | Description |
|-------|-------------|
| `/` | Home page (redirect ke dashboard jika login) |
| `/login` | Halaman login SSO |
| `/dashboard` | Dashboard utama |
| `/profile` | Profil pengguna (read-only) |
| `/logout` | Logout dari SSO |
| `/sso/login` | Memulai flow SSO |
| `/callback` | Callback dari Keycloak |

## License

Copyright © 2025 Dinas Pendidikan Provinsi DKI Jakarta
