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
- **Database**: PostgreSQL (JAKEDU External DB - Read Only)
- **Deployment**: Vercel Serverless Functions

## 📁 Struktur Folder

```
client-dinas-pendidikan/
├── api/                          # Vercel serverless functions
│   ├── main_handler.go           # Core routing dan handlers
│   ├── keycloak_helpers.go       # Helper SSO Keycloak
│   ├── profile_handler.go        # Handler halaman profile
│   ├── logo.png                  # Logo (embedded)
│   └── static/
│       └── sso-handler.js        # SSO JavaScript handler
│
├── docs/                         # Dokumentasi
│   └── SSO_INTEGRATION_GUIDE.md  # 📚 Panduan integrasi SSO
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

## Setup

### Prerequisites
- Go 1.20+
- Keycloak Server yang sudah dikonfigurasi
- Akses ke database JAKEDU PostgreSQL

### Environment Variables

Buat file `.env`:

```bash
# SSO Keycloak Configuration
KEYCLOAK_BASE_URL=https://sso.jakedu.id
KEYCLOAK_REALM=dinas-pendidikan
KEYCLOAK_CLIENT_ID=client-dinas
KEYCLOAK_REDIRECT_URI=http://localhost:8070/callback

# JAKEDU External DB (Read Only)
JAKEDU_PG_HOST=10.40.69.10
JAKEDU_PG_PORT=5434
JAKEDU_PG_DB=jakedu_dwh
JAKEDU_PG_USER=reader_dwh
JAKEDU_PG_PASSWORD=password

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
