# Client Dinas Pendidikan - SSO Only

Website client untuk Dinas Pendidikan Provinsi DKI Jakarta dengan autentikasi **Single Sign-On (SSO) Keycloak**.

## 🔐 Autentikasi

Aplikasi ini **hanya mendukung SSO Keycloak**. Tidak ada login email/password tradisional.

### Fitur
- ✅ Login via SSO Keycloak
- ✅ Dashboard dengan informasi user dari SSO
- ✅ Profil pengguna (Read-Only, data dari SSO)
- ✅ Session management
- ✅ Auto-logout sync dengan SSO
- ✅ PKCE (Proof Key for Code Exchange) untuk keamanan

## Tech Stack

- **Backend**: Go (Golang)
- **SSO**: Keycloak dengan OAuth 2.0 / OIDC + PKCE
- **Database**: PostgreSQL (via Supabase untuk session storage)
- **Deployment**: Vercel Serverless Functions

## 📁 Struktur Folder

```
client-dinas-pendidikan/
├── api/                          # Vercel serverless functions
│   ├── main_handler.go           # Core routing dan handlers
│   ├── keycloak_helpers.go       # Helper SSO Keycloak
│   ├── logo.png                  # Logo (embedded)
│   └── static/
│       └── sso-handler.js        # SSO JavaScript handler
│
├── assets/                       # Aset statis
│   └── logo.png                  # Logo Dinas Pendidikan
│
├── cmd/                          # Entry points
│   └── dev.go                    # Development server
│
├── docs/                         # Dokumentasi
│   └── SSO_INTEGRATION_GUIDE.md  # Panduan integrasi SSO
│
├── pkg/                          # Packages reusable
│   ├── helpers/
│   │   └── utils.go              # Utility functions
│   └── sso/
│       └── keycloak_helpers.go   # SSO module (reusable)
│
├── .env                          # Environment variables
├── .gitignore
├── .vercelignore
├── dev.go                        # Development server (root)
├── go.mod
├── go.sum
├── README.md
└── vercel.json                   # Vercel config
```

## 📚 Dokumentasi

- **[SSO Integration Guide](docs/SSO_INTEGRATION_GUIDE.md)** - Panduan lengkap untuk mengintegrasikan SSO Keycloak ke website client lain (Go, JavaScript, PHP, Python, Node.js)

## Setup

### Prerequisites
- Go 1.20+
- Keycloak Server yang sudah dikonfigurasi
- PostgreSQL database

### Environment Variables

Buat file `.env`:

```bash
# SSO Keycloak Configuration
SSO_URL=http://localhost:8080
SSO_REALM=dinas-pendidikan
SSO_CLIENT_ID=client-dinas
SSO_CLIENT_SECRET=your-client-secret
SSO_REDIRECT_URI=http://localhost:8070/sso/callback

# PostgreSQL Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5433
POSTGRES_DB=dinas_pendidikan
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres123

# Supabase (untuk session storage - optional)
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

### Build

```bash
cd api && go build .
```

## Routes

| Route | Description |
|-------|-------------|
| `/` | Home page (redirect ke dashboard jika login) |
| `/login` | Halaman login SSO |
| `/dashboard` | Dashboard utama |
| `/profile` | Profil pengguna (read-only) |
| `/logout` | Logout dari SSO |
| `/sso/login` | Memulai flow SSO |
| `/sso/callback` | Callback dari Keycloak |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/profile` | GET | Mendapatkan data profil user |
| `/api/logout` | POST | Logout dan clear session |
| `/api/users/sso-login` | POST | Check/create user dari SSO |
| `/auth/validate` | GET | Validasi session |

## Untuk Developer Website Client Lain

Jika Anda ingin mengintegrasikan SSO Keycloak ke website client Anda, silakan baca:

📖 **[SSO Integration Guide](docs/SSO_INTEGRATION_GUIDE.md)**

Panduan tersebut mencakup:
- Arsitektur SSO
- Implementasi PKCE
- Contoh kode untuk Go, JavaScript, PHP (Laravel), Python (Flask), dan Node.js
- Session management
- Logout dan token revocation
- Troubleshooting

## License

Copyright © 2025 Dinas Pendidikan Provinsi DKI Jakarta
