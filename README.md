# Client Dinas Pendidikan

Website client untuk Dinas Pendidikan Provinsi DKI Jakarta.

## Tech Stack

- **Backend**: Go (Golang) dengan Vercel Serverless Functions
- **Frontend**: HTML, CSS (inline), JavaScript (vanilla)
- **Database**: Supabase (REST API)
- **SSO**: Keycloak (SSO Simple - token-based authentication)
- **Deployment**: Vercel

## 🔐 SSO Integration

Website ini menggunakan **SSO Simple** untuk autentikasi. Portal SSO mengirim token langsung ke client, dan client hanya perlu decode token untuk mendapatkan user info **TANPA perlu call API ke Keycloak**.

📖 **Panduan Lengkap:** Lihat [SSO_SIMPLE_GUIDE.md](./SSO_SIMPLE_GUIDE.md)

### Quick Start SSO

1. Portal SSO mengirim URL: `/?sso_token=<access_token>&sso_id_token=<id_token>`
2. Backend decode `sso_id_token` untuk dapat user info
3. Extract email dari claims
4. Create session dengan email
5. Redirect ke dashboard

**Tidak perlu call API ke Keycloak!**

## Setup

### Prerequisites

- Go 1.20 atau lebih baru
- Akun Supabase
- Akun Vercel

### Installation

1. Clone repository:
```bash
git clone <repository-url>
cd client-dinas-pendidikan
```

2. Install dependencies:
```bash
go mod download
```

3. Setup environment variables:
```bash
cp .env.example .env
```

Edit `.env` dan isi dengan:
```
# PostgreSQL Configuration (Database Utama)
POSTGRES_HOST=localhost
POSTGRES_PORT=5433
POSTGRES_DB=dinas_pendidikan
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres123

# Supabase Configuration (untuk session storage)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key

# JWT Configuration (Optional)
JWT_PUBLIC_KEY=your-jwt-public-key  # Optional: untuk signature validation (development mode jika tidak di-set)

# Server Configuration
PORT=8070
```

4. Setup database di PostgreSQL:
Buat database dan tabel di PostgreSQL:

```sql
-- Connect ke PostgreSQL
psql -h localhost -p 5433 -U postgres

-- Create database
CREATE DATABASE dinas_pendidikan;

-- Connect ke database
\c dinas_pendidikan;

-- Create table pengguna
CREATE TABLE pengguna (
    id_pengguna UUID PRIMARY KEY,
    nama_pengguna VARCHAR(100),
    email VARCHAR(255) UNIQUE NOT NULL,
    nama_lengkap VARCHAR(255) NOT NULL,
    peran VARCHAR(50) NOT NULL,
    password VARCHAR(255),
    aktif BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test user
INSERT INTO pengguna (id_pengguna, nama_pengguna, email, nama_lengkap, peran, aktif) VALUES 
('05374820-444f-45a4-b9e1-487284b35206', 'admin', 'admin@dinas-pendidikan.go.id', 'Administrator', 'admin', true);
```

5. Setup session storage di Supabase:
Jalankan SQL berikut di Supabase SQL Editor:

```sql
-- Table: sesi_login (untuk session storage)
CREATE TABLE sesi_login (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    id_pengguna TEXT NOT NULL,
    id_sesi TEXT UNIQUE NOT NULL,
    ip TEXT,
    user_agent TEXT,
    kadaluarsa TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
```

## Development

### Run Local Server

```bash
go run dev.go
```

Server akan berjalan di `http://localhost:8070`

### Build

```bash
go build ./api
```

## Deployment

### Deploy ke Vercel

1. Install Vercel CLI:
```bash
npm i -g vercel
```

2. Login ke Vercel:
```bash
vercel login
```

3. Deploy:
```bash
vercel --prod
```

4. Set environment variables di Vercel Dashboard:
   - `SUPABASE_URL` (required)
   - `SUPABASE_KEY` (required)
   - `JWT_PUBLIC_KEY` (optional: untuk signature validation, development mode jika tidak di-set)

## Features

- ✅ Authentication (Login/Register)
- ✅ SSO Integration (SSO Simple - token-based)
- ✅ **PostgreSQL Database** (User authentication dan data)
- ✅ **Supabase Integration** (Session storage)
- ✅ Session Management
- ✅ Home Page dengan pengumuman
- ✅ About Page
- ✅ Services Page
- ✅ News/Announcements Page
- ✅ Profile Page dengan edit profile dan change password
- ✅ Dashboard dengan informasi user
- ✅ Responsive Design
- ✅ Lighthouse Optimized

## Routes

- `/` - Home page (requires auth)
- `/login` - Login page
- `/register` - Register page
- `/about` - About page (requires auth)
- `/services` - Services page (requires auth)
- `/news` - News page (requires auth)
- `/profile` - Profile page (requires auth)
- `/logout` - Logout

## API Endpoints

- `POST /api/login` - Login
- `POST /api/register` - Register
- `POST /api/logout` - Logout
- `GET /api/profile` - Get profile
- `PUT /api/profile` - Update profile
- `PUT /api/password` - Change password
- `GET /api/news` - Get news
- `GET /api/announcements` - Get announcements

## Project Structure

```
client-dinas-pendidikan/
├── api/
│   ├── main_handler.go          # Single entrypoint untuk Vercel
│   └── logo.png                  # Logo untuk embed
├── pkg/
│   └── helpers/
│       └── utils.go              # Helper functions
├── dev.go                        # Development server
├── vercel.json                   # Vercel config
├── .vercelignore                 # Vercel ignore
├── go.mod                        # Go module
└── README.md                     # Documentation
```

## Documentation

### 📖 SSO Simple (Versi Terbaru)

- **[SSO_SIMPLE_GUIDE.md](./SSO_SIMPLE_GUIDE.md)** ⭐ - Panduan lengkap implementasi SSO Simple (versi terbaru)
- **[SSO_SERVER_REQUIREMENTS.md](./SSO_SERVER_REQUIREMENTS.md)** - Requirements untuk Portal SSO (SSO Simple)
- **[SSO_TROUBLESHOOTING.md](./SSO_TROUBLESHOOTING.md)** - Troubleshooting guide untuk SSO Simple
- **[SSO_USER_DATA_FLOW.md](./SSO_USER_DATA_FLOW.md)** - Flow mendapatkan data user dari SSO (SSO Simple)
- **[POSTGRESQL_SETUP.md](./POSTGRESQL_SETUP.md)** 🔄 - Setup PostgreSQL database

### 📚 Legacy Documentation (Authorization Code Flow)

> ⚠️ **Catatan:** Dokumentasi berikut untuk versi lama yang sudah tidak digunakan.

- **[README_SSO.md](./README_SSO.md)** - Dokumentasi SSO (legacy - Authorization Code Flow dengan PKCE)
- **[SSO_CLIENT_IMPLEMENTATION_GUIDE.md](./SSO_CLIENT_IMPLEMENTATION_GUIDE.md)** - Panduan implementasi SSO client (legacy)
- **[SSO_FLOW_README.md](./SSO_FLOW_README.md)** - Dokumentasi alur SSO (legacy)

## Notes

- Semua handler logic ada di `api/main_handler.go` untuk menghindari "undefined" errors di Vercel
- Logo dan assets di-embed menggunakan `//go:embed`
- CSS dan JavaScript inline untuk performance (Lighthouse optimization)
- Session management menggunakan cookie-based dengan storage di Supabase
- **SSO Simple**: Portal SSO mengirim token langsung, client hanya perlu decode token (tidak perlu call API)

## License

Copyright © 2025 Dinas Pendidikan Provinsi DKI Jakarta

