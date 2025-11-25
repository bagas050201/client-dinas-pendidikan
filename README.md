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
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key
JWT_PUBLIC_KEY=your-jwt-public-key  # Optional: untuk signature validation (development mode jika tidak di-set)
PORT=8070
```

4. Setup database di Supabase:
Jalankan SQL berikut di Supabase SQL Editor:

```sql
-- Table: pengguna
CREATE TABLE pengguna (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    nama_lengkap TEXT NOT NULL,
    peran TEXT NOT NULL CHECK (peran IN ('guru', 'wali', 'murid', 'admin', 'user')),
    aktif BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table: sesi_login
CREATE TABLE sesi_login (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES pengguna(id) ON DELETE CASCADE,
    session_id TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL
);

-- Table: berita
CREATE TABLE berita (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    judul TEXT NOT NULL,
    konten TEXT NOT NULL,
    kategori TEXT NOT NULL,
    penulis_id UUID REFERENCES pengguna(id),
    published BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table: pengumuman
CREATE TABLE pengumuman (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    judul TEXT NOT NULL,
    konten TEXT NOT NULL,
    prioritas TEXT DEFAULT 'normal' CHECK (prioritas IN ('low', 'normal', 'high', 'urgent')),
    published BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP
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

