# 📚 Dokumentasi SSO - Index

> **Central Hub**: Daftar lengkap semua dokumentasi SSO untuk website aplikasi Dinas Pendidikan

---

## 🎯 Untuk Siapa Dokumentasi Ini?

### 👨‍💻 Developer Website Baru
Anda ingin mengintegrasikan website baru dengan SSO Dinas Pendidikan?

**Mulai di sini:**
1. 📖 **[SSO_QUICK_START.md](./SSO_QUICK_START.md)** - Panduan cepat 10 langkah
2. 📘 **[PANDUAN_SSO_UNTUK_WEBSITE_LAIN.md](./PANDUAN_SSO_UNTUK_WEBSITE_LAIN.md)** - Panduan lengkap & detail

### 🔧 Developer yang Sedang Debugging
Ada masalah dengan SSO? Perlu memahami alur lengkapnya?

**Baca ini:**
1. 📊 **[SSO_FLOW_VISUAL_GUIDE.md](./SSO_FLOW_VISUAL_GUIDE.md)** - Diagram visual alur SSO
2. 🔍 **[SSO_TROUBLESHOOTING.md](./SSO_TROUBLESHOOTING.md)** - Troubleshooting umum
3. 🏗️ **[IMPLEMENTATION_COMPLETE.md](./IMPLEMENTATION_COMPLETE.md)** - Dokumentasi implementasi website ini

### 🛠️ Admin Keycloak
Perlu setup client baru di Keycloak?

**Lihat ini:**
1. ⚙️ **[KEYCLOAK_CLIENT_SETUP.md](./KEYCLOAK_CLIENT_SETUP.md)** - Setup Keycloak client

---

## 📂 Struktur Dokumentasi

### 📌 Quick Reference (Mulai Di Sini)

| Dokumen | Deskripsi | Waktu Baca | Untuk Siapa |
|---------|-----------|------------|-------------|
| **[SSO_QUICK_START.md](./SSO_QUICK_START.md)** | Panduan cepat 10 langkah implementasi SSO | ⏱️ 10 min | Developer baru |
| **[PANDUAN_SSO_UNTUK_WEBSITE_LAIN.md](./PANDUAN_SSO_UNTUK_WEBSITE_LAIN.md)** | Panduan lengkap dengan code examples | ⏱️ 30 min | Developer semua level |
| **[SSO_FLOW_VISUAL_GUIDE.md](./SSO_FLOW_VISUAL_GUIDE.md)** | Diagram visual alur login, logout, data | ⏱️ 15 min | Developer & architect |

---

### 🔧 Setup & Configuration

| Dokumen | Deskripsi | Waktu Baca |
|---------|-----------|------------|
| **[KEYCLOAK_CLIENT_SETUP.md](./KEYCLOAK_CLIENT_SETUP.md)** | Cara setup client di Keycloak Admin Console | ⏱️ 10 min |
| **[POSTGRESQL_SETUP.md](./POSTGRESQL_SETUP.md)** | Setup database PostgreSQL untuk SSO | ⏱️ 10 min |
| **[.env.example](./.env.example)** | Contoh environment variables | ⏱️ 5 min |

---

### 📖 Deep Dive (Advanced)

| Dokumen | Deskripsi | Waktu Baca |
|---------|-----------|------------|
| **[IMPLEMENTATION_COMPLETE.md](./IMPLEMENTATION_COMPLETE.md)** | Log implementasi SSO di website ini (history) | ⏱️ 15 min |
| **[SERVER_RUNNING.md](./SERVER_RUNNING.md)** | Cara run development server | ⏱️ 10 min |
| **[PKCE_UPDATE.md](./PKCE_UPDATE.md)** | Update ke PKCE dari plain OAuth | ⏱️ 10 min |
| **[SSO_SERVER_REQUIREMENTS.md](./SSO_SERVER_REQUIREMENTS.md)** | Requirements untuk SSO server | ⏱️ 10 min |

---

### 🐛 Debugging & Troubleshooting

| Dokumen | Deskripsi | Waktu Baca |
|---------|-----------|------------|
| **[SSO_TROUBLESHOOTING.md](./SSO_TROUBLESHOOTING.md)** | Common issues dan solusinya | ⏱️ 10 min |
| **[PKCE_UPDATE.md](./PKCE_UPDATE.md)** | Update ke PKCE dari plain OAuth | ⏱️ 10 min |
| **[PROJECT_CLEANUP.md](./PROJECT_CLEANUP.md)** | File-file yang dihapus saat cleaning project | ⏱️ 5 min |

---

### 📝 Implementation Logs (History)

| Dokumen | Deskripsi |
|---------|-----------|
| **[IMPLEMENTATION_COMPLETE.md](./IMPLEMENTATION_COMPLETE.md)** | Log implementasi SSO di website ini |
| **[SERVER_RUNNING.md](./SERVER_RUNNING.md)** | Cara run server development |
| **[PROJECT_CLEANUP.md](./PROJECT_CLEANUP.md)** | Cleaning project - files yang dihapus |

---

## 🚀 Quick Start Paths

### Path 1: Saya Mau Implementasi SSO dari Nol

```
1. Baca: SSO_QUICK_START.md (10 menit)
   ↓
2. Setup Keycloak: KEYCLOAK_CLIENT_SETUP.md (10 menit)
   ↓
3. Setup Database: POSTGRESQL_SETUP.md → buat tabel pengguna & sesi_login
   ↓
4. Config .env: Copy .env.example → isi KEYCLOAK_* variables
   ↓
5. Copy code: Ambil dari PANDUAN_SSO_UNTUK_WEBSITE_LAIN.md
   ↓
6. Testing: Ikuti checklist di SSO_QUICK_START.md
   ↓
7. ✅ SSO berhasil!
```

**Total waktu: ~2-4 jam** (termasuk coding & testing)

---

### Path 2: SSO Saya Sudah Ada, tapi Error

```
1. Check error message
   ↓
2. Baca: SSO_TROUBLESHOOTING.md → cari error yang sama
   ↓
3. Lihat flow diagram: SSO_FLOW_VISUAL_GUIDE.md → pahami alur yang error
   ↓
4. Debug: Check logs di browser console & server logs
   ↓
5. Fix berdasarkan troubleshooting guide
   ↓
6. ✅ Error solved!
```

**Total waktu: ~30 menit - 2 jam** (tergantung complexity error)

---

### Path 3: Saya Butuh Memahami Arsitektur SSO

```
1. Read: SSO_FLOW_VISUAL_GUIDE.md → diagram lengkap
   ↓
2. Read: PANDUAN_SSO_UNTUK_WEBSITE_LAIN.md → section "Arsitektur SSO"
   ↓
3. Read: SSO_FLOW_DIAGRAMS.md → diagram Docker architecture
   ↓
4. ✅ Paham arsitektur!
```

**Total waktu: ~1 jam**

---

## 🔑 Konsep Kunci

### OAuth 2.0 Authorization Code Flow

```
User → Aplikasi → Keycloak (Login) → Return Code → 
Aplikasi Exchange Code → Get Token → Get User Info → Create Session
```

**Dokumentasi:** [PANDUAN_SSO_UNTUK_WEBSITE_LAIN.md](./PANDUAN_SSO_UNTUK_WEBSITE_LAIN.md) - Section "OAuth 2.0 Authorization Code Flow"

---

### PKCE (Proof Key for Code Exchange)

Mekanisme keamanan tambahan untuk mencegah authorization code interception.

**Flow:**
1. Generate `code_verifier` (random string)
2. Generate `code_challenge` = SHA256(code_verifier)
3. Kirim `code_challenge` ke Keycloak saat authorize
4. Kirim `code_verifier` saat exchange code untuk token
5. Keycloak verify: SHA256(code_verifier) == code_challenge

**Dokumentasi:** [PKCE_UPDATE.md](./PKCE_UPDATE.md)

---

### Centralized Logout

Logout dari 1 aplikasi = logout dari semua aplikasi yang menggunakan Keycloak yang sama.

**Flow:**
1. User klik logout di Aplikasi A
2. Aplikasi A redirect ke Keycloak logout endpoint
3. Keycloak destroy session
4. Keycloak notify semua aplikasi lain (front-channel logout)
5. Semua aplikasi clear session mereka

**Dokumentasi:** [SSO_FLOW_VISUAL_GUIDE.md](./SSO_FLOW_VISUAL_GUIDE.md) - Section "Flow Logout"

---

## 📊 Komponen Sistem

### 1. Portal SSO (Port 3000)
- **Fungsi:** Central login page & app launcher
- **Tech Stack:** Next.js, PostgreSQL
- **Repository:** `sso-dinas-pendidikan` (terpisah)

### 2. Keycloak (Port 8080)
- **Fungsi:** Authorization server, user management
- **Tech Stack:** Keycloak (Java)
- **Docker:** `quay.io/keycloak/keycloak`

### 3. Website Client (Port 8070 - **WEBSITE INI**)
- **Fungsi:** Aplikasi yang menerima SSO
- **Tech Stack:** Go, PostgreSQL
- **Repository:** Ini (current repository)

### 4. PostgreSQL Database (Port 5433)
- **Fungsi:** Menyimpan data user & session
- **Database:** `dinas_pendidikan`
- **Tables:** `pengguna`, `sesi_login`

---

## 🎓 Belajar dari Implementasi Website Ini

### File-file Penting

**Backend (Go):**
```
api/
├── main_handler.go          # Main routing & handlers
├── keycloak_helpers.go      # Keycloak integration
├── sso_handlers.go          # SSO-specific handlers
└── session/
    └── session.go           # Session management
```

**Frontend (Embedded in Go):**
```
api/
├── main_handler.go          # renderLoginPage() → HTML dengan button SSO
└── static/
    └── sso-handler.js       # SSO client-side handler (optional)
```

**Configuration:**
```
.env                         # Environment variables
```

### Cara Menjalankan Website Ini

```bash
# 1. Clone repository
git clone <repo-url>
cd client-dinas-pendidikan

# 2. Setup .env
cp .env.example .env
# Edit .env sesuai kebutuhan

# 3. Run server
go run dev.go

# 4. Access
http://localhost:8070
```

**Dokumentasi:** [SERVER_RUNNING.md](./SERVER_RUNNING.md)

---

## 🛠️ Tools & Dependencies

### Required Tools
- **Go** 1.21+ ([Download](https://go.dev/dl/))
- **PostgreSQL** 14+ ([Download](https://www.postgresql.org/download/))
- **Docker** (optional, for Keycloak) ([Download](https://www.docker.com/))

### Go Dependencies
```bash
go get github.com/golang-jwt/jwt/v5
go get github.com/lib/pq
go get golang.org/x/crypto/bcrypt
```

### JavaScript Dependencies
- **None!** Menggunakan native browser APIs (fetch, crypto, sessionStorage)

---

## 📞 Kontak & Support

### Ada Pertanyaan?

1. **Check dokumentasi** terlebih dahulu (lihat index di atas)
2. **Check troubleshooting guide** → [SSO_TROUBLESHOOTING.md](./SSO_TROUBLESHOOTING.md)
3. **Hubungi tim IT Pusdatin** Dinas Pendidikan DKI Jakarta

### Kontribusi

Menemukan kesalahan di dokumentasi atau ada improvement?
- Submit Pull Request
- Atau hubungi tim maintainer

---

## 📝 Changelog

### v2.0 - SSO dengan Keycloak + PKCE (Current)
- ✅ OAuth 2.0 Authorization Code Flow
- ✅ PKCE untuk keamanan ekstra
- ✅ Centralized logout
- ✅ Auto-login dengan prompt=none
- ✅ Session management di PostgreSQL

### v1.0 - SSO Simple (Legacy)
- ❌ Deprecated - tidak lagi digunakan
- Dokumentasi: [SSO_SIMPLE_GUIDE.md](./SSO_SIMPLE_GUIDE.md)

---

## 🏆 Best Practices

### Keamanan
- ✅ Gunakan HTTPS di production
- ✅ Enable PKCE (S256)
- ✅ Validate state (CSRF protection)
- ✅ Set secure cookies (HttpOnly, Secure, SameSite)
- ✅ Session expiry (24 jam max)
- ✅ Regular security audit

### Development
- ✅ Logging yang baik (log setiap step OAuth flow)
- ✅ Error handling yang jelas
- ✅ Testing di incognito window
- ✅ Dokumentasi code
- ✅ Environment variables untuk config

### Production
- ✅ HTTPS mandatory
- ✅ Load balancing untuk high traffic
- ✅ Database connection pooling
- ✅ Monitoring & alerting
- ✅ Backup session database

---

## 📚 Referensi External

### OAuth 2.0 & OpenID Connect
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)

### Keycloak
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [Keycloak GitHub](https://github.com/keycloak/keycloak)

### Go Libraries
- [golang-jwt/jwt](https://github.com/golang-jwt/jwt)
- [lib/pq](https://github.com/lib/pq) - PostgreSQL driver

---

## ✨ Summary

Dokumentasi SSO ini dibuat untuk memudahkan developer mengintegrasikan website dengan SSO Dinas Pendidikan. Pilih path yang sesuai dengan kebutuhan Anda:

- **Implementasi baru?** → [SSO_QUICK_START.md](./SSO_QUICK_START.md)
- **Butuh detail lengkap?** → [PANDUAN_SSO_UNTUK_WEBSITE_LAIN.md](./PANDUAN_SSO_UNTUK_WEBSITE_LAIN.md)
- **Debugging error?** → [SSO_TROUBLESHOOTING.md](./SSO_TROUBLESHOOTING.md)
- **Pahami flow?** → [SSO_FLOW_VISUAL_GUIDE.md](./SSO_FLOW_VISUAL_GUIDE.md)

**Happy Coding! 🚀**

---

*Last Updated: 2025-12-05*  
*Maintained by: Tim IT Pusdatin Dinas Pendidikan DKI Jakarta*
