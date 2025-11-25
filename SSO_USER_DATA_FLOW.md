# Flow Mendapatkan Data User dari SSO (SSO Simple)

## 📋 Overview

Dokumen ini menjelaskan bagaimana website client mendapatkan data user dari Portal SSO menggunakan **SSO Simple** dan menampilkannya di halaman website.

## 🔄 Flow Lengkap (SSO Simple)

### **STEP 1: Portal SSO Mengirim Token**

Ketika user klik aplikasi di Portal SSO, Portal SSO akan redirect ke website client dengan token di URL:

```
http://localhost:8070/?sso_token=<access_token>&sso_id_token=<id_token>
```

**File:** `api/main_handler.go` (Handler function untuk root path `/`)
- Handler detect `sso_token` dan `sso_id_token` di URL
- Prioritas: `sso_id_token` diproses terlebih dahulu (karena sudah berisi user info)

---

### **STEP 2: Backend Decode ID Token**

Backend decode ID token untuk extract user info **TANPA perlu call API ke Keycloak**.

**File:** `api/main_handler.go` (function `handleSSOTokenWithCookie`)

```go
// Decode JWT token
parsedToken, err := jwt.Parse(token, ...)

// Extract claims
claims := parsedToken.Claims.(jwt.MapClaims)

// Extract email dari claims
email := claims["email"].(string)
```

**Claims yang diextract:**
- `email` - Email user (prioritas utama)
- `preferred_username` - Username (fallback)
- `sub` - User ID (fallback jika seperti email)

---

### **STEP 3: Cari User di Database**

Backend mencari user di database berdasarkan email dari token.

**File:** `api/main_handler.go` (function `createSessionFromEmail`)

```go
// Query user dari Supabase
apiURL := fmt.Sprintf("%s/rest/v1/pengguna?email=eq.%s", supabaseURL, email)

// Jika user tidak ditemukan, return error
// (atau bisa auto-create user jika diimplementasikan)
```

**Database Schema:**
- Tabel: `pengguna`
- Field: `id_pengguna` (PK), `email`, `nama_lengkap`, `peran`, `aktif`

---

### **STEP 4: Create Session**

Backend create session di database untuk user.

**File:** `api/main_handler.go` (function `createSessionFromEmail`)

```go
// Generate session ID
sessionID, err := helpers.GenerateSessionID()

// Create session di Supabase
sessionData := map[string]interface{}{
    "id_pengguna": userID,
    "id_sesi": sessionID,
    "ip": getIPAddress(r),
    "user_agent": r.UserAgent(),
    "kadaluarsa": expiresAt,
}
```

**Database Schema:**
- Tabel: `sesi_login`
- Field: `id` (PK), `id_sesi`, `id_pengguna`, `ip`, `user_agent`, `kadaluarsa`

---

### **STEP 5: Set Cookie**

Backend set cookie untuk session management.

**File:** `api/main_handler.go` (function `handleSSOTokenWithCookie`)

```go
// Set cookie dengan nama yang konsisten
helpers.SetCookie(w, r, "client_dinas_session", sessionID, 86400) // 24 jam
helpers.SetCookie(w, r, "session_id", sessionID, 86400) // Backward compatibility
```

**Cookie Properties:**
- Name: `client_dinas_session` (primary), `session_id` (backward compatibility)
- HttpOnly: true
- MaxAge: 86400 (24 jam)
- Path: `/`

---

### **STEP 6: Redirect ke Dashboard**

Backend redirect user ke dashboard setelah session berhasil dibuat.

**File:** `api/main_handler.go` (Handler function)

```go
http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
```

---

### **STEP 7: Dashboard Menampilkan Data User**

Dashboard mengambil data user dari database dan menampilkannya.

**File:** `api/main_handler.go` (function `DashboardHandler`)

```go
// Get user dari session
user, err := getCurrentUser(r)

// Render dashboard dengan data user
renderDashboardPage(w, user, counts)
```

**Data yang ditampilkan:**
- Nama lengkap
- Email
- Peran (dengan badge warna)
- Status (Aktif/Tidak Aktif)

---

## 📊 Diagram Flow

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│   Portal SSO    │         │  Client Website  │         │    Database     │
│  (Keycloak)     │         │  (Backend Go)    │         │   (Supabase)    │
└────────┬────────┘         └────────┬─────────┘         └────────┬────────┘
         │                            │                            │
         │  1. User klik aplikasi     │                            │
         │                            │                            │
         │  2. Redirect dengan token  │                            │
         ├───────────────────────────>│                            │
         │  URL: /?sso_token=...      │                            │
         │      &sso_id_token=...     │                            │
         │                            │                            │
         │                            │  3. Decode sso_id_token    │
         │                            │     Extract email          │
         │                            │                            │
         │                            │  4. Cari user by email     │
         │                            ├───────────────────────────>│
         │                            │                            │
         │                            │  5. Create session          │
         │                            ├───────────────────────────>│
         │                            │                            │
         │                            │  6. Set cookie             │
         │                            │                            │
         │  7. Redirect ke dashboard  │                            │
         │<───────────────────────────┤                            │
         │                            │                            │
         │                            │  8. Get user dari session  │
         │                            ├───────────────────────────>│
         │                            │                            │
         │                            │  9. Render dashboard       │
         │                            │     dengan data user        │
         │                            │                            │
```

---

## 📋 Data Flow Detail

### 1. Token dari Portal SSO

**Format:**
```
sso_token=<access_token>
sso_id_token=<id_token>
```

**ID Token Claims:**
```json
{
  "sub": "65d5dd7c-884a-4462-ac32-f41564f8c27b",
  "email": "admin@dinas-pendidikan.go.id",
  "name": "Administrator Sistem",
  "preferred_username": "admin",
  "email_verified": true,
  "given_name": "Administrator",
  "family_name": "Sistem",
  "iss": "http://localhost:8080/realms/dinas-pendidikan",
  "aud": "sso-dinas-pendidikan",
  "exp": 1764039547,
  "iat": 1764039247
}
```

### 2. Email Extraction

Backend extract email dengan prioritas:
1. `email` claim (prioritas utama)
2. `preferred_username` claim (fallback)
3. `sub` claim (fallback jika seperti email)

### 3. User Lookup

**Query ke Supabase:**
```sql
SELECT * FROM pengguna WHERE email = 'admin@dinas-pendidikan.go.id';
```

**Response:**
```json
[{
  "id_pengguna": "uuid-here",
  "email": "admin@dinas-pendidikan.go.id",
  "nama_lengkap": "Administrator Sistem",
  "peran": "admin",
  "aktif": true
}]
```

### 4. Session Creation

**Insert ke Supabase:**
```sql
INSERT INTO sesi_login (id_pengguna, id_sesi, ip, user_agent, kadaluarsa)
VALUES (?, ?, ?, ?, ?);
```

### 5. Cookie Setting

**Cookie yang di-set:**
- `client_dinas_session` = sessionID (primary)
- `session_id` = sessionID (backward compatibility)

### 6. Dashboard Display

**Data yang ditampilkan:**
- Nama: dari `pengguna.nama_lengkap`
- Email: dari `pengguna.email`
- Peran: dari `pengguna.peran` (dengan badge warna)
- Status: dari `pengguna.aktif` (Aktif/Tidak Aktif)

---

## 🔑 Key Points

1. **Tidak Perlu Call API:**
   - User info langsung dari ID token claims
   - Tidak perlu call `/userinfo` endpoint ke Keycloak

2. **Prioritas Token:**
   - `sso_id_token` diproses terlebih dahulu (karena sudah berisi user info)
   - `sso_token` digunakan sebagai fallback

3. **Email adalah Key:**
   - Email dari token digunakan untuk mencari user di database
   - Pastikan email di token match dengan email di database

4. **Session Management:**
   - Session dibuat di database Supabase
   - Cookie digunakan untuk session tracking
   - Session expires setelah 24 jam

---

## 🔗 Referensi

- **[SSO_SIMPLE_GUIDE.md](./SSO_SIMPLE_GUIDE.md)** - Panduan lengkap SSO Simple
- **[SSO_SERVER_REQUIREMENTS.md](./SSO_SERVER_REQUIREMENTS.md)** - Requirements untuk Portal SSO
- **[SSO_TROUBLESHOOTING.md](./SSO_TROUBLESHOOTING.md)** - Troubleshooting guide
