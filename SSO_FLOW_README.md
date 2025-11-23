# 📚 Dokumentasi Alur SSO (Single Sign-On)

Membahas Supabase (24 matches)
Dokumentasi alur SSO dengan database Supabase
Arsitektur dan flow diagram

Dokumentasi lengkap untuk memahami alur SSO di Client Website Dinas Pendidikan DKI Jakarta.

---

## 📋 Daftar Isi

1. [Overview](#overview)
2. [Arsitektur SSO](#arsitektur-sso)
3. [File dan Fungsi yang Terlibat](#file-dan-fungsi-yang-terlibat)
4. [Alur Data Berdasarkan Database Supabase](#alur-data-berdasarkan-database-supabase)
5. [Flow Diagram Lengkap](#flow-diagram-lengkap)
6. [Environment Variables](#environment-variables)
7. [Cookies yang Digunakan](#cookies-yang-digunakan)

---

## 🎯 Overview

Sistem SSO di website ini menggunakan **OAuth 2.0 Authorization Code Flow** untuk autentikasi user melalui SSO server eksternal. Setelah user berhasil login di SSO server, client website akan:

1. Menerima authorization code dari SSO server
2. Menukar code tersebut dengan access token
3. Mengambil informasi user dari SSO server
4. Membuat atau update user di database Supabase
5. Membuat session lokal di database Supabase
6. Set cookie untuk session management

---

## 🏗️ Arsitektur SSO

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│   User Browser  │         │  Client Website  │         │   SSO Server    │
│  (localhost:8070)│         │  (localhost:8070) │         │  (localhost:8080)│
└────────┬────────┘         └────────┬─────────┘         └────────┬────────┘
         │                            │                            │
         │  1. Klik "Login dengan SSO"│                            │
         ├───────────────────────────>│                            │
         │                            │  2. Redirect ke SSO        │
         │                            ├───────────────────────────>│
         │                            │                            │
         │  3. Redirect ke SSO         │                            │
         │<────────────────────────────┤                            │
         │                            │                            │
         │  4. Login di SSO           │                            │
         ├─────────────────────────────┼──────────────────────────>│
         │                            │                            │
         │  5. Redirect dengan code    │                            │
         │<────────────────────────────┼───────────────────────────┤
         │                            │                            │
         │  6. Callback dengan code   │                            │
         ├───────────────────────────>│                            │
         │                            │  7. Exchange code → token   │
         │                            ├───────────────────────────>│
         │                            │                            │
         │                            │  8. Get user info          │
         │                            ├───────────────────────────>│
         │                            │                            │
         │                            │  9. Create/Update user     │
         │                            │     di Supabase             │
         │                            │                            │
         │                            │ 10. Create session         │
         │                            │     di Supabase             │
         │                            │                            │
         │ 11. Redirect ke dashboard  │                            │
         │<───────────────────────────┤                            │
         │                            │                            │
```

---

## 📁 File dan Fungsi yang Terlibat

### 1. **`api/ui_sso.go`** - Handler SSO Flow

#### `getSSOConfig() → SSOConfig`
- **Tugas**: Mengambil konfigurasi SSO dari environment variables
- **Return**: Struct `SSOConfig` berisi:
  - `SSOServerURL`: URL SSO server (default: `http://localhost:8080`)
  - `RedirectURI`: URI callback (default: `http://localhost:8070/api/callback`)
  - `ClientID`: Client ID untuk OAuth (dari `SSO_CLIENT_ID`)
- **Environment Variables**:
  - `SSO_SERVER_URL` (opsional, default: `http://localhost:8080`)
  - `SSO_CLIENT_ID` (required)
  - `SSO_REDIRECT_URI` (opsional, default: `http://localhost:8070/api/callback`)

#### `SSOAuthorizeHandler(w, r)`
- **Tugas**: Memulai SSO flow dengan redirect ke SSO server
- **Route**: `/sso/authorize`
- **Flow**:
  1. Generate `state` untuk CSRF protection
  2. Simpan `state` di cookie `sso_state` (expires 10 menit)
  3. Build authorize URL: `{SSO_SERVER_URL}/apps/access?client_id={CLIENT_ID}&state={STATE}`
  4. Redirect user ke SSO server
- **Output**: Redirect ke SSO server

#### `SSOCallbackHandler(w, r)`
- **Tugas**: Menangani callback dari SSO setelah user login
- **Route**: `/api/callback` atau `/callback`
- **Flow**:
  1. Parse query parameters: `code`, `state`, `error`, `error_description`
  2. Validasi `state` (bandingkan dengan cookie `sso_state`)
  3. Panggil `exchangeCodeForToken()` untuk menukar code dengan access token
  4. Simpan access token di cookie `sso_access_token` dan `sso_token_expires`
  5. Panggil `getUserInfoFromSSO()` untuk mengambil user info
  6. Panggil `findOrCreateUser()` untuk membuat/update user di database
  7. Panggil `internal.CreateSession()` untuk membuat session lokal
  8. Set cookie `client_dinas_session` dengan session ID
  9. Redirect ke `/dashboard` (atau `next` parameter)
- **Output**: Redirect ke dashboard atau error page

#### `exchangeCodeForToken(code, config) → *TokenResponse`
- **Tugas**: Menukar authorization code dengan access token
- **Endpoint SSO**: `POST {SSO_SERVER_URL}/api/token`
- **Request Body**:
  ```json
  {
    "grant_type": "authorization_code",
    "code": "{AUTHORIZATION_CODE}",
    "redirect_uri": "{REDIRECT_URI}",
    "client_id": "{CLIENT_ID}"
  }
  ```
- **Response**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "openid profile email"
  }
  ```
- **Return**: `*TokenResponse` atau error

#### `getUserInfoFromSSO(accessToken, config) → *UserInfo`
- **Tugas**: Mengambil informasi user dari SSO menggunakan access token
- **Endpoint SSO**: `GET {SSO_SERVER_URL}/api/userinfo`
- **Headers**:
  ```
  Authorization: Bearer {ACCESS_TOKEN}
  ```
- **Response**:
  ```json
  {
    "sub": "user-uuid",
    "email": "user@example.com",
    "name": "Nama Lengkap",
    "email_verified": true
  }
  ```
- **Fallback**: Jika `name` kosong, coba parse dari field `nama_lengkap`, `full_name`, atau `nama`
- **Return**: `*UserInfo` atau error

#### `findOrCreateUser(userInfo) → interface{}`
- **Tugas**: Mencari user di database atau membuat baru jika tidak ada
- **Database**: Tabel `pengguna` di Supabase
- **Flow**:
  1. Query user berdasarkan `email` di tabel `pengguna`
  2. Jika user sudah ada:
     - Ambil `id_pengguna`
     - Update `nama_lengkap` jika berbeda dari SSO (PATCH request)
     - Return `id_pengguna`
  3. Jika user belum ada:
     - Insert user baru dengan data:
       - `email`: dari SSO
       - `nama_lengkap`: dari SSO
       - `aktif`: `true`
       - `peran`: `"user"` (default)
     - Return `id_pengguna` dari response
- **Return**: `id_pengguna` (UUID) atau error

---

### 2. **`internal/session_helper.go`** - Session Management

#### `CreateSession(userID, r) → (sessionID, error)`
- **Tugas**: Membuat session baru di database Supabase
- **Database**: Tabel `sesi_login` di Supabase
- **Flow**:
  1. Generate session ID unik menggunakan `helpers.GenerateSessionID()`
  2. Siapkan data session:
     - `id_pengguna`: UUID user dari parameter
     - `id_sesi`: Session ID yang di-generate
     - `ip`: IP address dari request
     - `user_agent`: User agent dari request
     - `kadaluarsa`: Timestamp 24 jam dari sekarang (RFC3339 format)
  3. POST ke Supabase: `POST /rest/v1/sesi_login`
  4. Return session ID
- **Return**: Session ID (string) atau error

#### `ValidateSession(sessionID) → (userID, ok, error)`
- **Tugas**: Memvalidasi session ID dan mengembalikan user ID jika valid
- **Database**: Tabel `sesi_login` di Supabase
- **Flow**:
  1. Query session dengan filter:
     - `id_sesi = {SESSION_ID}`
     - `kadaluarsa > {NOW}` (session belum expired)
  2. Jika session ditemukan dan valid:
     - Return `id_pengguna` dari session
  3. Jika session tidak ditemukan atau expired:
     - Return `ok = false`
- **Return**: `(userID, ok, error)`

#### `ClearSession(sessionID) → error`
- **Tugas**: Menghapus session dari database (DELETE)
- **Database**: Tabel `sesi_login` di Supabase
- **Flow**:
  1. DELETE dari Supabase: `DELETE /rest/v1/sesi_login?id_sesi=eq.{SESSION_ID}`
- **Return**: Error jika gagal

---

### 3. **`api/ui_login.go`** - Login Page Handler

#### `LoginPageHandler(w, r)`
- **Tugas**: Menampilkan halaman login atau redirect jika sudah login
- **Route**: `GET /login`
- **Flow**:
  1. Cek apakah user sudah login:
     - Cek cookie `sso_access_token` dan `sso_token_expires`
     - Cek cookie `client_dinas_session` dan validasi dengan `internal.ValidateSession()`
  2. Jika sudah login → redirect ke `/dashboard`
  3. Jika belum login → tampilkan form login dengan tombol "Login dengan SSO"
- **Output**: HTML login page atau redirect

#### `LoginPostHandler(w, r)`
- **Tugas**: Menangani direct login (tanpa SSO)
- **Route**: `POST /login`
- **Flow**:
  1. Parse email dan password dari form
  2. Query user di tabel `pengguna` berdasarkan email
  3. Verifikasi password (bcrypt atau plain text fallback)
  4. Jika valid → panggil `internal.CreateSession()` untuk membuat session
  5. Set cookie `client_dinas_session` dengan session ID
  6. Return JSON dengan `redirect: "/dashboard"` atau redirect langsung
- **Output**: JSON response atau redirect

---

### 4. **`api/middleware_auth.go`** - Authentication Middleware

#### `RequireAuth(next) → http.HandlerFunc`
- **Tugas**: Middleware untuk protect routes yang memerlukan autentikasi
- **Flow**:
  1. Cek access token:
     - Ambil cookie `sso_access_token` dan `sso_token_expires`
     - Validasi expiration timestamp
     - Jika valid → lanjutkan ke handler
  2. Cek session:
     - Ambil cookie `client_dinas_session` (atau `session_id` untuk backward compatibility)
     - Validasi dengan `internal.ValidateSession()`
     - Jika valid → lanjutkan ke handler
  3. Jika tidak valid → redirect ke `/login?next={CURRENT_PATH}`
- **Return**: Handler function yang sudah di-wrap dengan auth check

---

### 5. **`api/ui_dashboard.go`** - Dashboard Handler

#### `DashboardHandler(w, r)`
- **Tugas**: Menampilkan halaman dashboard (protected route)
- **Route**: `GET /dashboard`
- **Flow**:
  1. Gunakan `RequireAuth()` middleware untuk protect route
  2. Panggil `renderDashboardWithToken()` untuk render dashboard

#### `renderDashboardWithToken(w, r)`
- **Tugas**: Render dashboard setelah token/session validated
- **Flow**:
  1. Ambil session ID dari cookie `client_dinas_session` (atau `session_id`)
  2. Validasi session dengan `internal.ValidateSession()`
  3. Ambil user data dengan `getUserByID(userID)`
  4. Ambil dashboard counts dengan `getDashboardCounts()`
  5. Render dashboard HTML dengan user name dan counts

#### `getUserByID(userID) → (map[string]interface{}, error)`
- **Tugas**: Mengambil data user dari Supabase berdasarkan ID
- **Database**: Tabel `pengguna` di Supabase
- **Query**: `GET /rest/v1/pengguna?id_pengguna=eq.{USER_ID}&select=*`
- **Return**: Map user data atau error

---

### 6. **`api/main_handler.go`** - Main Router

#### `Handler(w, r)`
- **Tugas**: Single entrypoint untuk semua request (Vercel serverless function)
- **Flow**:
  1. Parse path dari request
  2. Route ke handler yang sesuai:
     - `/sso/authorize` → `SSOAuthorizeHandler()`
     - `/api/callback` atau `/callback` → `SSOCallbackHandler()`
     - `/login` → `LoginPageHandler()` atau `LoginPostHandler()`
     - `/dashboard` → `DashboardHandler()`
     - `/` → `renderHomePage()` (protected)
     - dll.

#### `getCurrentUser(r) → (map[string]interface{}, error)`
- **Tugas**: Mengambil data user dari session (untuk halaman umum)
- **Flow**:
  1. Ambil session ID dari cookie `client_dinas_session` (atau `session_id`)
  2. Validasi session dengan `internal.ValidateSession()`
  3. Ambil user data dengan `getUserByIDForHome(userID)`
- **Return**: Map user data atau error

#### `getUserByIDForHome(userID) → (map[string]interface{}, error)`
- **Tugas**: Mengambil data user dari Supabase (sama seperti `getUserByID()` di `ui_dashboard.go`)
- **Database**: Tabel `pengguna` di Supabase
- **Query**: `GET /rest/v1/pengguna?id_pengguna=eq.{USER_ID}&select=*`
- **Return**: Map user data atau error

---

### 7. **`api/ui_logout.go`** - Logout Handler

#### `LogoutHandler(w, r)`
- **Tugas**: Menangani proses logout user
- **Route**: `GET /logout`
- **Flow**:
  1. Ambil session ID dari cookie `client_dinas_session`
  2. Panggil `internal.ClearSession()` untuk menghapus session dari database
  3. Clear semua cookie terkait auth:
     - `client_dinas_session`
     - `sso_access_token`
     - `sso_token_expires`
     - `sso_state`
     - `sso_code_verifier`
     - `session_id` (backward compatibility)
  4. **PENTING**: Jangan clear `sso_admin_session` (cookie dari SSO server)
  5. Redirect ke `/`
- **Output**: Redirect ke home page

---

## 🗄️ Alur Data Berdasarkan Database Supabase

### Tabel yang Terlibat

#### 1. **Tabel `pengguna`** (User Data)

**Schema**:
```sql
CREATE TABLE pengguna (
    id_pengguna UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    nama_lengkap TEXT,
    password_hash TEXT,  -- bcrypt hash (untuk direct login)
    password TEXT,       -- plain text (fallback, deprecated)
    aktif BOOLEAN DEFAULT true,
    peran TEXT DEFAULT 'user',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

**Alur Data**:

1. **SSO Login Flow**:
   ```
   SSO Server → getUserInfoFromSSO() → findOrCreateUser()
   ↓
   Query: SELECT * FROM pengguna WHERE email = '{EMAIL}'
   ↓
   Jika user ada:
     - Ambil id_pengguna
     - Update nama_lengkap jika berbeda (PATCH)
   ↓
   Jika user tidak ada:
     - INSERT INTO pengguna (email, nama_lengkap, aktif, peran)
     - VALUES ('{email}', '{name}', true, 'user')
     - Ambil id_pengguna dari response
   ↓
   Return id_pengguna → CreateSession()
   ```

2. **Direct Login Flow**:
   ```
   LoginPostHandler() → Query user by email
   ↓
   Query: SELECT * FROM pengguna WHERE email = '{EMAIL}'
   ↓
   Verifikasi password (bcrypt atau plain text)
   ↓
   Jika valid → CreateSession(id_pengguna)
   ```

#### 2. **Tabel `sesi_login`** (Session Data)

**Schema**:
```sql
CREATE TABLE sesi_login (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    id_sesi TEXT NOT NULL UNIQUE,
    id_pengguna UUID NOT NULL REFERENCES pengguna(id_pengguna),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    kadaluarsa TIMESTAMPTZ NOT NULL,
    ip TEXT,
    user_agent TEXT
);
```

**Alur Data**:

1. **Create Session** (setelah SSO atau direct login):
   ```
   CreateSession(userID, request)
   ↓
   Generate session ID (random string)
   ↓
   INSERT INTO sesi_login (
       id_pengguna,
       id_sesi,
       ip,
       user_agent,
       kadaluarsa
   ) VALUES (
       '{userID}',
       '{sessionID}',
       '{ip}',
       '{userAgent}',
       NOW() + INTERVAL '24 hours'
   )
   ↓
   Set cookie: client_dinas_session = {sessionID}
   ↓
   Return sessionID
   ```

2. **Validate Session** (setiap request ke protected route):
   ```
   ValidateSession(sessionID)
   ↓
   Query: SELECT id_pengguna 
          FROM sesi_login 
          WHERE id_sesi = '{sessionID}' 
            AND kadaluarsa > NOW()
   ↓
   Jika ditemukan:
     - Return id_pengguna, ok = true
   ↓
   Jika tidak ditemukan atau expired:
     - Return ok = false
   ```

3. **Clear Session** (saat logout):
   ```
   ClearSession(sessionID)
   ↓
   DELETE FROM sesi_login WHERE id_sesi = '{sessionID}'
   ↓
   Clear cookie: client_dinas_session
   ```

---

## 🔄 Flow Diagram Lengkap

### **Flow 1: SSO Login (OAuth 2.0 Authorization Code Flow)**

```
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: User Klik "Login dengan SSO"                            │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: GET /sso/authorize                                      │
│ Handler: SSOAuthorizeHandler()                                 │
│ - Generate state (CSRF protection)                              │
│ - Set cookie: sso_state = {state} (10 menit)                   │
│ - Redirect ke: {SSO_SERVER}/apps/access?client_id={ID}&state={S}│
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: User Login di SSO Server                                │
│ (User memasukkan email/password di SSO server)                 │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 4: SSO Server Redirect ke Callback                        │
│ URL: /api/callback?code={AUTH_CODE}&state={STATE}              │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 5: GET /api/callback                                       │
│ Handler: SSOCallbackHandler()                                   │
│ - Parse code dan state dari query                               │
│ - Validasi state (bandingkan dengan cookie sso_state)           │
│ - Clear cookie sso_state                                        │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 6: Exchange Code to Token                                 │
│ Function: exchangeCodeForToken()                                │
│ - POST {SSO_SERVER}/api/token                                   │
│   Body: grant_type=authorization_code&code={CODE}&...           │
│ - Response: {access_token, token_type, expires_in, scope}       │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 7: Save Access Token                                       │
│ - Set cookie: sso_access_token = {ACCESS_TOKEN}                 │
│ - Set cookie: sso_token_expires = {TIMESTAMP}                    │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 8: Get User Info from SSO                                 │
│ Function: getUserInfoFromSSO()                                 │
│ - GET {SSO_SERVER}/api/userinfo                                 │
│   Header: Authorization: Bearer {ACCESS_TOKEN}                 │
│ - Response: {sub, email, name, email_verified}                  │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 9: Find or Create User in Database                         │
│ Function: findOrCreateUser()                                    │
│ - Query: SELECT * FROM pengguna WHERE email = '{EMAIL}'         │
│ - Jika user ada:                                                │
│     • Ambil id_pengguna                                          │
│     • Update nama_lengkap jika berbeda (PATCH)                  │
│ - Jika user tidak ada:                                          │
│     • INSERT INTO pengguna (email, nama_lengkap, aktif, peran) │
│     • Ambil id_pengguna dari response                            │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 10: Create Session in Database                             │
│ Function: internal.CreateSession()                              │
│ - Generate session ID (random string)                           │
│ - INSERT INTO sesi_login (id_pengguna, id_sesi, ip, ...)        │
│ - Set cookie: client_dinas_session = {SESSION_ID} (24 jam)       │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 11: Redirect to Dashboard                                  │
│ - Redirect ke: /dashboard (atau next parameter)                 │
│ - User sekarang sudah login ✅                                   │
└─────────────────────────────────────────────────────────────────┘
```

### **Flow 2: Direct Login (Tanpa SSO)**

```
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: User Submit Login Form                                 │
│ POST /login                                                      │
│ Body: email={EMAIL}&password={PASSWORD}                        │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: Handler: LoginPostHandler()                             │
│ - Parse email dan password dari form                            │
│ - Query: SELECT * FROM pengguna WHERE email = '{EMAIL}'        │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: Verify Password                                         │
│ - Cek password_hash (bcrypt) atau password (plain text)         │
│ - Jika tidak valid → return error                               │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 4: Create Session                                          │
│ Function: internal.CreateSession()                              │
│ - Generate session ID                                            │
│ - INSERT INTO sesi_login (id_pengguna, id_sesi, ...)            │
│ - Set cookie: client_dinas_session = {SESSION_ID}                │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 5: Redirect to Dashboard                                    │
│ - Return JSON: {success: true, redirect: "/dashboard"}           │
│   atau redirect langsung ke /dashboard                           │
└─────────────────────────────────────────────────────────────────┘
```

### **Flow 3: Access Protected Route**

```
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: User Request Protected Route                            │
│ GET /dashboard (atau route lain yang protected)                 │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: Middleware: RequireAuth()                               │
│ - Cek cookie: sso_access_token dan sso_token_expires             │
│   • Jika ada dan belum expired → lanjutkan                      │
│ - Cek cookie: client_dinas_session (atau session_id)            │
│   • Validasi dengan internal.ValidateSession()                   │
│     - Query: SELECT id_pengguna FROM sesi_login                │
│              WHERE id_sesi = '{SESSION_ID}'                      │
│                AND kadaluarsa > NOW()                            │
│     - Jika valid → lanjutkan                                     │
│ - Jika tidak valid → redirect ke /login?next={PATH}              │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: Handler: DashboardHandler() atau handler lain            │
│ - Ambil user data dengan getUserByID(userID)                     │
│ - Query: SELECT * FROM pengguna WHERE id_pengguna = '{ID}'     │
│ - Render page dengan user data                                   │
└─────────────────────────────────────────────────────────────────┘
```

### **Flow 4: Logout**

```
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: User Klik "Logout"                                     │
│ GET /logout                                                      │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: Handler: LogoutHandler()                                │
│ - Ambil session ID dari cookie: client_dinas_session             │
│ - Function: internal.ClearSession()                              │
│   • DELETE FROM sesi_login WHERE id_sesi = '{SESSION_ID}'        │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: Clear All Auth Cookies                                  │
│ - Clear: client_dinas_session                                    │
│ - Clear: sso_access_token                                        │
│ - Clear: sso_token_expires                                      │
│ - Clear: sso_state                                              │
│ - Clear: sso_code_verifier                                      │
│ - Clear: session_id (backward compatibility)                     │
│ - PENTING: Jangan clear sso_admin_session (cookie dari SSO)     │
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 4: Redirect to Home                                        │
│ - Redirect ke: /                                                │
│ - User sekarang sudah logout ✅                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔧 Environment Variables

### Required Variables

```bash
# Supabase Configuration
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-anon-key

# SSO Configuration
SSO_CLIENT_ID=client-dinas-pendidikan
```

### Optional Variables

```bash
# SSO Server URL (default: http://localhost:8080)
SSO_SERVER_URL=http://localhost:8080

# SSO Redirect URI (default: http://localhost:8070/api/callback)
SSO_REDIRECT_URI=http://localhost:8070/api/callback
```

---

## 🍪 Cookies yang Digunakan

### 1. **`sso_state`**
- **Purpose**: CSRF protection untuk SSO flow
- **Set by**: `SSOAuthorizeHandler()`
- **Expires**: 10 menit (600 detik)
- **Cleared by**: `SSOCallbackHandler()` setelah validasi

### 2. **`sso_access_token`**
- **Purpose**: Access token dari SSO server (OAuth 2.0)
- **Set by**: `SSOCallbackHandler()` setelah token exchange
- **Expires**: Sesuai `expires_in` dari token response (default: 3600 detik = 1 jam)
- **Cleared by**: `LogoutHandler()`

### 3. **`sso_token_expires`**
- **Purpose**: Timestamp expiration untuk access token
- **Set by**: `SSOCallbackHandler()` setelah token exchange
- **Expires**: Sesuai `expires_in` dari token response
- **Cleared by**: `LogoutHandler()`

### 4. **`client_dinas_session`**
- **Purpose**: Session ID lokal di client website (untuk session management)
- **Set by**: 
  - `SSOCallbackHandler()` setelah SSO login
  - `LoginPostHandler()` setelah direct login
- **Expires**: 24 jam (86400 detik)
- **Cleared by**: `LogoutHandler()` atau saat session expired
- **PENTING**: Cookie ini berbeda dari `sso_admin_session` (cookie dari SSO server)

### 5. **`session_id`** (Backward Compatibility)
- **Purpose**: Cookie lama untuk backward compatibility
- **Set by**: `LoginPostHandler()` (direct login lama)
- **Expires**: 24 jam
- **Cleared by**: `LogoutHandler()`

### 6. **`sso_code_verifier`** (Jika menggunakan PKCE)
- **Purpose**: PKCE code verifier (saat ini tidak digunakan)
- **Set by**: Tidak digunakan saat ini
- **Cleared by**: `LogoutHandler()`

---

## 📝 Catatan Penting

### 1. **Cookie Separation**
- Client website menggunakan cookie `client_dinas_session` yang berbeda dari SSO server (`sso_admin_session`)
- Ini mencegah auto-login/logout antara dua website yang berbeda

### 2. **Session Management**
- Session dibuat di database Supabase (tabel `sesi_login`)
- Session ID disimpan di cookie `client_dinas_session`
- Session expired setelah 24 jam (kolom `kadaluarsa`)

### 3. **OAuth 2.0 Best Practices**
- Menggunakan Authorization Code Flow (tanpa PKCE saat ini)
- State parameter untuk CSRF protection
- Access token disimpan di cookie (HttpOnly, Secure di production)
- Token expiration di-handle dengan timestamp

### 4. **Database Schema**
- Tabel `pengguna`: Primary key adalah `id_pengguna` (bukan `id`)
- Tabel `sesi_login`: Kolom `id_sesi` (bukan `session_id`), `kadaluarsa` (bukan `expires_at`), `ip` (bukan `ip_address`)

### 5. **Error Handling**
- Semua error di-log untuk debugging
- User-friendly error messages di redirect ke login page
- Error dari SSO server di-forward ke user

---

## 🚀 Quick Start untuk Testing

1. **Setup Environment Variables**:
   ```bash
   export SUPABASE_URL="https://your-project.supabase.co"
   export SUPABASE_KEY="your-supabase-key"
   export SSO_CLIENT_ID="client-dinas-pendidikan"
   export SSO_SERVER_URL="http://localhost:8080"
   ```

2. **Start Server**:
   ```bash
   go run dev.go
   ```

3. **Test SSO Flow**:
   - Buka browser: `http://localhost:8070/login`
   - Klik "Login dengan SSO"
   - Login di SSO server
   - Klik "Lanjut ke Aplikasi"
   - User akan di-redirect ke dashboard

4. **Test Direct Login**:
   - Buka browser: `http://localhost:8070/login`
   - Masukkan email dan password
   - Submit form
   - User akan di-redirect ke dashboard

5. **Test Logout**:
   - Klik "Logout" di navbar
   - User akan di-redirect ke home page
   - Session akan dihapus dari database

---

## 📚 Referensi

- [OAuth 2.0 Authorization Code Flow](https://oauth.net/2/grant-types/authorization-code/)
- [Supabase REST API Documentation](https://supabase.com/docs/reference/javascript/introduction)
- [Go HTTP Server Documentation](https://pkg.go.dev/net/http)

---

**Dokumentasi ini dibuat untuk membantu memahami alur SSO di Client Website Dinas Pendidikan DKI Jakarta.**

