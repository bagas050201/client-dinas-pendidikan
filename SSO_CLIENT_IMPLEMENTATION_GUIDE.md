# Panduan Implementasi SSO Client (OAuth 2.0 Authorization Code Flow)

## 📋 Daftar Isi
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Alur Lengkap SSO Flow](#alur-lengkap-sso-flow)
4. [Step-by-Step Implementation](#step-by-step-implementation)
5. [Diagram Alur (Tabel)](#diagram-alur-tabel)
6. [Struktur Database](#struktur-database)
7. [Environment Variables](#environment-variables)
8. [Error Handling](#error-handling)
9. [Best Practices](#best-practices)

---

## Overview

Panduan ini menjelaskan implementasi SSO (Single Sign-On) dari sisi **Client Website** menggunakan **OAuth 2.0 Authorization Code Flow**. Client website akan menerima callback dari SSO server setelah user berhasil login di SSO server.

**Format Callback URL:**
```
{redirect_uri}?code={auth_code}&state={state}
```

**Contoh:**
```
https://client.com/api/callback?code=aBc123XyZ&state=xyz789
```

---

## Prerequisites

### 1. Konfigurasi di SSO Server
- Client website harus terdaftar di SSO server dengan:
  - `client_id`: Identifier unik untuk client website
  - `redirect_uri`: URL callback yang akan menerima authorization code
  - `scope`: Permissions yang diminta (biasanya: `openid profile email`)

### 2. Database Schema
Client website harus memiliki tabel:
- **`pengguna`**: Menyimpan data user
- **`sesi_login`**: Menyimpan session user

### 3. Dependencies (Go)
```go
import (
    "net/http"
    "encoding/json"
    "crypto/rand"
    "encoding/base64"
    "time"
)
```

---

## Alur Lengkap SSO Flow

### Phase 1: Initiate SSO Login
1. User mengakses client website dan klik "Login dengan SSO"
2. Client website redirect ke SSO server dengan `client_id` dan `state`
3. User login di SSO server
4. SSO server redirect kembali ke client dengan `code` dan `state`

### Phase 2: Handle Callback
5. Client website menerima callback dengan `code` dan `state`
6. Client validasi `state` (CSRF protection)
7. Client exchange `code` ke `access_token`
8. Client ambil user info dari SSO menggunakan `access_token`
9. Client cari atau buat user di database
10. Client buat session di database
11. Client set cookie session
12. Client redirect user ke dashboard/home

---

## Step-by-Step Implementation

### **STEP 1: Terima Callback dari SSO Server**

#### **Function:** `SSOCallbackHandler`
- **File:** `api/main_handler.go`
- **Method:** `GET` atau `POST`
- **Route:** `/api/callback`
- **Pengertian:** Handler utama yang menerima callback dari SSO server setelah user login

#### **Input Data:**
```json
Query Parameters:
{
  "code": "aBc123XyZ789...",      // Authorization code dari SSO
  "state": "xyz789abc...",          // State untuk CSRF protection (optional)
  "error": "",                      // Error code jika ada (optional)
  "error_description": ""           // Error message jika ada (optional)
}
```

#### **Output Data:**
- **Success:** HTTP Redirect ke `/dashboard` atau `/`
- **Error:** HTTP Redirect ke `/login?error={error_code}&message={error_message}`

#### **Proses yang Terjadi:**
1. Parse query parameters (`code`, `state`, `error`)
2. Handle error jika ada dari SSO server
3. Validasi `code` tidak kosong
4. Validasi `state` (jika ada) dengan cookie `sso_state`
5. Panggil `exchangeCodeForToken()` untuk menukar code ke token
6. Panggil `getUserInfoFromSSO()` untuk ambil user info
7. Panggil `findOrCreateUser()` untuk cari/buat user
8. Panggil `session.CreateSession()` untuk buat session
9. Set cookie `client_dinas_session`
10. Redirect ke dashboard

#### **Database yang Terlibat:**
- Tidak ada query langsung di step ini (hanya validasi)

---

### **STEP 2: Exchange Authorization Code ke Access Token**

#### **Function:** `exchangeCodeForToken`
- **File:** `api/main_handler.go`
- **Method:** `POST` (ke SSO server)
- **Pengertian:** Menukar authorization code dengan access token dari SSO server

#### **Input Data:**
```go
Parameters:
- code: string          // Authorization code dari callback
- config: SSOConfig      // Konfigurasi SSO (SSOServerURL, ClientID, RedirectURI)
```

#### **Output Data:**
```go
TokenResponse {
  AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  TokenType: "Bearer",
  ExpiresIn: 3600,        // Detik (1 jam)
  Scope: "openid profile email"
}
```

#### **Proses yang Terjadi:**
1. Build token URL: `{SSOServerURL}/oauth/token`
2. Prepare form data:
   ```
   grant_type=authorization_code
   code={code}
   redirect_uri={redirect_uri}
   client_id={client_id}
   ```
3. POST request ke SSO server dengan `Content-Type: application/x-www-form-urlencoded`
4. Parse JSON response ke `TokenResponse`
5. Validasi `access_token` tidak kosong
6. Return `TokenResponse` atau error

#### **Database yang Terlibat:**
- Tidak ada (hanya HTTP request ke SSO server)

#### **Request ke SSO Server:**
```
POST {SSOServerURL}/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=aBc123XyZ&redirect_uri=https://client.com/api/callback&client_id=client-id
```

#### **Response dari SSO Server:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email"
}
```

---

### **STEP 3: Ambil User Info dari SSO Server**

#### **Function:** `getUserInfoFromSSO`
- **File:** `api/main_handler.go`
- **Method:** `GET` (ke SSO server)
- **Pengertian:** Mengambil informasi user dari SSO server menggunakan access token

#### **Input Data:**
```go
Parameters:
- accessToken: string    // Access token dari step sebelumnya
- config: SSOConfig      // Konfigurasi SSO
```

#### **Output Data:**
```go
UserInfo {
  Sub: "11111111-1111-1111-1111-111111111111",  // User ID dari SSO
  Email: "user@example.com",
  Name: "Nama Lengkap User",
  EmailVerified: true,
  Peran: "admin",        // Role dari SSO (admin, user, dll)
  Role: "admin"          // Alternative field name
}
```

#### **Proses yang Terjadi:**
1. Build userinfo URL: `{SSOServerURL}/oauth/userinfo`
2. GET request dengan header `Authorization: Bearer {access_token}`
3. Parse JSON response ke `UserInfo`
4. **Fallback parsing** jika field tidak ditemukan:
   - Email: coba `email`, `user_email`, `mail`, atau `sub` (jika mengandung "@")
   - Name: coba `name`, `nama_lengkap`, `full_name`, `nama`
   - Peran: coba `peran`, `role`
5. **Fallback decode JWT:** Jika userinfo tidak lengkap, decode access token JWT untuk ambil claims
6. Return `UserInfo` atau error

#### **Database yang Terlibat:**
- Tidak ada (hanya HTTP request ke SSO server)

#### **Request ke SSO Server:**
```
GET {SSOServerURL}/oauth/userinfo
Authorization: Bearer {access_token}
```

#### **Response dari SSO Server:**
```json
{
  "sub": "11111111-1111-1111-1111-111111111111",
  "email": "user@example.com",
  "name": "Nama Lengkap User",
  "peran": "admin",
  "email_verified": true
}
```

---

### **STEP 4: Cari atau Buat User di Database**

#### **Function:** `findOrCreateUser`
- **File:** `api/main_handler.go`
- **Method:** `GET` dan `POST` (ke database)
- **Pengertian:** Mencari user berdasarkan email, jika tidak ada maka buat user baru

#### **Input Data:**
```go
Parameters:
- userInfo: *UserInfo   // User info dari SSO server
```

#### **Output Data:**
```go
userID: interface{}      // ID user (uuid) dari database
```

#### **Proses yang Terjadi:**

**A. Cari User (GET):**
1. Query database: `GET /rest/v1/pengguna?email=eq.{email}&select=*`
2. Jika user ditemukan:
   - Ambil `id_pengguna` (primary key)
   - Cek apakah `nama_lengkap` atau `peran` berbeda dengan SSO
   - Jika berbeda, update user (PATCH)
   - Return `id_pengguna`

**B. Buat User Baru (POST):**
1. Jika user tidak ditemukan:
   - Siapkan data user:
     ```json
     {
       "email": "user@example.com",
       "nama_lengkap": "Nama Lengkap User",
       "peran": "admin",        // Dari SSO, fallback ke "user"
       "aktif": true
     }
     ```
   - POST ke database: `POST /rest/v1/pengguna`
   - Return `id_pengguna` dari response

#### **Database yang Terlibat:**

**Tabel: `pengguna`**

**Query 1: Cari User**
```sql
SELECT * FROM pengguna WHERE email = 'user@example.com';
```

**Query 2: Update User (jika perlu)**
```sql
UPDATE pengguna 
SET nama_lengkap = 'Nama Baru', peran = 'admin'
WHERE id_pengguna = 'uuid-user-id';
```

**Query 3: Insert User Baru**
```sql
INSERT INTO pengguna (email, nama_lengkap, peran, aktif)
VALUES ('user@example.com', 'Nama Lengkap', 'admin', true);
```

---

### **STEP 5: Buat Session di Database**

#### **Function:** `session.CreateSession`
- **File:** `api/session/session_helper.go`
- **Method:** `POST` (ke database)
- **Pengertian:** Membuat session baru di database untuk user yang berhasil login

#### **Input Data:**
```go
Parameters:
- userID: interface{}    // ID user dari database
- r: *http.Request       // HTTP request untuk ambil IP dan User-Agent
```

#### **Output Data:**
```go
sessionID: string        // Session ID unik (untuk disimpan sebagai cookie)
```

#### **Proses yang Terjadi:**
1. Generate session ID unik (random string, base64 encoded)
2. Hitung expiry time: `now() + 24 hours`
3. Siapkan data session:
   ```json
   {
     "id_pengguna": "uuid-user-id",
     "id_sesi": "random-session-id",
     "ip": "192.168.1.1",
     "user_agent": "Mozilla/5.0...",
     "kadaluarsa": "2025-11-17T12:00:00Z"
   }
   ```
4. POST ke database: `POST /rest/v1/sesi_login`
5. Return `sessionID`

#### **Database yang Terlibat:**

**Tabel: `sesi_login`**

**Query: Insert Session**
```sql
INSERT INTO sesi_login (id_pengguna, id_sesi, ip, user_agent, kadaluarsa)
VALUES (
  'uuid-user-id',
  'random-session-id',
  '192.168.1.1',
  'Mozilla/5.0...',
  '2025-11-17T12:00:00Z'
);
```

---

### **STEP 6: Set Cookie dan Redirect**

#### **Function:** `SSOCallbackHandler` (lanjutan)
- **File:** `api/main_handler.go`
- **Pengertian:** Set cookie session dan redirect user ke dashboard

#### **Input Data:**
```go
- sessionID: string      // Session ID dari step sebelumnya
- tokenResponse: TokenResponse  // Token response untuk set access token cookie
```

#### **Output Data:**
- HTTP Redirect ke `/dashboard` atau `/`

#### **Proses yang Terjadi:**
1. Set cookie `client_dinas_session` dengan value `sessionID` (expires: 24 jam)
2. Set cookie `sso_access_token` dengan value `access_token` (expires: sesuai `expires_in`)
3. Set cookie `sso_token_expires` dengan value timestamp expiry (untuk validasi)
4. Clear cookie `sso_state` (sudah digunakan)
5. HTTP Redirect ke `/dashboard` atau `/`

#### **Cookie yang Diset:**
```
Set-Cookie: client_dinas_session={sessionID}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400
Set-Cookie: sso_access_token={access_token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600
Set-Cookie: sso_token_expires={timestamp}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600
```

#### **Database yang Terlibat:**
- Tidak ada (hanya set cookie)

---

## Diagram Alur (Tabel)

### **Diagram Lengkap: SSO Server ↔ Client Website**

| **Step** | **SSO Server** | **Client Website** | **Keterangan** |
|----------|---------------|-------------------|----------------|
| **1. Initiate** | | User klik "Login dengan SSO" | User memulai proses login |
| **2. Redirect** | | `SSOAuthorizeHandler()` → Redirect ke SSO | Client redirect ke SSO dengan `client_id` dan `state` |
| **3. Login** | User login di SSO server | | User memasukkan credentials di SSO |
| **4. Authorize** | SSO validasi credentials | | SSO server validasi user |
| **5. Generate Code** | SSO generate `authorization_code` | | SSO membuat code unik |
| **6. Redirect Callback** | SSO redirect ke `{redirect_uri}?code={code}&state={state}` | `SSOCallbackHandler()` menerima callback | SSO mengirim code ke client |
| **7. Validate** | | Validasi `code` dan `state` | Client validasi untuk security |
| **8. Exchange Token** | SSO menerima POST `/oauth/token` | `exchangeCodeForToken()` → POST ke SSO | Client menukar code ke token |
| **9. Return Token** | SSO return `access_token` | Menerima `TokenResponse` | SSO mengirim access token |
| **10. Get User Info** | SSO menerima GET `/oauth/userinfo` | `getUserInfoFromSSO()` → GET ke SSO | Client ambil user info |
| **11. Return User Info** | SSO return user info JSON | Menerima `UserInfo` | SSO mengirim data user |
| **12. Find/Create User** | | `findOrCreateUser()` → Query database `pengguna` | Client cari/buat user |
| **13. Create Session** | | `session.CreateSession()` → Insert ke `sesi_login` | Client buat session |
| **14. Set Cookie** | | Set cookie `client_dinas_session` | Client set session cookie |
| **15. Redirect** | | Redirect ke `/dashboard` | User berhasil login |

---

### **Diagram Detail: Callback Flow (Step 6-15)**

| **Step** | **SSO Server** | **Client Website** | **Data Flow** | **Status** |
|----------|---------------|-------------------|---------------|------------|
| **6. Receive Callback** | Redirect dengan query params | `SSOCallbackHandler()` parse query | `code=aBc123`, `state=xyz789` | ✅ Received |
| **7. Validate Code** | - | Check `code != ""` | `code` string | ✅ Valid |
| **7b. Validate State** | - | Compare `state` dengan cookie `sso_state` | `state` string | ✅ Match |
| **8. Exchange Request** | Receive POST request | `exchangeCodeForToken()` build request | `POST /oauth/token`<br>`grant_type=authorization_code`<br>`code=aBc123`<br>`redirect_uri=...`<br>`client_id=...` | 📤 Sending |
| **9. Token Response** | Return JSON response | Parse `TokenResponse` | `{access_token: "...", expires_in: 3600}` | ✅ Received |
| **10. UserInfo Request** | Receive GET request | `getUserInfoFromSSO()` build request | `GET /oauth/userinfo`<br>`Authorization: Bearer {token}` | 📤 Sending |
| **11. UserInfo Response** | Return JSON response | Parse `UserInfo` | `{sub: "...", email: "...", name: "...", peran: "admin"}` | ✅ Received |
| **12. Query User** | - | `findOrCreateUser()` query DB | `GET /rest/v1/pengguna?email=eq.{email}` | 📤 Querying |
| **12b. User Found** | - | Update user if needed | `PATCH /rest/v1/pengguna?id_pengguna=eq.{id}` | ✅ Updated |
| **12c. User Not Found** | - | Create new user | `POST /rest/v1/pengguna`<br>`{email, nama_lengkap, peran, aktif}` | ✅ Created |
| **13. Create Session** | - | `session.CreateSession()` insert DB | `POST /rest/v1/sesi_login`<br>`{id_pengguna, id_sesi, ip, user_agent, kadaluarsa}` | ✅ Created |
| **14. Set Cookies** | - | Set HTTP cookies | `Set-Cookie: client_dinas_session={id}`<br>`Set-Cookie: sso_access_token={token}` | ✅ Set |
| **15. Redirect** | - | HTTP 302 Redirect | `Location: /dashboard` | ✅ Redirected |

---

### **Diagram Detail: Function Call Sequence**

| **Order** | **Function Name** | **File Location** | **Called By** | **Calls** | **Purpose** |
|-----------|------------------|------------------|---------------|-----------|-------------|
| **1** | `SSOCallbackHandler` | `api/main_handler.go` | HTTP Router | `exchangeCodeForToken()` | Main callback handler |
| **2** | `exchangeCodeForToken` | `api/main_handler.go` | `SSOCallbackHandler` | HTTP POST to SSO | Exchange code to token |
| **3** | `getUserInfoFromSSO` | `api/main_handler.go` | `SSOCallbackHandler` | HTTP GET to SSO | Get user info |
| **4** | `findOrCreateUser` | `api/main_handler.go` | `SSOCallbackHandler` | Database queries | Find or create user |
| **5** | `session.CreateSession` | `api/session/session_helper.go` | `SSOCallbackHandler` | Database INSERT | Create session |
| **6** | `helpers.SetCookie` | `pkg/helpers/utils.go` | `SSOCallbackHandler` | HTTP Set-Cookie | Set session cookie |

---

### **Diagram Detail: Data Transformation Flow**

| **Step** | **Input Data** | **Transformation** | **Output Data** | **Storage** |
|----------|---------------|-------------------|-----------------|-------------|
| **1. Callback** | Query params: `code`, `state` | Parse URL query | `code` string, `state` string | Memory |
| **2. Exchange** | `code` + `config` | POST to SSO `/oauth/token` | `TokenResponse` {access_token, expires_in} | Memory + Cookie |
| **3. UserInfo** | `access_token` + `config` | GET to SSO `/oauth/userinfo` | `UserInfo` {sub, email, name, peran} | Memory |
| **4. Find User** | `UserInfo.Email` | Query DB `pengguna` | `userID` (uuid) | Database |
| **5. Create User** | `UserInfo` (if not found) | INSERT to DB `pengguna` | `userID` (uuid) | Database |
| **6. Create Session** | `userID` + Request | INSERT to DB `sesi_login` | `sessionID` (string) | Database + Cookie |
| **7. Set Cookie** | `sessionID` + `access_token` | HTTP Set-Cookie header | Cookie `client_dinas_session` | Browser |

---

## Struktur Database

### **Tabel: `pengguna`**

| **Kolom** | **Type** | **Primary Key** | **Keterangan** |
|-----------|----------|-----------------|----------------|
| `id_pengguna` | `uuid` | ✅ Yes | ID unik user |
| `email` | `text` | ❌ No | Email user (unique) |
| `nama_lengkap` | `text` | ❌ No | Nama lengkap user |
| `password` | `text` | ❌ No | Password hash (optional untuk SSO) |
| `peran` | `text` | ❌ No | Role user (admin, user, dll) |
| `aktif` | `bool` | ❌ No | Status aktif user |
| `created_at` | `timestamp` | ❌ No | Waktu dibuat |
| `last_login` | `timestamp` | ❌ No | Waktu login terakhir |

**Query Examples:**
```sql
-- Cari user berdasarkan email
SELECT * FROM pengguna WHERE email = 'user@example.com';

-- Update user
UPDATE pengguna 
SET nama_lengkap = 'Nama Baru', peran = 'admin'
WHERE id_pengguna = 'uuid-user-id';

-- Insert user baru
INSERT INTO pengguna (email, nama_lengkap, peran, aktif)
VALUES ('user@example.com', 'Nama Lengkap', 'admin', true)
RETURNING id_pengguna;
```

---

### **Tabel: `sesi_login`**

| **Kolom** | **Type** | **Primary Key** | **Keterangan** |
|-----------|----------|-----------------|----------------|
| `id` | `uuid` | ✅ Yes | ID unik session |
| `id_sesi` | `text` | ❌ No | Session ID (untuk cookie) |
| `id_pengguna` | `uuid` | ❌ No | Foreign key ke `pengguna` |
| `ip` | `text` | ❌ No | IP address user |
| `user_agent` | `text` | ❌ No | User agent browser |
| `created_at` | `timestamp` | ❌ No | Waktu dibuat |
| `kadaluarsa` | `timestamp` | ❌ No | Waktu expiry session |
| `aktif` | `bool` | ❌ No | Status aktif session |

**Query Examples:**
```sql
-- Insert session baru
INSERT INTO sesi_login (id_pengguna, id_sesi, ip, user_agent, kadaluarsa)
VALUES (
  'uuid-user-id',
  'random-session-id',
  '192.168.1.1',
  'Mozilla/5.0...',
  '2025-11-17T12:00:00Z'
);

-- Validasi session (untuk middleware)
SELECT id_pengguna FROM sesi_login 
WHERE id_sesi = 'session-id' 
  AND kadaluarsa > NOW() 
  AND aktif = true;
```

---

## Environment Variables

### **Required Variables:**

```bash
# SSO Configuration
SSO_SERVER_URL=https://sso-server.example.com        # URL SSO server
SSO_CLIENT_ID=client-website-id                      # Client ID dari SSO
SSO_REDIRECT_URI=https://client.com/api/callback     # Callback URL
SSO_STATE_SECRET=random-secret-string                # Secret untuk state validation (optional)

# Database Configuration
SUPABASE_URL=https://xxx.supabase.co                # Supabase project URL
SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... # Supabase anon key
```

### **Setup di Vercel/Production:**
1. Masuk ke Vercel Dashboard
2. Pilih project
3. Settings → Environment Variables
4. Tambahkan semua variable di atas
5. Redeploy aplikasi

---

## Error Handling

### **Error Codes dan Handling:**

| **Error Code** | **Keterangan** | **Handler** |
|----------------|----------------|-------------|
| `sso_error` | Error dari SSO server | Redirect ke `/login?error=sso_error&message={msg}` |
| `missing_code` | Authorization code tidak ditemukan | Redirect ke `/login?error=missing_code` |
| `state_mismatch` | State tidak cocok (CSRF) | Redirect ke `/login?error=state_mismatch` |
| `token_exchange_failed` | Gagal exchange code ke token | Redirect ke `/login?error=token_exchange_failed&message={msg}` |
| `userinfo_failed` | Gagal ambil user info | Redirect ke `/login?error=userinfo_failed&message={msg}` |
| `missing_email` | Email tidak ditemukan di user info | Redirect ke `/login?error=missing_email&message={msg}` |
| `user_creation_failed` | Gagal membuat user | Redirect ke `/login?error=user_creation_failed&message={msg}` |
| `session_creation_failed` | Gagal membuat session | Redirect ke `/login?error=session_creation_failed&message={msg}` |

### **Error Response Format:**
```
/login?error={error_code}&message={url_encoded_message}
```

---

## Best Practices

### **1. Security**
- ✅ **Selalu validasi `state`** untuk CSRF protection
- ✅ **Gunakan HTTPS** di production
- ✅ **Set cookie dengan `Secure` flag** di production
- ✅ **Set cookie dengan `HttpOnly` flag** untuk prevent XSS
- ✅ **Set cookie dengan `SameSite=Lax`** untuk prevent CSRF
- ✅ **Jangan simpan access token di database** (hanya di cookie)

### **2. Error Handling**
- ✅ **Log semua error** untuk debugging
- ✅ **Jangan expose sensitive info** di error message
- ✅ **Redirect ke login page** dengan error message yang user-friendly

### **3. Database**
- ✅ **Gunakan prepared statements** atau parameterized queries
- ✅ **Validasi input** sebelum insert/update
- ✅ **Handle duplicate email** dengan update existing user
- ✅ **Set expiry time** untuk session (24 jam recommended)

### **4. Performance**
- ✅ **Cache SSO config** jika memungkinkan
- ✅ **Timeout untuk HTTP requests** ke SSO server
- ✅ **Retry mechanism** untuk network errors (optional)

### **5. Logging**
- ✅ **Log semua step** untuk debugging
- ✅ **Log error dengan detail** (tanpa sensitive data)
- ✅ **Log user actions** untuk audit trail

---

## Contoh Implementasi Lengkap

### **1. Route Handler Setup**

```go
// api/main_handler.go
func main() {
    http.HandleFunc("/api/callback", SSOCallbackHandler)
    http.HandleFunc("/api/sso/authorize", SSOAuthorizeHandler)
    http.ListenAndServe(":8080", nil)
}
```

### **2. SSO Config Struct**

```go
type SSOConfig struct {
    SSOServerURL string
    ClientID     string
    RedirectURI  string
    StateSecret  string
}

func getSSOConfig() SSOConfig {
    return SSOConfig{
        SSOServerURL: os.Getenv("SSO_SERVER_URL"),
        ClientID:     os.Getenv("SSO_CLIENT_ID"),
        RedirectURI:  os.Getenv("SSO_REDIRECT_URI"),
        StateSecret:  os.Getenv("SSO_STATE_SECRET"),
    }
}
```

### **3. Callback Handler Skeleton**

```go
func SSOCallbackHandler(w http.ResponseWriter, r *http.Request) {
    // 1. Parse query parameters
    code := r.URL.Query().Get("code")
    state := r.URL.Query().Get("state")
    
    // 2. Validate code
    if code == "" {
        http.Redirect(w, r, "/login?error=missing_code", http.StatusSeeOther)
        return
    }
    
    // 3. Validate state
    // ... (implementasi validasi state)
    
    // 4. Exchange code to token
    config := getSSOConfig()
    tokenResponse, err := exchangeCodeForToken(code, config)
    if err != nil {
        // Handle error
        return
    }
    
    // 5. Get user info
    userInfo, err := getUserInfoFromSSO(tokenResponse.AccessToken, config)
    if err != nil {
        // Handle error
        return
    }
    
    // 6. Find or create user
    userID, err := findOrCreateUser(userInfo)
    if err != nil {
        // Handle error
        return
    }
    
    // 7. Create session
    sessionID, err := session.CreateSession(userID, r)
    if err != nil {
        // Handle error
        return
    }
    
    // 8. Set cookie and redirect
    helpers.SetCookie(w, r, "client_session", sessionID, 86400)
    http.Redirect(w, r, "/dashboard", http.StatusFound)
}
```

---

## Testing

### **1. Test Callback Handler**
```bash
# Test dengan curl
curl "http://localhost:8080/api/callback?code=test123&state=xyz789"
```

### **2. Test Token Exchange**
```bash
# Test exchange code (harus dari SSO server yang valid)
curl -X POST "https://sso-server.com/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=test123&redirect_uri=https://client.com/api/callback&client_id=client-id"
```

### **3. Test User Info**
```bash
# Test get user info
curl "https://sso-server.com/oauth/userinfo" \
  -H "Authorization: Bearer {access_token}"
```

---

## Troubleshooting

### **Problem: "Email tidak ditemukan"**
**Solution:**
- Pastikan SSO server mengembalikan field `email` di `/oauth/userinfo`
- Implementasi fallback parsing di `getUserInfoFromSSO()`
- Cek log untuk melihat field apa saja yang dikembalikan SSO

### **Problem: "State mismatch"**
**Solution:**
- Pastikan cookie `sso_state` diset saat initiate SSO
- Pastikan cookie tidak expired (10 menit default)
- Pastikan domain cookie sama antara initiate dan callback

### **Problem: "Token exchange failed"**
**Solution:**
- Pastikan `SSO_SERVER_URL` benar
- Pastikan `SSO_REDIRECT_URI` sama dengan yang terdaftar di SSO server
- Pastikan `SSO_CLIENT_ID` benar
- Cek log untuk melihat response error dari SSO server

### **Problem: "Session tidak dibuat"**
**Solution:**
- Pastikan database connection OK
- Pastikan schema `sesi_login` benar
- Cek log untuk melihat error dari database
- Pastikan `SUPABASE_URL` dan `SUPABASE_KEY` benar

---

## Kesimpulan

Panduan ini menjelaskan implementasi SSO client secara lengkap dari menerima callback hingga user berhasil login. Semua step sudah dijelaskan dengan detail termasuk:
- Function yang terlibat
- Input/output data
- Proses yang terjadi
- Database yang terlibat
- Error handling
- Best practices

Dengan mengikuti panduan ini, website manapun bisa mengimplementasikan SSO client dengan mudah.

---

**Last Updated:** November 2025  
**Version:** 1.0  
**Author:** SSO Implementation Guide

