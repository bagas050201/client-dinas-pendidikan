# 🎯 SSO Simple - Panduan Implementasi untuk Client Website

## ✅ Overview

Website client menggunakan **SSO Simple** yang lebih mudah dan sederhana. Website SSO mengirim token langsung ke client, dan client hanya perlu decode token untuk mendapatkan user info **TANPA perlu call API ke Keycloak**.

## 📋 Yang Dikirim dari Portal SSO

Ketika user klik aplikasi di Portal SSO, website client akan menerima URL:

```
http://localhost:8070/?sso_token=<access_token>&sso_id_token=<id_token>
```

**Hanya 2 parameter:**
- `sso_token` = access token (opsional, untuk verify token jika diperlukan)
- `sso_id_token` = ID token (berisi user info lengkap) **← PRIORITAS UTAMA**

## 🔧 Implementasi di Backend (Go)

### 1. Handler di Root Path (`/`)

Backend sudah handle `sso_token` dan `sso_id_token` di root path:

```go
// Prioritas: sso_id_token > sso_token
if ssoIdToken != "" || ssoToken != "" {
    // Process sso_id_token dulu (karena sudah berisi user info)
    if ssoIdToken != "" {
        success = handleSSOTokenWithCookie(w, r, ssoIdToken)
    }
    
    // Jika sso_id_token gagal, coba sso_token sebagai fallback
    if !success && ssoToken != "" {
        success = handleSSOTokenWithCookie(w, r, ssoToken)
    }
    
    if success {
        http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
    }
}
```

### 2. Handler di Login Page (`/login`)

Backend juga handle token di login page untuk kompatibilitas:

```go
// Prioritas: sso_id_token > sso_token
if ssoIdToken != "" || ssoToken != "" {
    // Process sso_id_token dulu
    if ssoIdToken != "" {
        success = handleSSOTokenWithCookie(w, r, ssoIdToken)
    }
    
    // Fallback ke sso_token
    if !success && ssoToken != "" {
        success = handleSSOTokenWithCookie(w, r, ssoToken)
    }
}
```

### 3. Decode JWT Token

Fungsi `handleSSOTokenWithCookie` akan:
1. Decode JWT token (dengan atau tanpa signature validation)
2. Extract email dari claims: `email`, `preferred_username`, atau `sub` (jika seperti email)
3. Create session dengan email tersebut
4. Set cookie `client_dinas_session`

```go
func handleSSOTokenWithCookie(w http.ResponseWriter, r *http.Request, token string) bool {
    // Decode JWT token
    parsedToken, err := jwt.Parse(token, ...)
    
    // Extract claims
    claims := parsedToken.Claims.(jwt.MapClaims)
    
    // Extract email dari claims
    email := claims["email"].(string)
    
    // Create session
    sessionID, ok := createSessionFromEmail(r, email)
    
    // Set cookie
    helpers.SetCookie(w, r, "client_dinas_session", sessionID, 86400)
    return true
}
```

## 🎯 Cara Kerja

1. **User klik aplikasi di Portal SSO**
   - Portal SSO mengirim URL dengan `sso_token` dan `sso_id_token`

2. **Backend terima token**
   - Backend detect `sso_id_token` dan `sso_token` di URL
   - Prioritas: `sso_id_token` diproses terlebih dahulu

3. **Decode ID token untuk dapat user info**
   - Backend decode JWT token untuk extract claims
   - Extract email dari claims: `email`, `preferred_username`, atau `sub`
   - **TANPA perlu call API ke Keycloak**

4. **Auto-login user**
   - Cari user di database berdasarkan email
   - Create session di database
   - Set cookie `client_dinas_session`
   - Redirect ke dashboard

## 📝 User Info dari ID Token

ID token sudah berisi semua info yang diperlukan:

```json
{
  "sub": "user-id",
  "email": "admin@dinas-pendidikan.go.id",
  "name": "Administrator Sistem",
  "preferred_username": "admin",
  "email_verified": true,
  "given_name": "Administrator",
  "family_name": "Sistem",
  // ... dan lainnya
}
```

**Tidak perlu call API lagi!**

## ✅ Keuntungan SSO Simple

- ✅ **Lebih cepat** - Tidak ada network call ke Keycloak
- ✅ **Lebih sederhana** - Hanya decode JWT token
- ✅ **Lebih reliable** - Tidak bergantung pada ketersediaan Keycloak API
- ✅ **Lebih aman** - Token langsung dari SSO, tidak perlu verify lagi

## 🔐 Security

### 1. JWT Token Validation

Backend support 2 mode:

**Development Mode (tanpa signature validation):**
- Jika `JWT_PUBLIC_KEY` tidak di-set
- Token didecode tanpa validasi signature
- Cocok untuk development/testing

**Production Mode (dengan signature validation):**
- Jika `JWT_PUBLIC_KEY` di-set
- Token divalidasi dengan RSA public key
- Lebih aman untuk production

### 2. Cookie Security

- Cookie name: `client_dinas_session` (berbeda dari SSO server)
- HttpOnly: true (tidak bisa diakses dari JavaScript)
- MaxAge: 86400 (24 jam)
- Path: `/`

## 🛠️ Environment Variables

```bash
# Optional: JWT Public Key untuk signature validation
# Jika tidak di-set, token akan didecode tanpa validasi (development mode)
JWT_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----

# Required: Supabase untuk database
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key
```

## 📋 Checklist Implementasi

- [x] Backend handle `sso_token` dan `sso_id_token` di root path (`/`)
- [x] Backend handle `sso_token` dan `sso_id_token` di login page (`/login`)
- [x] Prioritas: `sso_id_token` > `sso_token`
- [x] Decode JWT token untuk extract email
- [x] Create session dengan email
- [x] Set cookie `client_dinas_session`
- [x] Redirect ke dashboard setelah login berhasil

## 🆘 Troubleshooting

### 1. Token tidak bisa di-decode

**Error:** `ERROR parsing SSO token`

**Solusi:**
- Pastikan token format JWT yang benar (3 bagian dipisah titik)
- Cek log backend untuk detail error
- Jika `JWT_PUBLIC_KEY` di-set tapi format salah, sistem akan otomatis fallback ke decode tanpa validasi

### 2. Email tidak ditemukan di claims

**Error:** `ERROR: Email not found in token claims`

**Solusi:**
- Cek log backend untuk melihat semua claims yang tersedia
- Pastikan ID token berisi claim `email`, `preferred_username`, atau `sub` (jika seperti email)
- Update Keycloak client configuration untuk include email di ID token

### 3. User tidak ditemukan di database

**Error:** `WARNING: User with email ... not found in database`

**Solusi:**
- Pastikan user sudah ada di database dengan email yang sesuai
- Atau implementasikan auto-create user jika belum ada

### 4. Session tidak dibuat

**Error:** `ERROR creating session`

**Solusi:**
- Cek koneksi ke Supabase
- Pastikan `SUPABASE_URL` dan `SUPABASE_KEY` sudah di-set dengan benar
- Cek log backend untuk detail error dari Supabase

## 📚 File yang Terlibat

```
api/
  ├── main_handler.go          # Handler untuk root path dan login page
  │   ├── Handler()            # Root path handler
  │   ├── LoginPageHandler()    # Login page handler
  │   └── handleSSOTokenWithCookie()  # Decode token dan create session
  └── session/
      └── session_helper.go     # Session management
```

## 🎯 Flow Diagram

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
         │                            │  4. Cari user by email    │
         │                            ├───────────────────────────>│
         │                            │                            │
         │                            │  5. Create session         │
         │                            ├───────────────────────────>│
         │                            │                            │
         │  6. Redirect ke dashboard  │                            │
         │<───────────────────────────┤                            │
         │                            │                            │
```

## 📝 Catatan Penting

1. **Prioritas Token:**
   - `sso_id_token` diproses terlebih dahulu (karena sudah berisi user info)
   - `sso_token` digunakan sebagai fallback jika `sso_id_token` gagal

2. **Tidak Perlu Call API:**
   - User info langsung dari ID token claims
   - Tidak perlu call `/userinfo` endpoint ke Keycloak

3. **User Harus Ada di Database:**
   - Pastikan user sudah ada di database dengan email yang sesuai
   - Email dari token akan digunakan untuk mencari user

4. **Development vs Production:**
   - Development: Token didecode tanpa signature validation (jika `JWT_PUBLIC_KEY` tidak di-set)
   - Production: Token divalidasi dengan RSA public key (jika `JWT_PUBLIC_KEY` di-set)

---

**TL;DR:**
1. Portal SSO mengirim `sso_token` dan `sso_id_token` ke client
2. Backend decode `sso_id_token` untuk dapat user info (tanpa call API)
3. Extract email dari claims
4. Create session dengan email
5. Redirect ke dashboard

**Total: Hanya decode JWT token, tidak perlu call API!**

