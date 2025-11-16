# Setup SSO Integration - Client Website

Dokumentasi ini menjelaskan setup SSO integration untuk client website menggunakan pola baru yang lebih sederhana.

## ✅ Yang Sudah Diimplementasikan

### 1. Endpoint Callback (`/api/callback`)
- ✅ Sudah ada di `api/ui_sso.go` - `SSOCallbackHandler`
- ✅ Menerima `code` dari query parameter
- ✅ Exchange code ke token
- ✅ Simpan token di cookie (`sso_access_token`)
- Redirect ke dashboard

### 2. Router Setup
- ✅ Sudah ada di `api/main_handler.go`
- ✅ Route `/api/callback` → `SSOCallbackHandler`
- ✅ Route `/sso/authorize` → `SSOAuthorizeHandler`
- ✅ Route `/login` → `LoginPageHandler` (dengan tombol SSO)

### 3. Halaman Login dengan Tombol SSO
- ✅ Sudah ada di `api/main_handler.go` - `renderLoginPage`
- ✅ Tombol "Login dengan SSO" yang redirect ke `/sso/authorize`

### 4. Middleware Auth
- ✅ Sudah ada di `api/middleware_auth.go` - `RequireAuth`
- ✅ Cek access token dari cookie
- ✅ Cek token expiration
- ✅ Support session fallback untuk direct login

### 5. Dashboard Handler
- ✅ Sudah ada di `api/ui_dashboard.go` - `DashboardHandler`
- ✅ Protected dengan `RequireAuth` middleware
- ✅ Menampilkan user info dari session

## 🔧 Konfigurasi

### Environment Variables

```bash
# SSO Server URL (default: production)
SSO_SERVER_URL=https://sso-dinas-pendidikan.vercel.app
# Untuk development:
# SSO_SERVER_URL=http://localhost:8080

# Callback URL (auto-detect jika tidak di-set)
SSO_REDIRECT_URI=https://client-dinas-pendidikan.vercel.app/api/callback
# Untuk development:
# SSO_REDIRECT_URI=http://localhost:8070/api/callback

# Client ID
SSO_CLIENT_ID=client-dinas-pendidikan
```

### Auto-Detection

Kode akan auto-detect environment:
- Jika `SSO_SERVER_URL` mengandung `localhost` → gunakan `http://` dan callback `http://localhost:8070/api/callback`
- Jika tidak → gunakan `https://` dan callback `https://client-dinas-pendidikan.vercel.app/api/callback`

## 📋 Flow Lengkap

1. **User klik "Login dengan SSO"**
   - Redirect ke: `https://sso-dinas-pendidikan.vercel.app/apps/access?client_id=client-dinas-pendidikan`

2. **User login di SSO**
   - User input credentials di SSO server
   - SSO server validasi credentials

3. **SSO redirect ke callback**
   - Redirect ke: `https://client-dinas-pendidikan.vercel.app/api/callback?code=ABC123...`

4. **Client exchange code ke token**
   - POST ke: `https://sso-dinas-pendidikan.vercel.app/api/token`
   - Body: `grant_type=authorization_code&code=ABC123&redirect_uri=...&client_id=...`
   - Response: `{"access_token": "...", "token_type": "Bearer", "expires_in": 3600}`

5. **Client simpan token**
   - Set cookie: `sso_access_token` (expires sesuai `expires_in`)
   - Set cookie: `sso_token_expires` (timestamp expiration)

6. **Client ambil user info (opsional)**
   - GET: `https://sso-dinas-pendidikan.vercel.app/api/userinfo`
   - Header: `Authorization: Bearer <access_token>`
   - Response: `{"sub": "...", "email": "...", "name": "..."}`

7. **Client buat session lokal**
   - Cari atau buat user di database berdasarkan email
   - Buat session di tabel `sesi_login`
   - Set cookie: `sso_admin_session`

8. **Redirect ke dashboard**
   - User sudah login ✅

## 🔍 Testing

### Development
```bash
# Set environment variables
export SSO_SERVER_URL=http://localhost:8080
export SSO_REDIRECT_URI=http://localhost:8070/api/callback

# Run server
go run dev.go
```

### Production
```bash
# Set di Vercel environment variables
SSO_SERVER_URL=https://sso-dinas-pendidikan.vercel.app
SSO_REDIRECT_URI=https://client-dinas-pendidikan.vercel.app/api/callback
SSO_CLIENT_ID=client-dinas-pendidikan
```

## 📝 Catatan

- **Tidak menggunakan PKCE**: Sistem SSO baru lebih sederhana, tidak memerlukan PKCE
- **State validation**: Optional, untuk CSRF protection
- **Token storage**: Menggunakan HTTP-only cookies (lebih aman dari localStorage)
- **Session fallback**: Support direct login (email/password) sebagai fallback

## 🐛 Troubleshooting

### Error: "token_exchange_failed"
- Cek SSO server logs
- Pastikan `redirect_uri` sama dengan yang di-register di SSO
- Pastikan `client_id` benar

### Error: "column pengguna.id does not exist"
- Pastikan menggunakan `id_pengguna` bukan `id` (sudah diperbaiki)

### Redirect loop
- Pastikan `RequireAuth` middleware tidak redirect jika sudah ada token/session valid
- Clear cookies dan coba lagi

## ✅ Checklist

- [x] Endpoint `/api/callback` sudah ada
- [x] Router sudah setup
- [x] Halaman login dengan tombol SSO
- [x] Middleware auth untuk protect routes
- [x] Dashboard handler
- [x] Auto-detect environment (dev/prod)
- [x] Token storage di cookie
- [x] Session management
- [x] Error handling
- [x] Logging untuk debugging

## 🎉 Selesai!

Client website sudah siap untuk integrasi dengan SSO server yang baru!

