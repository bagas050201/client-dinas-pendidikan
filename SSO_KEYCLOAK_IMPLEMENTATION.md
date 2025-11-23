# SSO Keycloak Implementation Guide

## 📋 Overview

Implementasi SSO Keycloak untuk website client agar user yang sudah login di Portal SSO bisa **auto-login** ke website tanpa perlu login ulang.

## 📁 File Structure

Semua kode SSO Keycloak ada di lokasi berikut untuk memudahkan pencarian:

```
client-dinas-pendidikan/
├── api/
│   ├── main_handler.go              # Backend handlers (SSO section di line ~3643)
│   └── static/
│       └── sso-handler.js            # Frontend JavaScript handler
└── SSO_KEYCLOAK_IMPLEMENTATION.md   # Dokumentasi ini
```

## 🔧 Konfigurasi

### 1. Register Client di Keycloak

Minta admin Keycloak untuk register client dengan:
- **Client ID**: `client-dapodik` (atau sesuai nama aplikasi)
- **Valid redirect URIs**: `https://dapodik.dinas-pendidikan.go.id/*`
- **Web origins**: `https://dapodik.dinas-pendidikan.go.id`
- **Client authentication**: OFF (Public client)
- **Standard flow**: ON
- **PKCE Code Challenge Method**: S256

### 2. Update Client ID di Kode

**File: `api/static/sso-handler.js`** (line 12)
```javascript
const SSO_CONFIG = {
    keycloakBaseUrl: 'https://sso.dinas-pendidikan.go.id',
    realm: 'dinas-pendidikan',
    clientId: 'client-dapodik' // GANTI dengan client ID aplikasi Anda
};
```

**File: `api/main_handler.go`** (line ~4463)
```javascript
const clientId = 'client-dapodik'; // GANTI dengan client ID aplikasi Anda
```

## 📥 Format URL yang Diterima

Ketika user klik aplikasi di Portal SSO, website akan menerima URL dengan format:

```
https://dapodik.dinas-pendidikan.go.id/?sso_token=<access_token>&sso_id_token=<id_token>&sso_client_id=client-dapodik
```

**Parameter:**
- `sso_token`: Access token JWT dari Keycloak (untuk verify user)
- `sso_id_token`: ID token JWT dari Keycloak (berisi info user: email, name, dll)
- `sso_client_id`: Client ID aplikasi di Keycloak

## 🔄 Flow SSO Login

### 1. User Klik Aplikasi di Portal SSO
Portal SSO redirect ke website dengan URL: `/?sso_token=...&sso_id_token=...&sso_client_id=...`

### 2. Root Path Handler (`/`)
- Check SSO token dari URL parameter
- Jika ada, redirect ke `/login` dengan parameter SSO
- **File**: `api/main_handler.go` (line ~83)

### 3. Login Page Handler (`/login`)
- Include `sso-handler.js` script
- Script akan check SSO token dari URL saat page load
- **File**: `api/main_handler.go` (line ~211, ~4445)

### 4. Frontend: `sso-handler.js`
- **`handleSSO()`**: Check token dari URL parameter
- **`verifyToken(accessToken)`**: Verify token dengan Keycloak userinfo endpoint
- **`autoLogin(userInfo, accessToken, idToken)`**: Auto-login user ke aplikasi
- **`checkOrCreateUser(userData, accessToken)`**: Check atau create user di database
- **`createAppSession(user, accessToken)`**: Create session aplikasi
- **File**: `api/static/sso-handler.js`

### 5. Backend API Endpoints

#### `POST /api/users/sso-login`
- Check atau create user di database
- **Handler**: `handleSSOUserLoginAPI()` di `api/main_handler.go` (line ~3643)
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "name": "User Name",
    "keycloak_id": "user-id-from-keycloak"
  }
  ```
- **Headers**: `Authorization: Bearer <sso_access_token>`
- **Response**:
  ```json
  {
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "name": "User Name",
      "keycloak_id": "user-id-from-keycloak"
    }
  }
  ```

#### `POST /api/auth/sso-login`
- Create session aplikasi setelah SSO login
- **Handler**: `handleSSOAuthLoginAPI()` di `api/main_handler.go` (line ~3840)
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "keycloak_id": "user-id-from-keycloak"
  }
  ```
- **Headers**: `Authorization: Bearer <sso_access_token>`
- **Response**:
  ```json
  {
    "session_token": "session-id",
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "name": "User Name"
    }
  }
  ```

## 🎯 Lokasi Kode (Mudah Dicari)

### Backend Handlers
- **SSO User Login API**: `api/main_handler.go` line ~3643 (`handleSSOUserLoginAPI`)
- **SSO Auth Login API**: `api/main_handler.go` line ~3840 (`handleSSOAuthLoginAPI`)
- **Root Path Handler**: `api/main_handler.go` line ~83 (check SSO token)
- **Login Page Handler**: `api/main_handler.go` line ~211 (include script)
- **Static File Handler**: `api/main_handler.go` line ~67 (serve JavaScript)

### Frontend JavaScript
- **SSO Handler**: `api/static/sso-handler.js` (semua fungsi SSO)
- **Login Page Script**: `api/main_handler.go` line ~4445 (include script + button)

## 🔐 Security

1. **Selalu verify token** dengan Keycloak sebelum auto-login
2. **HTTPS wajib** untuk production
3. **Simpan token di sessionStorage** (bukan localStorage)
4. **Handle token expiry** dengan refresh atau re-login
5. **Clear session** saat logout

## ✅ Checklist Implementasi

- [x] File `api/static/sso-handler.js` dibuat
- [x] Handler serve static file JavaScript
- [x] Endpoint `POST /api/users/sso-login` 
- [x] Endpoint `POST /api/auth/sso-login`
- [x] Login page include `sso-handler.js`
- [x] Button "Login dengan SSO" di login page
- [x] Root path handler untuk SSO token dari URL
- [ ] Register client di Keycloak
- [ ] Update `clientId` di `sso-handler.js` dan `main_handler.go`
- [ ] Test flow dari Portal SSO
- [ ] Test flow langsung akses website

## 🧪 Testing

### Test dari Portal SSO
1. Login ke Portal SSO
2. Klik aplikasi (contoh: Dapodik)
3. Website akan redirect dengan SSO token
4. User akan auto-login ke website

### Test Manual
1. Akses website: `https://dapodik.dinas-pendidikan.go.id/`
2. Klik "Login dengan SSO Dinas Pendidikan"
3. Redirect ke Keycloak untuk login
4. Setelah login, redirect kembali ke website
5. User akan auto-login

## 📚 Referensi

- Keycloak URL: `https://sso.dinas-pendidikan.go.id`
- Realm: `dinas-pendidikan`
- Userinfo Endpoint: `https://sso.dinas-pendidikan.go.id/realms/dinas-pendidikan/protocol/openid-connect/userinfo`

## 🐛 Troubleshooting

### Token tidak valid
- Check apakah token sudah expired
- Verify token dengan Keycloak userinfo endpoint
- Check console browser untuk error message

### User tidak ditemukan
- Check apakah email sudah terdaftar di database
- Check log backend untuk error create user
- Verify request body format

### Session tidak dibuat
- Check apakah endpoint `/api/auth/sso-login` berhasil
- Check cookie `client_dinas_session` di browser
- Check log backend untuk error create session

---

**Semua kode SSO Keycloak ada di section yang jelas dan mudah dicari di `api/main_handler.go` (line ~3643 untuk handlers) dan `api/static/sso-handler.js` untuk frontend.**

