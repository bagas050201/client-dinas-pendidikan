# Panduan Implementasi SSO Client (Keycloak Authorization Code Flow)

> ⚠️ **CATATAN:** Panduan ini untuk **versi lama** (Authorization Code Flow dengan PKCE).  
> Website client sekarang menggunakan **SSO Simple** yang lebih mudah.  
> 📖 **Lihat [SSO_SIMPLE_GUIDE.md](./SSO_SIMPLE_GUIDE.md) untuk panduan versi terbaru.**

---

## 📋 Daftar Isi
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Alur Lengkap SSO Flow](#alur-lengkap-sso-flow)
4. [Step-by-Step Implementation](#step-by-step-implementation)
5. [Frontend Implementation (JavaScript)](#frontend-implementation-javascript)
6. [Backend Implementation (Go)](#backend-implementation-go)
7. [Diagram Alur (Tabel)](#diagram-alur-tabel)
8. [Struktur Database](#struktur-database)
9. [Keycloak Client Configuration](#keycloak-client-configuration)
10. [Error Handling](#error-handling)
11. [Best Practices](#best-practices)

---

## Overview (Legacy)

Panduan ini menjelaskan implementasi SSO (Single Sign-On) dari sisi **Client Website** menggunakan **OAuth 2.0 Authorization Code Flow** dengan Keycloak. Client website akan menerima callback dari Portal SSO (yang menggunakan Keycloak) setelah user berhasil login.

**⚠️ Versi ini sudah tidak digunakan. Gunakan SSO Simple sebagai gantinya.**

**Format Callback URL:**
```
{redirect_uri}?code={authorization_code}&state={state_token}
```

**Contoh:**
```
http://localhost:8070/?code=aBc123XyZ789&state=xyz789abc
```

**Flow:**
1. User klik aplikasi di Portal SSO
2. Portal SSO redirect ke Keycloak dengan `redirect_uri` ke website client
3. Keycloak check session user
4. Keycloak redirect ke website client dengan `code` dan `state`
5. Website client exchange `code` untuk token
6. Website client verify token dan auto-login user

---

## Prerequisites

### 1. Register Client di Keycloak

Minta admin Keycloak untuk register client dengan:

- **Client ID**: `localhost-8070-website-dinas-pendidikan` (atau sesuai nama aplikasi)
- **Valid redirect URIs**: `http://localhost:8070/*` (development) atau `https://client.dinas-pendidikan.go.id/*` (production)
- **Web origins**: `http://localhost:8070` (development) atau `https://client.dinas-pendidikan.go.id` (production)
- **Client authentication**: OFF (Public client)
- **Standard flow**: ON
- **PKCE Code Challenge Method**: `S256` atau `Not required` (jika Portal SSO tidak support PKCE)
- **Root URL**: `http://localhost:8070` (development) atau `https://client.dinas-pendidikan.go.id` (production)
- **Home URL**: `http://localhost:8070/dashboard` (optional)

### 2. Database Schema

Client website harus memiliki tabel:

- **`pengguna`**: Menyimpan data user
  - `id_pengguna` (uuid, primary key)
  - `email` (text, unique)
  - `nama_lengkap` (text)
  - `peran` (text: admin, user, dll)
  - `aktif` (bool)
  - `created_at` (timestamp)

- **`sesi_login`**: Menyimpan session user
  - `id` (uuid, primary key)
  - `id_sesi` (text, unique)
  - `id_pengguna` (uuid, foreign key)
  - `ip` (text)
  - `user_agent` (text)
  - `kadaluarsa` (timestamptz)
  - `created_at` (timestamp)

### 3. Dependencies

**Go:**
```go
import (
    "net/http"
    "encoding/json"
    "time"
    "crypto/rand"
    "encoding/base64"
)
```

**JavaScript:**
- Native browser APIs (crypto, fetch, sessionStorage, localStorage)
- Tidak perlu library eksternal

---

## Alur Lengkap SSO Flow

### Phase 1: User Klik Aplikasi di Portal SSO
1. User login di Portal SSO
2. User klik aplikasi di Portal SSO
3. Portal SSO redirect ke Keycloak dengan `redirect_uri` ke website client
4. Keycloak check session user (jika sudah login, langsung lanjut)
5. Keycloak redirect ke website client dengan `code` dan `state`

### Phase 2: Website Client Handle Callback
6. Website client menerima callback dengan `code` dan `state` di URL
7. Frontend (`sso-handler.js`) detect `code` di URL
8. Frontend verify `state` (CSRF protection)
9. Frontend exchange `code` untuk `access_token` via Keycloak token endpoint
10. Frontend verify token via Keycloak userinfo endpoint
11. Frontend extract user info (email, name, peran, dll)
12. Frontend call backend API `/api/users/sso-login` untuk check/create user
13. Frontend call backend API `/api/auth/sso-login` untuk create session
14. Backend set cookies (`client_dinas_session`, `sso_access_token`, dll)
15. Frontend redirect ke dashboard

---

## Step-by-Step Implementation

### **STEP 1: Terima Callback dari Portal SSO (Keycloak)**

#### **Function:** `handleSSOCallback()` (Frontend)
- **File:** `static/sso-handler.js` atau `api/static/sso-handler.js`
- **Method:** Auto-execute saat page load
- **Pengertian:** Handler utama yang menerima callback dari Keycloak setelah user login

#### **Input Data:**
```javascript
URL Query Parameters:
{
  "code": "aBc123XyZ789...",      // Authorization code dari Keycloak
  "state": "xyz789abc...",          // State untuk CSRF protection
  "error": "",                      // Error code jika ada (optional)
  "error_description": ""           // Error message jika ada (optional)
}
```

#### **Output Data:**
- **Success:** Auto-login dan redirect ke `/dashboard`
- **Error:** Alert error message dan tampilkan form login

#### **Proses yang Terjadi:**
1. Parse query parameters dari URL (`code`, `state`, `error`)
2. Handle error jika ada dari Keycloak
3. Verify `state` dengan `sessionStorage.getItem('oauth_state')`
4. Jika `code` ada, panggil `exchangeCodeForToken(code)`
5. Jika token exchange berhasil, panggil `verifyToken(accessToken)`
6. Jika token verified, panggil `autoLogin(userInfo, accessToken, idToken)`
7. Hapus `code` dan `state` dari URL (security)

#### **Database yang Terlibat:**
- Tidak ada query langsung di step ini (hanya validasi)

---

### **STEP 2: Exchange Authorization Code untuk Access Token**

#### **Function:** `exchangeCodeForToken(code)` (Frontend)
- **File:** `static/sso-handler.js`
- **Method:** `POST` (ke Keycloak)
- **Pengertian:** Menukar authorization code dengan access token dari Keycloak

#### **Input Data:**
```javascript
Parameters:
- code: string          // Authorization code dari callback
- code_verifier: string // PKCE code verifier (optional, jika PKCE digunakan)
```

#### **Output Data:**
```javascript
{
  access_token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  token_type: "Bearer",
  expires_in: 3600,        // Detik (1 jam)
  refresh_token: "...",    // Optional
  id_token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...", // Optional
  scope: "openid email profile"
}
```

#### **Proses yang Terjadi:**
1. Build token URL: `{keycloakBaseUrl}/realms/{realm}/protocol/openid-connect/token`
2. Get `code_verifier` dari `sessionStorage` (jika PKCE digunakan)
3. Prepare form data:
   ```
   grant_type=authorization_code
   code={code}
   redirect_uri={redirect_uri}
   client_id={client_id}
   code_verifier={code_verifier}  // Optional, jika PKCE
   ```
4. POST request ke Keycloak dengan `Content-Type: application/x-www-form-urlencoded`
5. Parse JSON response
6. Return token data atau null jika error

#### **Database yang Terlibat:**
- Tidak ada (hanya HTTP request ke Keycloak)

#### **Request ke Keycloak:**
```
POST {keycloakBaseUrl}/realms/{realm}/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=aBc123XyZ&redirect_uri=http://localhost:8070&client_id=localhost-8070-website-dinas-pendidikan&code_verifier=... (optional)
```

#### **Response dari Keycloak:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "...",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "openid email profile"
}
```

---

### **STEP 3: Verify Token dan Ambil User Info**

#### **Function:** `verifyToken(accessToken)` (Frontend)
- **File:** `static/sso-handler.js`
- **Method:** `GET` (ke Keycloak)
- **Pengertian:** Verify access token dan ambil informasi user dari Keycloak

#### **Input Data:**
```javascript
Parameters:
- accessToken: string    // Access token dari step sebelumnya
```

#### **Output Data:**
```javascript
{
  id_user: "ef4ab147-68a4-4f3e-800c-53c13319728b",  // sub dari Keycloak (ID user)
  email: "user@example.com",
  name: "Nama Lengkap User",
  preferred_username: "username",
  email_verified: true,
  peran: "admin"        // Role dari Keycloak (admin, user, dll)
}
```

#### **Proses yang Terjadi:**
1. Build userinfo URL: `{keycloakBaseUrl}/realms/{realm}/protocol/openid-connect/userinfo`
2. GET request dengan header `Authorization: Bearer {access_token}`
3. Parse JSON response
4. Transform user info: ubah `sub` menjadi `id_user`
5. Extract peran/role jika ada
6. Return transformed user info atau null jika error

#### **Database yang Terlibat:**
- Tidak ada (hanya HTTP request ke Keycloak)

#### **Request ke Keycloak:**
```
GET {keycloakBaseUrl}/realms/{realm}/protocol/openid-connect/userinfo
Authorization: Bearer {access_token}
```

#### **Response dari Keycloak:**
```json
{
  "sub": "ef4ab147-68a4-4f3e-800c-53c13319728b",
  "email": "user@example.com",
  "name": "Nama Lengkap User",
  "preferred_username": "username",
  "email_verified": true,
  "peran": "admin"
}
```

---

### **STEP 4: Auto-Login User**

#### **Function:** `autoLogin(userInfo, accessToken, idToken)` (Frontend)
- **File:** `static/sso-handler.js`
- **Pengertian:** Auto-login user ke aplikasi setelah token verified

#### **Input Data:**
```javascript
Parameters:
- userInfo: object       // User info dari verifyToken()
- accessToken: string    // Access token dari exchangeCodeForToken()
- idToken: string        // ID token (optional)
```

#### **Output Data:**
- Redirect ke `/dashboard` atau halaman yang diminta

#### **Proses yang Terjadi:**
1. Simpan token di `sessionStorage`:
   - `sso_access_token`: access token
   - `sso_id_token`: ID token (jika ada)
   - `sso_user_info`: user info (JSON string)
2. Prepare user data untuk backend
3. Panggil `checkOrCreateUser(userData, accessToken)` untuk check/create user
4. Panggil `createAppSession(user, accessToken)` untuk create session
5. Redirect ke dashboard atau halaman yang diminta
6. Hapus `code` dan `state` dari URL

#### **Database yang Terlibat:**
- Tidak ada query langsung (hanya call backend API)

---

### **STEP 5: Check atau Create User di Database**

#### **Function:** `checkOrCreateUser(userData, accessToken)` (Frontend)
- **File:** `static/sso-handler.js`
- **Method:** `POST` (ke backend API)
- **Endpoint:** `/api/users/sso-login`
- **Pengertian:** Check user berdasarkan email, jika tidak ada maka buat user baru

#### **Input Data:**
```javascript
POST /api/users/sso-login
Headers:
  Authorization: Bearer {accessToken}
  Content-Type: application/json

Body:
{
  "email": "user@example.com",
  "name": "Nama Lengkap User",
  "keycloak_id": "ef4ab147-68a4-4f3e-800c-53c13319728b"
}
```

#### **Output Data:**
```javascript
{
  "success": true,
  "user": {
    "id_pengguna": "uuid-user-id",
    "email": "user@example.com",
    "nama_lengkap": "Nama Lengkap User",
    "peran": "admin"
  }
}
```

#### **Proses yang Terjadi (Backend):**
1. Backend validasi access token (optional, bisa skip untuk public client)
2. Query database: `GET /rest/v1/pengguna?email=eq.{email}&select=*`
3. Jika user ditemukan:
   - Ambil `id_pengguna`
   - Update user jika `nama_lengkap` atau `peran` berbeda
   - Return user data
4. Jika user tidak ditemukan:
   - Insert user baru: `POST /rest/v1/pengguna`
   - Return user data

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
VALUES ('user@example.com', 'Nama Lengkap', 'admin', true)
RETURNING id_pengguna;
```

---

### **STEP 6: Create Session Aplikasi**

#### **Function:** `createAppSession(user, accessToken)` (Frontend)
- **File:** `static/sso-handler.js`
- **Method:** `POST` (ke backend API)
- **Endpoint:** `/api/auth/sso-login`
- **Pengertian:** Membuat session aplikasi di database dan set cookies

#### **Input Data:**
```javascript
POST /api/auth/sso-login
Headers:
  Authorization: Bearer {accessToken}
  Content-Type: application/json

Body:
{
  "email": "user@example.com",
  "keycloak_id": "ef4ab147-68a4-4f3e-800c-53c13319728b"
}
```

#### **Output Data:**
```javascript
{
  "success": true,
  "session_token": "random-session-id",  // Optional, untuk localStorage
  "user": {
    "id_pengguna": "uuid-user-id",
    "email": "user@example.com",
    "nama_lengkap": "Nama Lengkap User"
  }
}
```

#### **Proses yang Terjadi (Backend):**
1. Backend validasi access token (optional)
2. Query user berdasarkan email: `GET /rest/v1/pengguna?email=eq.{email}&select=id_pengguna`
3. Generate session ID unik (random string, base64 encoded)
4. Hitung expiry time: `now() + 24 hours`
5. Insert session: `POST /rest/v1/sesi_login`
6. Set cookies:
   - `client_dinas_session`: session ID (expires: 24 jam)
   - `sso_access_token`: access token (expires: sesuai `expires_in`)
   - `sso_token_expires`: timestamp expiry
7. Return session data

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

## Frontend Implementation (JavaScript)

### **File: `static/sso-handler.js`**

Semua fungsi SSO ada di satu file untuk memudahkan pencarian:

#### **1. Konfigurasi Keycloak**

```javascript
// Auto-detect Keycloak URL berdasarkan environment
function getKeycloakBaseUrl() {
    const hostname = window.location.hostname;
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
        return 'http://localhost:8080'; // Local Keycloak
    }
    return 'https://sso.dinas-pendidikan.go.id'; // Production Keycloak
}

const SSO_CONFIG = {
    keycloakBaseUrl: getKeycloakBaseUrl(),
    realm: 'dinas-pendidikan',
    clientId: 'localhost-8070-website-dinas-pendidikan', // GANTI dengan client ID aplikasi
    redirectUri: window.location.origin // Keycloak redirect ke root
};
```

#### **2. Fungsi Utama: `handleSSOCallback()`**

```javascript
async function handleSSOCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    const error = urlParams.get('error');

    // Handle error dari Keycloak
    if (error) {
        alert(`Error dari SSO: ${error}. Silakan coba lagi.`);
        return;
    }

    // Jika ada code, exchange untuk token
    if (code) {
        // Verify state (CSRF protection)
        const storedState = sessionStorage.getItem('oauth_state');
        if (state && storedState && state !== storedState) {
            alert('State tidak valid. Silakan coba lagi.');
            return;
        }

        // Exchange code untuk token
        const tokenData = await exchangeCodeForToken(code);
        if (tokenData && tokenData.access_token) {
            // Verify token dan get user info
            const userInfo = await verifyToken(tokenData.access_token);
            if (userInfo) {
                await autoLogin(userInfo, tokenData.access_token, tokenData.id_token);
            }
        }
    }
}
```

#### **3. Fungsi: `exchangeCodeForToken(code)`**

```javascript
async function exchangeCodeForToken(code) {
    const tokenUrl = `${SSO_CONFIG.keycloakBaseUrl}/realms/${SSO_CONFIG.realm}/protocol/openid-connect/token`;
    
    // Get code_verifier dari sessionStorage (untuk PKCE, optional)
    const codeVerifier = sessionStorage.getItem('oauth_code_verifier');
    
    const params = {
        grant_type: 'authorization_code',
        client_id: SSO_CONFIG.clientId,
        code: code,
        redirect_uri: SSO_CONFIG.redirectUri
    };
    
    // Tambahkan code_verifier jika ada (PKCE)
    if (codeVerifier) {
        params.code_verifier = codeVerifier;
    }
    
    const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams(params)
    });

    if (response.ok) {
        return await response.json();
    }
    return null;
}
```

#### **4. Fungsi: `verifyToken(accessToken)`**

```javascript
async function verifyToken(accessToken) {
    const userinfoUrl = `${SSO_CONFIG.keycloakBaseUrl}/realms/${SSO_CONFIG.realm}/protocol/openid-connect/userinfo`;
    
    const response = await fetch(userinfoUrl, {
        headers: {
            'Authorization': `Bearer ${accessToken}`
        }
    });

    if (response.ok) {
        const userInfo = await response.json();
        
        // Transform: ubah 'sub' menjadi 'id_user'
        return {
            id_user: userInfo.sub,
            email: userInfo.email,
            name: userInfo.name || userInfo.preferred_username || userInfo.email,
            preferred_username: userInfo.preferred_username || userInfo.email,
            email_verified: userInfo.email_verified || false,
            peran: userInfo.peran || userInfo.role || 'user'
        };
    }
    return null;
}
```

#### **5. Fungsi: `autoLogin(userInfo, accessToken, idToken)`**

```javascript
async function autoLogin(userInfo, accessToken, idToken) {
    // Simpan token di sessionStorage
    sessionStorage.setItem('sso_access_token', accessToken);
    if (idToken) {
        sessionStorage.setItem('sso_id_token', idToken);
    }
    sessionStorage.setItem('sso_user_info', JSON.stringify(userInfo));

    // Prepare user data
    const userData = {
        id: userInfo.id_user || userInfo.sub,
        email: userInfo.email,
        name: userInfo.name,
        username: userInfo.preferred_username || userInfo.email
    };

    // Check atau create user
    const user = await checkOrCreateUser(userData, accessToken);
    if (!user) {
        alert('Gagal membuat atau menemukan user.');
        return;
    }

    // Create session
    const sessionResult = await createAppSession(user, accessToken);
    if (!sessionResult) {
        alert('Gagal membuat session.');
        return;
    }

    // Redirect ke dashboard
    const redirectUrl = sessionStorage.getItem('redirect_after_login') || '/dashboard';
    sessionStorage.removeItem('redirect_after_login');
    sessionStorage.removeItem('oauth_state');
    sessionStorage.removeItem('oauth_code_verifier');
    
    window.location.href = redirectUrl;
}
```

#### **6. Fungsi: `checkOrCreateUser(userData, accessToken)`**

```javascript
async function checkOrCreateUser(userData, accessToken) {
    const response = await fetch('/api/users/sso-login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`
        },
        body: JSON.stringify({
            email: userData.email,
            name: userData.name,
            keycloak_id: userData.id
        })
    });

    if (response.ok) {
        const result = await response.json();
        return result.user;
    }
    return null;
}
```

#### **7. Fungsi: `createAppSession(user, accessToken)`**

```javascript
async function createAppSession(user, accessToken) {
    const response = await fetch('/api/auth/sso-login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`
        },
        body: JSON.stringify({
            email: user.email,
            keycloak_id: user.keycloak_id || user.id
        })
    });

    if (response.ok) {
        const data = await response.json();
        if (data.session_token) {
            localStorage.setItem('app_session_token', data.session_token);
        }
        return data;
    }
    return null;
}
```

#### **8. Fungsi: `redirectToKeycloak()` (Optional - untuk direct login)**

```javascript
function redirectToKeycloak() {
    // Simpan URL saat ini
    sessionStorage.setItem('redirect_after_login', window.location.pathname);
    
    // Generate state untuk CSRF protection
    const state = generateRandomString(32);
    sessionStorage.setItem('oauth_state', state);
    
    // Generate PKCE (optional)
    const codeVerifier = generateRandomString(128);
    sessionStorage.setItem('oauth_code_verifier', codeVerifier);
    
    generateCodeChallenge(codeVerifier).then(codeChallenge => {
        const authParams = new URLSearchParams({
            client_id: SSO_CONFIG.clientId,
            redirect_uri: SSO_CONFIG.redirectUri,
            response_type: 'code',
            scope: 'openid email profile',
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });
        
        const authUrl = `${SSO_CONFIG.keycloakBaseUrl}/realms/${SSO_CONFIG.realm}/protocol/openid-connect/auth?${authParams.toString()}`;
        window.location.href = authUrl;
    });
}
```

#### **9. Fungsi: `generateCodeChallenge(codeVerifier)` (PKCE)**

```javascript
async function generateCodeChallenge(codeVerifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const base64 = btoa(String.fromCharCode(...hashArray));
    const base64url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    return base64url;
}
```

#### **10. Initialize saat Page Load**

```javascript
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 SSO Handler initialized (Authorization Code Flow)');
    handleSSOCallback();
});
```

---

## Backend Implementation (Go)

### **File: `api/main_handler.go`**

#### **1. Handler untuk Root Path (Menerima Callback)**

```go
case "/", "/home":
    // Check SSO callback dari Keycloak (Authorization Code Flow)
    code := r.URL.Query().Get("code")
    state := r.URL.Query().Get("state")
    errorParam := r.URL.Query().Get("error")

    // Jika ada authorization code, redirect ke login dengan query parameters
    if code != "" || state != "" || errorParam != "" {
        queryString := r.URL.RawQuery
        if queryString != "" {
            redirectURL := "/login?" + queryString
            http.Redirect(w, r, redirectURL, http.StatusSeeOther)
            return
        }
    }

    // Check if authenticated
    if !isAuthenticated(r) {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    renderHomePage(w, r)
```

#### **2. Handler untuk Login Page**

```go
case "/login":
    if r.Method == "POST" {
        LoginPostHandler(w, r)
    } else {
        LoginPageHandler(w, r) // Include sso-handler.js di halaman login
    }
    return
```

#### **3. API Endpoint: `/api/users/sso-login`**

```go
case path == "/api/users/sso-login" && method == "POST":
    handleSSOUserLoginAPI(w, r)
```

**Function: `handleSSOUserLoginAPI`**
- **Input:** `{email, name, keycloak_id}`
- **Process:** Check user di database, create jika tidak ada
- **Output:** `{success: true, user: {...}}`

#### **4. API Endpoint: `/api/auth/sso-login`**

```go
case path == "/api/auth/sso-login" && method == "POST":
    handleSSOAuthLoginAPI(w, r)
```

**Function: `handleSSOAuthLoginAPI`**
- **Input:** `{email, keycloak_id}`
- **Process:** Create session di database, set cookies
- **Output:** `{success: true, session_token: "...", user: {...}}`

---

## Diagram Alur (Tabel)

### **Diagram Lengkap: Portal SSO ↔ Keycloak ↔ Client Website**

| **Step** | **Portal SSO** | **Keycloak** | **Client Website** | **Keterangan** |
|----------|---------------|--------------|-------------------|----------------|
| **1. Initiate** | User klik aplikasi | | | User memulai proses login |
| **2. Redirect** | Redirect ke Keycloak dengan `redirect_uri` | | | Portal SSO redirect ke Keycloak |
| **3. Check Session** | | Check user session | | Keycloak check apakah user sudah login |
| **4. Login (jika perlu)** | | User login di Keycloak | | Jika belum login, user login di Keycloak |
| **5. Generate Code** | | Generate `authorization_code` | | Keycloak membuat code unik |
| **6. Redirect Callback** | | Redirect ke `{redirect_uri}?code={code}&state={state}` | `handleSSOCallback()` menerima callback | Keycloak mengirim code ke client |
| **7. Validate** | | | Validasi `code` dan `state` | Client validasi untuk security |
| **8. Exchange Token** | | Menerima POST `/protocol/openid-connect/token` | `exchangeCodeForToken()` → POST ke Keycloak | Client menukar code ke token |
| **9. Return Token** | | Return `access_token` | Menerima `TokenResponse` | Keycloak mengirim access token |
| **10. Get User Info** | | Menerima GET `/protocol/openid-connect/userinfo` | `verifyToken()` → GET ke Keycloak | Client ambil user info |
| **11. Return User Info** | | Return user info JSON | Menerima `UserInfo` | Keycloak mengirim data user |
| **12. Find/Create User** | | | `checkOrCreateUser()` → POST `/api/users/sso-login` | Client cari/buat user |
| **13. Create Session** | | | `createAppSession()` → POST `/api/auth/sso-login` | Client buat session |
| **14. Set Cookie** | | | Backend set cookie `client_dinas_session` | Client set session cookie |
| **15. Redirect** | | | Redirect ke `/dashboard` | User berhasil login |

---

### **Diagram Detail: Callback Flow (Step 6-15)**

| **Step** | **Keycloak** | **Client Website** | **Data Flow** | **Status** |
|----------|--------------|-------------------|---------------|------------|
| **6. Receive Callback** | Redirect dengan query params | `handleSSOCallback()` parse query | `code=aBc123`, `state=xyz789` | ✅ Received |
| **7. Validate Code** | - | Check `code != ""` | `code` string | ✅ Valid |
| **7b. Validate State** | - | Compare `state` dengan `sessionStorage.oauth_state` | `state` string | ✅ Match |
| **8. Exchange Request** | Receive POST request | `exchangeCodeForToken()` build request | `POST /protocol/openid-connect/token`<br>`grant_type=authorization_code`<br>`code=aBc123`<br>`redirect_uri=...`<br>`client_id=...`<br>`code_verifier=...` (optional) | 📤 Sending |
| **9. Token Response** | Return JSON response | Parse `TokenResponse` | `{access_token: "...", expires_in: 3600, id_token: "..."}` | ✅ Received |
| **10. UserInfo Request** | Receive GET request | `verifyToken()` build request | `GET /protocol/openid-connect/userinfo`<br>`Authorization: Bearer {token}` | 📤 Sending |
| **11. UserInfo Response** | Return JSON response | Parse `UserInfo` | `{sub: "...", email: "...", name: "...", peran: "admin"}` | ✅ Received |
| **12. Query User** | - | `checkOrCreateUser()` → POST `/api/users/sso-login` | `POST /api/users/sso-login`<br>`{email, name, keycloak_id}` | 📤 Requesting |
| **12b. User Found** | - | Backend query DB `pengguna` | `GET /rest/v1/pengguna?email=eq.{email}` | ✅ Found |
| **12c. User Not Found** | - | Backend create user | `POST /rest/v1/pengguna`<br>`{email, nama_lengkap, peran, aktif}` | ✅ Created |
| **13. Create Session** | - | `createAppSession()` → POST `/api/auth/sso-login` | `POST /api/auth/sso-login`<br>`{email, keycloak_id}` | 📤 Requesting |
| **13b. Insert Session** | - | Backend insert DB `sesi_login` | `POST /rest/v1/sesi_login`<br>`{id_pengguna, id_sesi, ip, user_agent, kadaluarsa}` | ✅ Created |
| **14. Set Cookies** | - | Backend set HTTP cookies | `Set-Cookie: client_dinas_session={id}`<br>`Set-Cookie: sso_access_token={token}`<br>`Set-Cookie: sso_token_expires={timestamp}` | ✅ Set |
| **15. Redirect** | - | Frontend redirect | `window.location.href = '/dashboard'` | ✅ Redirected |

---

### **Diagram Detail: Function Call Sequence**

| **Order** | **Function Name** | **File Location** | **Called By** | **Calls** | **Purpose** |
|-----------|------------------|------------------|---------------|-----------|-------------|
| **1** | `handleSSOCallback` | `static/sso-handler.js` | `DOMContentLoaded` | `exchangeCodeForToken()` | Main callback handler |
| **2** | `exchangeCodeForToken` | `static/sso-handler.js` | `handleSSOCallback` | HTTP POST to Keycloak | Exchange code to token |
| **3** | `verifyToken` | `static/sso-handler.js` | `handleSSOCallback` | HTTP GET to Keycloak | Verify token and get user info |
| **4** | `autoLogin` | `static/sso-handler.js` | `handleSSOCallback` | `checkOrCreateUser()`, `createAppSession()` | Auto-login user |
| **5** | `checkOrCreateUser` | `static/sso-handler.js` | `autoLogin` | HTTP POST to `/api/users/sso-login` | Check or create user |
| **6** | `handleSSOUserLoginAPI` | `api/main_handler.go` | HTTP Router | Database queries | Backend: find/create user |
| **7** | `createAppSession` | `static/sso-handler.js` | `autoLogin` | HTTP POST to `/api/auth/sso-login` | Create session |
| **8** | `handleSSOAuthLoginAPI` | `api/main_handler.go` | HTTP Router | `session.CreateSession()`, `helpers.SetCookie()` | Backend: create session and set cookies |

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
| `id_sesi` | `text` | ❌ No | Session ID (untuk cookie, unique) |
| `id_pengguna` | `uuid` | ❌ No | Foreign key ke `pengguna` |
| `ip` | `text` | ❌ No | IP address user |
| `user_agent` | `text` | ❌ No | User agent browser |
| `created_at` | `timestamp` | ❌ No | Waktu dibuat |
| `kadaluarsa` | `timestamptz` | ❌ No | Waktu expiry session |

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
  AND kadaluarsa > NOW();
```

---

## Keycloak Client Configuration

### **Setting yang Diperlukan:**

#### **1. General Settings**
- **Client ID**: `localhost-8070-website-dinas-pendidikan` (atau sesuai nama aplikasi)
- **Name**: Nama aplikasi (optional)
- **Description**: Deskripsi aplikasi (optional)
- **Always display in UI**: ON (optional)

#### **2. Access Settings**
- **Root URL**: `http://localhost:8070` (development) atau `https://client.dinas-pendidikan.go.id` (production)
- **Home URL**: `http://localhost:8070/dashboard` (optional)
- **Valid redirect URIs**: `http://localhost:8070/*` (development) atau `https://client.dinas-pendidikan.go.id/*` (production)
- **Valid post logout redirect URIs**: `http://localhost:8070/*` (optional)
- **Web origins**: `http://localhost:8070` (development) atau `https://client.dinas-pendidikan.go.id` (production)
- **Admin URL**: `http://localhost:8070` (optional)

#### **3. Capability Config**
- **Client authentication**: OFF (Public client)
- **Authorization**: OFF
- **Standard flow**: ON ✅
- **Direct access grants**: ON (optional)
- **Implicit flow**: OFF
- **Service accounts roles**: OFF
- **OAuth 2.0 Device Authorization Grant**: ON (optional)
- **OIDC CIBA Grant**: OFF

#### **4. Advanced Settings**
- **Proof Key for Code Exchange Code Challenge Method**: 
  - `S256` (jika Portal SSO support PKCE)
  - `Not required` (jika Portal SSO tidak support PKCE) ✅ **RECOMMENDED**
- **Access Token Lifespan**: Inherits from realm settings (default: 5 minutes)
- **Client Token Idle**: Inherits from realm settings
- **Client Token Max**: Inherits from realm settings

#### **5. Login Settings**
- **Login theme**: Choose... (optional)
- **Consent required**: OFF
- **Display client on screen**: OFF

#### **6. Logout Settings**
- **Front channel logout**: ON
- **Front-channel logout URL**: `http://localhost:8070/logout` (optional)
- **Backchannel logout**: OFF (optional)
- **Backchannel logout session required**: ON (optional)

---

## Error Handling

### **Error Codes dan Handling:**

| **Error Code** | **Keterangan** | **Handler** |
|----------------|----------------|-------------|
| `invalid_request` | Request tidak valid (missing parameter) | Alert error message |
| `missing_code` | Authorization code tidak ditemukan | Alert "Gagal menukar authorization code" |
| `state_mismatch` | State tidak cocok (CSRF) | Alert "State tidak valid" |
| `token_exchange_failed` | Gagal exchange code ke token | Alert "Gagal menukar authorization code" |
| `token_verification_failed` | Gagal verify token | Alert "Gagal memverifikasi token" |
| `user_creation_failed` | Gagal membuat user | Alert "Gagal membuat atau menemukan user" |
| `session_creation_failed` | Gagal membuat session | Alert "Gagal membuat session" |

### **Error Response Format:**
```javascript
// Frontend: Alert message
alert('Error dari SSO: {error_description}. Silakan coba lagi.');

// URL: (jika redirect)
/login?error={error_code}&error_description={url_encoded_message}
```

---

## Best Practices

### **1. Security**
- ✅ **Selalu validasi `state`** untuk CSRF protection
- ✅ **Gunakan HTTPS** di production
- ✅ **Set cookie dengan `Secure` flag** di production (auto-detect)
- ✅ **Set cookie dengan `HttpOnly` flag** untuk prevent XSS
- ✅ **Set cookie dengan `SameSite=Lax`** untuk prevent CSRF
- ✅ **Jangan simpan access token di database** (hanya di cookie)
- ✅ **Clear localStorage saat logout** (termasuk `app_session_token`)

### **2. Error Handling**
- ✅ **Log semua error** untuk debugging
- ✅ **Jangan expose sensitive info** di error message
- ✅ **Alert error message** yang user-friendly
- ✅ **Hapus query parameters dari URL** setelah processing (security)

### **3. Database**
- ✅ **Gunakan prepared statements** atau parameterized queries
- ✅ **Validasi input** sebelum insert/update
- ✅ **Handle duplicate email** dengan update existing user
- ✅ **Set expiry time** untuk session (24 jam recommended)

### **4. Performance**
- ✅ **Auto-detect Keycloak URL** berdasarkan environment
- ✅ **Timeout untuk HTTP requests** ke Keycloak
- ✅ **Cache SSO config** jika memungkinkan

### **5. Logging**
- ✅ **Log semua step** untuk debugging
- ✅ **Log error dengan detail** (tanpa sensitive data)
- ✅ **Log Keycloak URL** yang digunakan (untuk debugging)

### **6. Code Organization**
- ✅ **Semua fungsi SSO di satu file** (`sso-handler.js`) untuk mudah dicari
- ✅ **Backend API endpoints** di `api/main_handler.go` dengan prefix `/api/`
- ✅ **Gunakan naming convention** yang konsisten

---

## File Structure

```
client-website/
├── api/
│   ├── main_handler.go              # Backend handlers
│   │   ├── Handler()                # Main router (line ~56)
│   │   ├── handleSSOUserLoginAPI()  # POST /api/users/sso-login (line ~4046)
│   │   └── handleSSOAuthLoginAPI()  # POST /api/auth/sso-login (line ~4223)
│   └── static/
│       └── sso-handler.js            # Frontend JavaScript handler (SEMUA FUNGSI SSO DI SINI)
├── static/
│   └── sso-handler.js                # Copy dari api/static/sso-handler.js
├── internal/
│   └── session_helper.go             # Session helper functions
└── SSO_CLIENT_IMPLEMENTATION_GUIDE.md  # Dokumentasi ini
```

---

## Quick Start Checklist

### **1. Register Client di Keycloak**
- [ ] Buat client baru di Keycloak
- [ ] Set Client ID sesuai aplikasi
- [ ] Set Valid redirect URIs: `http://localhost:8070/*` (dev) atau `https://client.dinas-pendidikan.go.id/*` (prod)
- [ ] Set Web origins: `http://localhost:8070` (dev) atau `https://client.dinas-pendidikan.go.id` (prod)
- [ ] Set Client authentication: OFF
- [ ] Set Standard flow: ON
- [ ] Set PKCE: `Not required` (jika Portal SSO tidak support PKCE)

### **2. Copy File `sso-handler.js`**
- [ ] Copy `sso-handler.js` ke `static/sso-handler.js` atau `api/static/sso-handler.js`
- [ ] Update `SSO_CONFIG.clientId` dengan Client ID dari Keycloak
- [ ] Pastikan `redirectUri` sesuai dengan Keycloak setting

### **3. Update Backend Handler**
- [ ] Update handler di root (`/`) untuk handle `code` dan `state` parameter
- [ ] Implementasi `handleSSOUserLoginAPI()` untuk `/api/users/sso-login`
- [ ] Implementasi `handleSSOAuthLoginAPI()` untuk `/api/auth/sso-login`

### **4. Update Login Page**
- [ ] Include `sso-handler.js` di halaman login: `<script src="/static/sso-handler.js"></script>`
- [ ] Pastikan `sso-handler.js` di-load sebelum `handleSSOCallback()` dipanggil

### **5. Test Flow**
- [ ] Test dari Portal SSO: klik aplikasi → seharusnya auto-login
- [ ] Test direct login: klik button SSO → redirect ke Keycloak → login → callback
- [ ] Test error handling: invalid code, expired token, dll

---

## Troubleshooting

### **Problem: "Missing parameter: code_challenge_method"**
**Solution:**
- Update Keycloak client setting: Set "Proof Key for Code Exchange Code Challenge Method" ke `Not required`
- Atau pastikan Portal SSO mengirim `code_challenge` dan `code_challenge_method` saat redirect ke Keycloak

### **Problem: "ERR_NAME_NOT_RESOLVED" saat exchange token**
**Solution:**
- Pastikan `keycloakBaseUrl` benar (auto-detect sudah handle ini)
- Untuk development: pastikan Keycloak di `localhost:8080` sudah running
- Untuk production: pastikan `https://sso.dinas-pendidikan.go.id` accessible

### **Problem: "Email tidak ditemukan"**
**Solution:**
- Pastikan Keycloak userinfo endpoint mengembalikan field `email`
- Cek log untuk melihat field apa saja yang dikembalikan Keycloak
- Implementasi fallback parsing di `verifyToken()` (sudah ada)

### **Problem: "State mismatch"**
**Solution:**
- Pastikan `state` disimpan di `sessionStorage` saat initiate SSO
- Pastikan `state` tidak expired (clear setelah login berhasil)
- Pastikan Portal SSO mengirim `state` yang sama dengan yang disimpan

### **Problem: "Token exchange failed"**
**Solution:**
- Pastikan `redirect_uri` sama dengan yang terdaftar di Keycloak
- Pastikan `client_id` benar
- Pastikan `code` masih valid (tidak expired, biasanya 1-5 menit)
- Jika PKCE required: pastikan `code_verifier` ada di `sessionStorage`

### **Problem: "Session tidak dibuat"**
**Solution:**
- Pastikan database connection OK
- Pastikan schema `sesi_login` benar
- Cek log untuk melihat error dari database
- Pastikan `SUPABASE_URL` dan `SUPABASE_KEY` benar

---

## Kesimpulan

Panduan ini menjelaskan implementasi SSO client secara lengkap menggunakan **Keycloak Authorization Code Flow**. Semua fungsi sudah dijelaskan dengan detail termasuk:

- ✅ Function yang terlibat (frontend dan backend)
- ✅ Input/output data (JSON examples)
- ✅ Proses yang terjadi
- ✅ Database yang terlibat
- ✅ Error handling
- ✅ Best practices
- ✅ Keycloak configuration
- ✅ File structure

**Semua fungsi SSO ada di satu file (`sso-handler.js`)** untuk memudahkan pencarian dan maintenance.

Dengan mengikuti panduan ini, website manapun bisa mengimplementasikan SSO client dengan mudah.

---

**Last Updated:** November 2025  
**Version:** 2.0 (Authorization Code Flow dengan PKCE Support)  
**Author:** SSO Implementation Guide
