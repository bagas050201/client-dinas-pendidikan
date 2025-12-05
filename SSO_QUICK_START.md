# 🚀 Quick Start: Integrasi SSO untuk Website Baru

> **Ringkasan Cepat**: Panduan singkat untuk menghubungkan website Anda dengan SSO Dinas Pendidikan dalam 10 langkah.

---

## 📝 Overview

Dengan mengintegrasikan SSO, website Anda akan:
- ✅ Otomatis login user dari Portal SSO
- ✅ Sinkronisasi data user dari database pusat
- ✅ Logout terpusat (logout di 1 aplikasi = logout di semua aplikasi)

---

## ⚡ 10 Langkah Implementasi

### 1️⃣ Minta Admin Keycloak Buatkan Client

Hubungi admin Keycloak dan minta dibuatkan client dengan spesifikasi:

```
Client ID: nama-website-anda  (contoh: ppdb-dinas-pendidikan)
Client Type: OpenID Connect
Client Authentication: OFF (Public Client)
Standard Flow: ON
Valid Redirect URIs: https://website-anda.com/callback
                     https://website-anda.com/oauth/callback
                     https://website-anda.com/*
Web Origins: https://website-anda.com
```

---

### 2️⃣ Setup Database

Buat 2 tabel penting:

**Tabel User:**
```sql
CREATE TABLE pengguna (
    id_pengguna UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    nama_lengkap TEXT NOT NULL,
    peran TEXT DEFAULT 'user',
    aktif BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Tabel Session:**
```sql
CREATE TABLE sesi_login (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    id_pengguna UUID REFERENCES pengguna(id_pengguna),
    id_sesi TEXT UNIQUE NOT NULL,
    ip TEXT,
    user_agent TEXT,
    kadaluarsa TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

### 3️⃣ Konfigurasi Environment

Buat file `.env`:

```env
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=dinas-pendidikan
KEYCLOAK_CLIENT_ID=nama-website-anda
KEYCLOAK_REDIRECT_URI=https://website-anda.com/callback

POSTGRES_HOST=localhost
POSTGRES_PORT=5433
POSTGRES_DB=nama_database
POSTGRES_USER=postgres
POSTGRES_PASSWORD=***
```

---

### 4️⃣ Copy Helper Function

Download dan copy file:
- `keycloak_helpers.go` → Helper untuk integrasi Keycloak
- `session/session.go` → Helper untuk session management

Atau lihat contoh lengkap di folder `api/` pada repository ini.

---

### 5️⃣ Tambahkan Routing

Di file `main_handler.go` atau `router.go`:

```go
func Handler(w http.ResponseWriter, r *http.Request) {
    path := r.URL.Path

    switch path {
    case "/":
        // Auto-redirect to Keycloak if not authenticated
        if !isAuthenticated(r) {
            redirectToKeycloakLogin(w, r, true)
            return
        }
        renderHomePage(w, r)

    case "/callback", "/oauth/callback":
        // Handle OAuth callback
        handleOAuthCallback(w, r)
        return

    case "/sso/authorize":
        // Manual SSO login trigger
        redirectToKeycloakLogin(w, r, false)
        return

    case "/logout":
        // Centralized logout
        LogoutHandler(w, r)
        return

    // ... routes lainnya
    }
}
```

---

### 6️⃣ Tambahkan Tombol "Login dengan SSO"

Di halaman login HTML:

```html
<!-- Form Login Biasa -->
<form method="POST" action="/login">
    <input type="email" name="email" required>
    <input type="password" name="password" required>
    <button type="submit">Masuk</button>
</form>

<!-- Divider -->
<div style="text-align: center; margin: 20px 0;">
    <hr>
    <span>atau</span>
</div>

<!-- Tombol SSO -->
<a href="/sso/authorize" class="btn-sso">
    <svg><!-- Icon SSO --></svg>
    Login dengan SSO
</a>
```

**CSS untuk tombol SSO:**
```css
.btn-sso {
    width: 100%;
    padding: 14px;
    background: linear-gradient(135deg, #4f46e5 0%, #4338ca 100%);
    color: white;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    text-decoration: none;
}

.btn-sso:hover {
    background: linear-gradient(135deg, #4338ca 0%, #3730a3 100%);
    transform: translateY(-2px);
}
```

---

### 7️⃣ Implementasi Callback Handler

```go
func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
    // 1. Get code dan state dari query params
    code := r.URL.Query().Get("code")
    state := r.URL.Query().Get("state")

    // 2. Verify state (CSRF protection)
    storedState, _ := helpers.GetCookie(r, "oauth_state")
    if state != storedState {
        http.Error(w, "Invalid state", http.StatusBadRequest)
        return
    }

    // 3. Exchange code untuk access token
    tokenData, err := exchangeKeycloakCode(w, r, code)
    if err != nil {
        http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
        return
    }

    // 4. Get user info dari ID token
    userInfo, err := getUserInfoFromIDToken(tokenData.IDToken)
    if err != nil {
        http.Error(w, "Failed to get user info", http.StatusInternalServerError)
        return
    }

    // 5. Get email
    email := userInfo["email"].(string)

    // 6. Create session
    sessionID := createSessionFromEmail(r, email)

    // 7. Set cookies
    helpers.SetCookie(w, r, "app_session", sessionID, 86400)
    helpers.SetCookie(w, r, "sso_access_token", tokenData.AccessToken, 86400)

    // 8. Redirect to dashboard
    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
```

---

### 8️⃣ Implementasi Session Creation

```go
func createSessionFromEmail(r *http.Request, email string) string {
    db, _ := connectPostgreSQL()
    defer db.Close()

    // Get user by email
    var userID string
    db.QueryRow("SELECT id_pengguna FROM pengguna WHERE email = $1", email).Scan(&userID)

    // Generate session ID
    sessionID, _ := helpers.GenerateSessionID()
    expiresAt := time.Now().Add(24 * time.Hour)

    // Insert session
    db.Exec(`INSERT INTO sesi_login (id_pengguna, id_sesi, ip, user_agent, kadaluarsa) 
             VALUES ($1, $2, $3, $4, $5)`,
        userID, sessionID, r.RemoteAddr, r.Header.Get("User-Agent"), expiresAt)

    return sessionID
}
```

---

### 9️⃣ Implementasi Logout Handler

```go
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
    // Get session and tokens
    sessionID, _ := helpers.GetCookie(r, "app_session")
    idToken, _ := helpers.GetCookie(r, "sso_id_token")

    // Delete session dari database
    if sessionID != "" {
        db, _ := connectPostgreSQL()
        db.Exec("DELETE FROM sesi_login WHERE id_sesi = $1", sessionID)
        db.Close()
    }

    // Clear cookies
    helpers.ClearCookie(w, r, "app_session")
    helpers.ClearCookie(w, r, "sso_access_token")
    helpers.ClearCookie(w, r, "sso_id_token")

    // Centralized logout ke Keycloak
    keycloakBaseURL := os.Getenv("KEYCLOAK_BASE_URL")
    realm := os.Getenv("KEYCLOAK_REALM")
    
    logoutURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout?id_token_hint=%s&post_logout_redirect_uri=%s",
        keycloakBaseURL, realm, idToken, "https://website-anda.com")

    http.Redirect(w, r, logoutURL, http.StatusSeeOther)
}
```

---

### 🔟 Display User Data

```go
func DashboardHandler(w http.ResponseWriter, r *http.Request) {
    // Get user dari session
    sessionID, _ := helpers.GetCookie(r, "app_session")
    
    db, _ := connectPostgreSQL()
    defer db.Close()

    var nama, email, peran string
    query := `SELECT p.nama_lengkap, p.email, p.peran 
              FROM pengguna p 
              INNER JOIN sesi_login s ON s.id_pengguna = p.id_pengguna
              WHERE s.id_sesi = $1 AND s.kadaluarsa > NOW()`
    
    db.QueryRow(query, sessionID).Scan(&nama, &email, &peran)

    // Render dashboard dengan data user
    renderDashboard(w, nama, email, peran)
}
```

---

## ✅ Testing Checklist

Setelah implementasi, test hal berikut:

- [ ] **SSO Login**: Klik "Login dengan SSO" → redirect ke Keycloak → login → kembali ke website → auto-login ✅
- [ ] **Auto-Login**: Setelah login, buka tab baru → akses website → langsung masuk tanpa login lagi ✅
- [ ] **User Data**: Dashboard menampilkan nama, email, role user dengan benar ✅
- [ ] **Logout**: Klik logout → redirect ke Keycloak logout → session terhapus ✅
- [ ] **Session Expiry**: Tunggu 24 jam → session expired → harus login ulang ✅

---

## 🔧 Troubleshooting

### Error: "unauthorized_client"
**Fix:** Pastikan `Client Authentication = OFF` di Keycloak

### Error: "Invalid redirect_uri"
**Fix:** Tambahkan redirect URI yang benar di Keycloak client settings

### User tidak ditemukan
**Fix:** Pastikan email di Keycloak sama dengan email di database `pengguna`

### Token expired
**Fix:** Implement refresh token atau logout dan login ulang

---

## 📚 Referensi Lengkap

Untuk penjelasan detail, lihat:
- **[PANDUAN_SSO_UNTUK_WEBSITE_LAIN.md](./PANDUAN_SSO_UNTUK_WEBSITE_LAIN.md)** - Panduan lengkap dengan diagram dan penjelasan
- **[KEYCLOAK_CLIENT_SETUP.md](./KEYCLOAK_CLIENT_SETUP.md)** - Setup Keycloak client
- **[api/keycloak_helpers.go](./api/keycloak_helpers.go)** - Contoh implementasi backend

---

## 💡 Tips

1. **Gunakan HTTPS di production** (Keycloak tidak support HTTP untuk production)
2. **Enable PKCE** (Code Challenge Method: S256) untuk keamanan ekstra
3. **Set token lifespan** sesuai kebutuhan (default 5 menit)
4. **Implement token refresh** untuk session yang lebih panjang
5. **Log semua OAuth flow** untuk debugging

---

## 🆘 Butuh Bantuan?

Jika ada masalah atau pertanyaan:
1. Cek [Troubleshooting](#troubleshooting) di atas
2. Lihat [panduan lengkap](./PANDUAN_SSO_UNTUK_WEBSITE_LAIN.md)
3. Hubungi tim IT Pusdatin Dinas Pendidikan

---

**Happy Coding! 🚀**
