# 📊 Alur SSO Login, Data Display & Logout - Visual Guide

> **Dokumentasi Visual**: Diagram lengkap alur SSO untuk website aplikasi Dinas Pendidikan

---

## 📋 Daftar Isi
1. [Flow SSO Login](#flow-sso-login)
2. [Flow Menampilkan Data User](#flow-menampilkan-data-user)
3. [Flow Logout (Centralized)](#flow-logout-centralized)
4. [Flow Auto-Login (Prompt=None)](#flow-auto-login-promptnone)
5. [Sequence Diagram](#sequence-diagram)

---

## 🔐 Flow SSO Login

### Diagram Alur Login Lengkap

```
┌─────────────┐         ┌──────────────┐         ┌───────────┐         ┌──────────────┐
│   Browser   │         │  Website     │         │ Keycloak  │         │  Database    │
│   (User)    │         │  Client      │         │  Server   │         │  PostgreSQL  │
└──────┬──────┘         └──────┬───────┘         └─────┬─────┘         └──────┬───────┘
       │                       │                       │                       │
       │ 1. Klik "Login SSO"   │                       │                       │
       ├──────────────────────>│                       │                       │
       │                       │                       │                       │
       │ 2. Redirect ke        │                       │                       │
       │    /sso/authorize     │                       │                       │
       <──────────────────────┤                       │                       │
       │                       │                       │                       │
       │                       │ 3. Generate state,    │                       │
       │                       │    code_verifier      │                       │
       │                       │    + PKCE challenge   │                       │
       │                       │                       │                       │
       │ 4. Redirect to Keycloak Auth URL              │                       │
       │    + client_id                                │                       │
       │    + redirect_uri                             │                       │
       │    + state                                    │                       │
       │    + code_challenge                           │                       │
       ├──────────────────────────────────────────────>│                       │
       │                       │                       │                       │
       │                       │                  5. Check user session        │
       │                       │                       │                       │
       │ 6. Tampilkan login form (jika belum login)    │                       │
       <───────────────────────────────────────────────┤                       │
       │                       │                       │                       │
       │ 7. User input email + password                │                       │
       ├──────────────────────────────────────────────>│                       │
       │                       │                       │                       │
       │                       │                  8. Verify credentials        │
       │                       │                       ├──────────────────────>│
       │                       │                       │   Query user          │
       │                       │                       <──────────────────────┤
       │                       │                       │                       │
       │                       │                  9. Create Keycloak session   │
       │                       │                       │                       │
       │ 10. Redirect callback with code + state       │                       │
       │     http://website.com/callback?code=ABC&state=XYZ                    │
       <───────────────────────────────────────────────┤                       │
       │                       │                       │                       │
       │ 11. Send to /callback │                       │                       │
       ├──────────────────────>│                       │                       │
       │                       │                       │                       │
       │                       │ 12. Verify state      │                       │
       │                       │     (CSRF protection) │                       │
       │                       │                       │                       │
       │                       │ 13. POST to token endpoint                    │
       │                       │     + code                                    │
       │                       │     + code_verifier                           │
       │                       │     + client_id                               │
       │                       ├──────────────────────>│                       │
       │                       │                       │                       │
       │                       │ 14. Verify code + PKCE│                       │
       │                       │                       │                       │
       │                       │ 15. Return tokens     │                       │
       │                       │     - access_token    │                       │
       │                       │     - id_token        │                       │
       │                       │     - refresh_token   │                       │
       │                       <───────────────────────┤                       │
       │                       │                       │                       │
       │                       │ 16. Decode ID token   │                       │
       │                       │     Extract user info │                       │
       │                       │     (email, name)     │                       │
       │                       │                       │                       │
       │                       │ 17. Query user by email                       │
       │                       ├──────────────────────────────────────────────>│
       │                       │   SELECT * FROM pengguna WHERE email=?        │
       │                       <──────────────────────────────────────────────┤
       │                       │                       │                       │
       │                       │ 18. Generate session_id                       │
       │                       │                       │                       │
       │                       │ 19. INSERT session                            │
       │                       ├──────────────────────────────────────────────>│
       │                       │   INSERT INTO sesi_login (...) VALUES (...)   │
       │                       <──────────────────────────────────────────────┤
       │                       │                       │                       │
       │                       │ 20. Set cookies:      │                       │
       │                       │     - client_dinas_session                    │
       │                       │     - sso_access_token                        │
       │                       │     - sso_id_token                            │
       │                       │                       │                       │
       │ 21. Redirect to /dashboard                    │                       │
       <──────────────────────┤                       │                       │
       │                       │                       │                       │
       │ 22. Access /dashboard │                       │                       │
       ├──────────────────────>│                       │                       │
       │                       │                       │                       │
       │ 23. Render dashboard  │                       │                       │
       │     with user data    │                       │                       │
       <──────────────────────┤                       │                       │
       │                       │                       │                       │
```

### Step-by-Step Penjelasan

| Step | Aktor | Aksi | Output |
|------|-------|------|--------|
| 1 | User | Klik tombol "Login dengan SSO" | - |
| 2 | Browser | Redirect ke `/sso/authorize` | - |
| 3 | Website | Generate `state` (CSRF token), `code_verifier` (PKCE) | `state`, `code_verifier`, `code_challenge` |
| 4 | Website | Set cookies: `oauth_state`, `oauth_code_verifier` (5 min) | Cookies di browser |
| 5 | Website | Redirect ke Keycloak auth URL dengan params | Redirect 303 |
| 6 | Keycloak | Check apakah user sudah login | - |
| 7 | Keycloak | Tampilkan login form (jika belum login) | HTML login page |
| 8 | User | Input email + password | - |
| 9 | Keycloak | Verify credentials di database | User authenticated |
| 10 | Keycloak | Create session Keycloak | Keycloak session created |
| 11 | Keycloak | Redirect ke `redirect_uri` dengan `code` + `state` | Redirect 303 |
| 12 | Browser | GET `/callback?code=ABC&state=XYZ` | - |
| 13 | Website | Verify `state` dengan cookie `oauth_state` | State valid ✅ |
| 14 | Website | POST ke Keycloak token endpoint | HTTP POST |
| 15 | Keycloak | Verify `code` + `code_verifier` (PKCE) | Code valid ✅ |
| 16 | Keycloak | Return `access_token`, `id_token`, `refresh_token` | JSON response |
| 17 | Website | Decode `id_token` (JWT), extract `email`, `name` | User info object |
| 18 | Website | Query database: `SELECT * FROM pengguna WHERE email=?` | User record |
| 19 | Website | Generate `session_id` (random string) | Session ID |
| 20 | Website | INSERT session: `sesi_login` table | Session created in DB |
| 21 | Website | Set cookies: `client_dinas_session`, `sso_access_token` | Cookies di browser |
| 22 | Website | Redirect to `/dashboard` | Redirect 303 |
| 23 | Browser | GET `/dashboard` | - |
| 24 | Website | Render dashboard dengan user data | HTML response |

---

## 📊 Flow Menampilkan Data User

### Diagram Alur Get User Data

```
┌─────────────┐         ┌──────────────┐         ┌──────────────┐
│   Browser   │         │  Website     │         │  Database    │
│  (Frontend) │         │  Backend     │         │  PostgreSQL  │
└──────┬──────┘         └──────┬───────┘         └──────┬───────┘
       │                       │                       │
       │ 1. Page load          │                       │
       │    (dashboard.html)   │                       │
       │                       │                       │
       │ 2. JavaScript: fetch('/api/profile')          │
       ├──────────────────────>│                       │
       │   Headers:            │                       │
       │   - Cookie: client_dinas_session              │
       │   - Accept: application/json                  │
       │                       │                       │
       │                       │ 3. Extract session_id from cookie
       │                       │                       │
       │                       │ 4. Query database     │
       │                       │    JOIN pengguna + sesi_login
       │                       ├──────────────────────>│
       │                       │   SELECT p.id_pengguna, p.email,
       │                       │          p.nama_lengkap, p.peran
       │                       │   FROM pengguna p
       │                       │   INNER JOIN sesi_login s
       │                       │     ON s.id_pengguna = p.id_pengguna
       │                       │   WHERE s.id_sesi = ?
       │                       │     AND s.kadaluarsa > NOW()
       │                       │     AND p.aktif = true
       │                       │                       │
       │                       │ 5. User data          │
       │                       <───────────────────────┤
       │                       │                       │
       │ 6. JSON response:     │                       │
       │    {                  │                       │
       │      "success": true, │                       │
       │      "user": {        │                       │
       │        "id_pengguna": "uuid-123",             │
       │        "email": "user@disdik.go.id",          │
       │        "nama_lengkap": "John Doe",            │
       │        "peran": "admin"                       │
       │      }                │                       │
       │    }                  │                       │
       <──────────────────────┤                       │
       │                       │                       │
       │ 7. JavaScript:        │                       │
       │    - Display user.nama_lengkap                │
       │    - Display user.email                       │
       │    - Display user.peran                       │
       │                       │                       │
```

### Implementasi Frontend (JavaScript)

```javascript
// Load user info saat page load
async function loadUserInfo() {
    try {
        const response = await fetch('/api/profile', {
            headers: {
                'Accept': 'application/json'
            }
        });

        if (response.ok) {
            const data = await response.json();
            const user = data.user;

            // Display di UI
            document.getElementById('userName').textContent = user.nama_lengkap;
            document.getElementById('userEmail').textContent = user.email;
            document.getElementById('userRole').textContent = user.peran;

            // Conditional rendering berdasarkan role
            if (user.peran === 'admin') {
                document.getElementById('adminMenu').style.display = 'block';
            }
        } else {
            // Session expired, redirect to login
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Failed to load user info:', error);
    }
}

// Call on page load
document.addEventListener('DOMContentLoaded', loadUserInfo);
```

### Implementasi Backend (Go)

```go
func handleGetProfileAPI(w http.ResponseWriter, r *http.Request) {
    // 1. Get session ID dari cookie
    sessionID, err := helpers.GetCookie(r, "client_dinas_session")
    if err != nil {
        helpers.WriteError(w, http.StatusUnauthorized, "Session tidak valid")
        return
    }

    // 2. Connect to database
    db, err := connectPostgreSQL()
    if err != nil {
        helpers.WriteError(w, http.StatusInternalServerError, "Database error")
        return
    }
    defer db.Close()

    // 3. Query user data dengan JOIN
    query := `
        SELECT p.id_pengguna, p.email, p.nama_lengkap, p.peran, p.aktif
        FROM pengguna p
        INNER JOIN sesi_login s ON s.id_pengguna = p.id_pengguna
        WHERE s.id_sesi = $1 AND s.kadaluarsa > NOW() AND p.aktif = true
    `

    var user map[string]interface{}
    var idPengguna, email, namaLengkap, peran string
    var aktif bool

    err = db.QueryRow(query, sessionID).Scan(&idPengguna, &email, &namaLengkap, &peran, &aktif)
    if err != nil {
        if err == sql.ErrNoRows {
            helpers.WriteError(w, http.StatusUnauthorized, "Session expired")
        } else {
            helpers.WriteError(w, http.StatusInternalServerError, "Query error")
        }
        return
    }

    user = map[string]interface{}{
        "id_pengguna":  idPengguna,
        "email":        email,
        "nama_lengkap": namaLengkap,
        "peran":        peran,
        "aktif":        aktif,
    }

    // 4. Return JSON response
    helpers.WriteJSON(w, http.StatusOK, map[string]interface{}{
        "success": true,
        "user":    user,
    })
}
```

---

## 🚪 Flow Logout (Centralized)

### Diagram Alur Logout Lengkap

```
┌─────────────┐         ┌──────────────┐         ┌───────────┐         ┌──────────────┐
│   Browser   │         │  Website     │         │ Keycloak  │         │  Database    │
│   (User)    │         │  Client      │         │  Server   │         │  PostgreSQL  │
└──────┬──────┘         └──────┬───────┘         └─────┬─────┘         └──────┬───────┘
       │                       │                       │                       │
       │ 1. Klik "Logout"      │                       │                       │
       ├──────────────────────>│                       │                       │
       │                       │                       │                       │
       │ 2. GET /logout        │                       │                       │
       ├──────────────────────>│                       │                       │
       │                       │                       │                       │
       │                       │ 3. Get cookies:       │                       │
       │                       │    - client_dinas_session                     │
       │                       │    - sso_access_token                         │
       │                       │    - sso_id_token                             │
       │                       │                       │                       │
       │                       │ 4. DELETE session from DB                     │
       │                       ├──────────────────────────────────────────────>│
       │                       │   DELETE FROM sesi_login                      │
       │                       │   WHERE id_sesi = ?                           │
       │                       <──────────────────────────────────────────────┤
       │                       │                       │                       │
       │                       │ 5. Clear all cookies  │                       │
       │                       │    - SetCookie(..., MaxAge=-1)                │
       │                       │                       │                       │
       │                       │ 6. Build Keycloak logout URL                  │
       │                       │    + id_token_hint                            │
       │                       │    + post_logout_redirect_uri                 │
       │                       │                       │                       │
       │ 7. Redirect to Keycloak logout                │                       │
       │    https://keycloak/realms/dinas-pendidikan/protocol/openid-connect/logout
       │    ?id_token_hint=TOKEN&post_logout_redirect_uri=http://website.com
       <──────────────────────┤                       │                       │
       │                       │                       │                       │
       │ 8. GET Keycloak logout                        │                       │
       ├──────────────────────────────────────────────>│                       │
       │                       │                       │                       │
       │                       │                  9. Destroy Keycloak session  │
       │                       │                       │                       │
       │                       │                  10. Clear Keycloak cookies   │
       │                       │                       │                       │
       │                       │                  11. Notify other apps (Front-channel logout)
       │                       │                       │                       │
       │ 12. Redirect to post_logout_redirect_uri      │                       │
       │     http://website.com                        │                       │
       <───────────────────────────────────────────────┤                       │
       │                       │                       │                       │
       │ 13. GET /             │                       │                       │
       ├──────────────────────>│                       │                       │
       │                       │                       │                       │
       │ 14. Check session     │                       │                       │
       │     (no session found)│                       │                       │
       │                       │                       │                       │
       │ 15. Redirect to /login                        │                       │
       <──────────────────────┤                       │                       │
       │                       │                       │                       │
```

### Implementasi Logout Handler

```go
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
    log.Printf("🚪 Logout requested")

    // 1. Get session and tokens
    sessionID, _ := helpers.GetCookie(r, "client_dinas_session")
    idToken, _ := helpers.GetCookie(r, "sso_id_token")

    // 2. Delete session dari database
    if sessionID != "" {
        db, err := connectPostgreSQL()
        if err == nil {
            _, err = db.Exec("DELETE FROM sesi_login WHERE id_sesi = $1", sessionID)
            if err != nil {
                log.Printf("Warning: Failed to delete session: %v", err)
            }
            db.Close()
        }
    }

    // 3. Clear all cookies
    helpers.ClearCookie(w, r, "client_dinas_session")
    helpers.ClearCookie(w, r, "sso_access_token")
    helpers.ClearCookie(w, r, "sso_id_token")
    helpers.ClearCookie(w, r, "sso_token_expires")

    // 4. Centralized logout ke Keycloak
    if idToken != "" {
        keycloakBaseURL := getKeycloakBaseURL()
        realm := getKeycloakRealm()
        postLogoutURI := "http://localhost:8070" // Ganti dengan domain aplikasi

        logoutURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout?id_token_hint=%s&post_logout_redirect_uri=%s",
            keycloakBaseURL, realm, idToken, url.QueryEscape(postLogoutURI))

        log.Printf("🔄 Redirecting to Keycloak logout: %s", logoutURL)
        http.Redirect(w, r, logoutURL, http.StatusSeeOther)
        return
    }

    // 5. Fallback: redirect to home (jika tidak ada id_token)
    http.Redirect(w, r, "/", http.StatusSeeOther)
}
```

### Frontend Logout Button

```html
<button onclick="handleLogout()" class="btn-logout">
    <svg><!-- Logout icon --></svg>
    Logout
</button>

<script>
async function handleLogout() {
    if (confirm('Apakah Anda yakin ingin logout?')) {
        try {
            // Optional: Call API to delete session
            await fetch('/api/logout', {
                method: 'POST',
                headers: { 'Accept': 'application/json' }
            });
        } catch (error) {
            console.error('Logout API failed:', error);
        }

        // Redirect to logout handler (akan logout dari Keycloak juga)
        window.location.href = '/logout';
    }
}
</script>
```

---

## ⚡ Flow Auto-Login (Prompt=None)

### Diagram Alur Auto-Login

```
┌─────────────┐         ┌──────────────┐         ┌───────────┐
│   Browser   │         │  Website     │         │ Keycloak  │
│   (User)    │         │  Client      │         │  Server   │
└──────┬──────┘         └──────┬───────┘         └─────┬─────┘
       │                       │                       │
       │ 1. Access website (new tab)                   │
       │    http://website.com │                       │
       ├──────────────────────>│                       │
       │                       │                       │
       │                       │ 2. Check local session│
       │                       │    (no cookie found)  │
       │                       │                       │
       │                       │ 3. Redirect to Keycloak
       │                       │    WITH prompt=none   │
       │                       │    (auto-login)       │
       │                       │                       │
       │ 4. Redirect to Keycloak auth URL              │
       │    + prompt=none      │                       │
       <──────────────────────┤                       │
       │                       │                       │
       │ 5. GET Keycloak auth                          │
       ├──────────────────────────────────────────────>│
       │    ?prompt=none       │                       │
       │                       │                       │
       │                       │                  6. Check Keycloak session
       │                       │                     (session exists!)
       │                       │                       │
       │                       │                  7. Generate authorization code
       │                       │                     (tanpa tampilkan form login)
       │                       │                       │
       │ 8. Redirect callback with code                │
       │    http://website.com/callback?code=XYZ       │
       <───────────────────────────────────────────────┤
       │                       │                       │
       │ 9-20. Same as normal login flow               │
       │       (exchange code, get token, create session)
       │                       │                       │
       │ 21. Redirect to /dashboard                    │
       <──────────────────────┤                       │
       │                       │                       │
       │ ✅ AUTO-LOGGED IN     │                       │
       │    (tanpa input password!)                    │
       │                       │                       │
```

### Kapan Auto-Login Terjadi?

1. **User sudah login di aplikasi lain** (Portal SSO atau aplikasi lain yang menggunakan Keycloak yang sama)
2. **Keycloak session masih aktif** (belum expired)
3. **User mengakses aplikasi baru** (tidak ada session lokal)
4. **Applicasi menggunakan `prompt=none`** saat redirect ke Keycloak

### Implementasi Auto-Login

```go
case "/", "/home":
    // Check authorization code dari Keycloak
    code := r.URL.Query().Get("code")
    if code != "" {
        http.Redirect(w, r, "/callback?"+r.URL.RawQuery, http.StatusSeeOther)
        return
    }

    // Check session lokal
    if isAuthenticated(r) {
        http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
        return
    }

    // Tidak ada session lokal, check Keycloak session dengan prompt=none
    log.Printf("🔄 No local session, checking Keycloak session with prompt=none")
    redirectToKeycloakLogin(w, r, true) // true = dengan prompt=none (auto-login)
```

---

## 🔄 Sequence Diagram (Text-based)

### Complete SSO Flow

```
User    Browser    Website    Keycloak    Database
 │         │          │           │           │
 │  Click SSO Login  │           │           │
 ├────────>│          │           │           │
 │         │ GET /sso/authorize  │           │
 │         ├─────────>│           │           │
 │         │          │ Generate  │           │
 │         │          │ state+PKCE│           │
 │         │          │           │           │
 │         │ 303 Redirect to Keycloak         │
 │         <──────────┤           │           │
 │         │          │           │           │
 │         │ GET /auth?prompt=none            │
 │         ├──────────────────────>│           │
 │         │          │   Check    │           │
 │         │          │   session  │           │
 │         │          │           │           │
 │         │ Show login form      │           │
 │         <──────────────────────┤           │
 │         │          │           │           │
 │ Login   │          │           │           │
 ├────────>│ POST credentials     │           │
 │         ├──────────────────────>│           │
 │         │          │   Verify   │           │
 │         │          │   user     │           │
 │         │          │           ├──────────>│
 │         │          │           <──────────┤
 │         │          │           │           │
 │         │ 303 /callback?code=ABC           │
 │         <──────────────────────┤           │
 │         │          │           │           │
 │         │ GET /callback        │           │
 │         ├─────────>│           │           │
 │         │          │ Verify    │           │
 │         │          │ state     │           │
 │         │          │           │           │
 │         │          │ POST /token           │
 │         │          ├──────────>│           │
 │         │          │   return  │           │
 │         │          │   tokens  │           │
 │         │          <───────────┤           │
 │         │          │           │           │
 │         │          │ Decode    │           │
 │         │          │ ID token  │           │
 │         │          │           │           │
 │         │          │ Query user            │
 │         │          ├──────────────────────>│
 │         │          <──────────────────────┤
 │         │          │           │           │
 │         │          │ INSERT session        │
 │         │          ├──────────────────────>│
 │         │          <──────────────────────┤
 │         │          │           │           │
 │         │ Set cookies          │           │
 │         <──────────┤           │           │
 │         │          │           │           │
 │         │ 303 /dashboard       │           │
 │         <──────────┤           │           │
 │         │          │           │           │
 │ Dashboard loaded  │           │           │
 <────────┤          │           │           │
 │         │          │           │           │
```

---

## 📊 State Diagram

### User Authentication States

```
┌─────────────────────┐
│   LOGGED OUT        │
│  (No session)       │
└──────────┬──────────┘
           │
           │ Click "Login SSO"
           ▼
┌─────────────────────┐
│   AUTHENTICATING    │
│  (Redirected to KC) │
└──────────┬──────────┘
           │
           │ Login berhasil
           ▼
┌─────────────────────┐
│   LOGGED IN         │──────┐
│  (Has session)      │      │ Token refresh
└──────────┬──────────┘      │ (background)
           │                 │
           │                 └──────┐
           │                        │
           │ Click "Logout"         │
           ▼                        ▼
┌─────────────────────┐    ┌─────────────┐
│   LOGGING OUT       │    │ TOKEN       │
│  (Destroy session)  │    │ REFRESHED   │
└──────────┬──────────┘    └─────┬───────┘
           │                     │
           │                     │
           ▼                     ▼
┌─────────────────────┐    ┌─────────────┐
│   LOGGED OUT        │    │ LOGGED IN   │
│  (returned to home) │    │ (continue)  │
└─────────────────────┘    └─────────────┘
```

---

## 🔐 Security Checklist

- [x] **PKCE** (Proof Key for Code Exchange) - Mencegah authorization code interception
- [x] **State parameter** - CSRF protection
- [x] **HTTPS di production** - Enkripsi komunikasi
- [x] **Secure cookies** - HttpOnly, Secure, SameSite
- [x] **Session expiry** - 24 jam default
- [x] **Token expiry** - 5 menit untuk access token
- [x] **Centralized logout** - Logout dari Keycloak
- [x] **Database session** - Session disimpan di DB (bisa di-revoke)

---

## 📝 Summary

### Login Flow
1. User klik "Login dengan SSO"
2. Redirect ke Keycloak dengan PKCE
3. User login di Keycloak
4. Keycloak return authorization code
5. Exchange code untuk access token
6. Decode ID token untuk user info
7. Create session di database
8. Set cookies dan redirect ke dashboard

### Data Display Flow
1. Frontend fetch `/api/profile`
2. Backend verify session cookie
3. Query database (JOIN pengguna + sesi_login)
4. Return user data sebagai JSON
5. Frontend display data di UI

### Logout Flow
1. User klik "Logout"
2. Backend delete session dari database
3. Clear all cookies
4. Redirect ke Keycloak logout endpoint
5. Keycloak destroy session dan notify other apps
6. Redirect back to website (logged out)

### Auto-Login Flow
1. User access website (no local session)
2. Redirect ke Keycloak dengan `prompt=none`
3. Keycloak check session (jika ada, auto-approve)
4. Return authorization code tanpa login form
5. Same flow as normal login (exchange code, create session)
6. User auto-logged in!

---

**Dibuat dengan ❤️ untuk Dinas Pendidikan DKI Jakarta**
