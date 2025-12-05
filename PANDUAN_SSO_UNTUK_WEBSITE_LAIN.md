# 🔐 Panduan Implementasi SSO untuk Website Aplikasi Dinas Pendidikan

> **Panduan Lengkap**: Cara agar website kita mampu menerima SSO dari website utama (Keycloak), menampilkan data user, dan menangani logout dengan benar.

---

## 📋 Daftar Isi
1. [Pengenalan](#pengenalan)
2. [Arsitektur SSO](#arsitektur-sso)
3. [Prerequisites](#prerequisites)
4. [Konfigurasi Keycloak Client](#konfigurasi-keycloak-client)
5. [Implementasi Backend](#implementasi-backend)
6. [Implementasi Frontend](#implementasi-frontend)
7. [Menampilkan Data User](#menampilkan-data-user)
8. [Logout Handling](#logout-handling)
9. [Testing](#testing)
10. [Troubleshooting](#troubleshooting)

---

## 🌟 Pengenalan

### Apa itu SSO (Single Sign-On)?

SSO adalah sistem autentikasi yang memungkinkan user login sekali di **Portal SSO Utama** dan bisa mengakses semua aplikasi lain tanpa perlu login ulang.

### Flow SSO Dinas Pendidikan

```
User → Portal SSO (Login) → Keycloak → Aplikasi Client (Auto-Login)
```

**Keuntungan:**
- ✅ User hanya perlu 1 akun untuk semua aplikasi
- ✅ Sinkronisasi data user otomatis dari database pusat
- ✅ Logout di 1 aplikasi = logout di semua aplikasi
- ✅ Keamanan terpusat (password management, 2FA, dll)

---

## 🏗️ Arsitektur SSO

### Komponen Sistem

```
┌─────────────────┐      ┌──────────────────┐      ┌─────────────────┐
│  Portal SSO     │──────│   Keycloak       │──────│  Aplikasi       │
│  (Port 3000)    │      │   (Port 8080)    │      │  (Port 8070)    │
│                 │      │                  │      │                 │
│  - Login Page   │      │  - Auth Server   │      │  - Your App     │
│  - App Launcher │      │  - Token Manager │      │  - Auto Login   │
│  - User Profile │      │  - User Store    │      │  - User Data    │
└─────────────────┘      └──────────────────┘      └─────────────────┘
         │                        │                          │
         └────────────────────────┴──────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │  PostgreSQL Database      │
                    │  (Port 5433)              │
                    │  - User Data (pengguna)   │
                    │  - Sessions (sesi_login)  │
                    └───────────────────────────┘
```

### OAuth 2.0 Authorization Code Flow (dengan PKCE)

```
┌─────────┐                                           ┌─────────────┐
│ Browser │                                           │  Keycloak   │
└────┬────┘                                           └──────┬──────┘
     │                                                        │
     │ 1. Klik "Login dengan SSO"                            │
     ├───────────────────────────────────────────────────────>
     │                                                        │
     │ 2. Redirect ke /realms/dinas-pendidikan/auth          │
     │    + client_id, redirect_uri, state, code_challenge   │
     <───────────────────────────────────────────────────────┤
     │                                                        │
     │ 3. User login (jika belum) atau auto-SSO              │
     │                                                        │
     │ 4. Redirect callback dengan code + state              │
     │    http://localhost:8070/callback?code=ABC&state=XYZ  │
     <───────────────────────────────────────────────────────┤
     │                                                        │
     ├─────────────────────────┐                             │
     │ 5. POST /token          │                             │
     │    + code               │                             │
     │    + code_verifier      ├─────────────────────────────>
     │    + client_id          │                             │
     └─────────────────────────┘                             │
     │                                                        │
     │ 6. Response: access_token, id_token, refresh_token    │
     <───────────────────────────────────────────────────────┤
     │                                                        │
     │ 7. GET /userinfo dengan Bearer token                  │
     ├───────────────────────────────────────────────────────>
     │                                                        │
     │ 8. Response: user data (email, name, role, dll)       │
     <───────────────────────────────────────────────────────┤
     │                                                        │
     ├─────────────────────────┐                             │
     │ 9. Create local session │                             │
     │    + Set cookies        │                             │
     │    + Redirect dashboard │                             │
     └─────────────────────────┘                             │
```

---

## ✅ Prerequisites

### 1. Database Schema

Aplikasi harus memiliki 2 tabel penting:

#### Tabel `pengguna` (User Data)

```sql
CREATE TABLE IF NOT EXISTS pengguna (
    id_pengguna UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    nama_lengkap TEXT NOT NULL,
    peran TEXT DEFAULT 'user',
    aktif BOOLEAN DEFAULT true,
    password TEXT,  -- Optional untuk SSO-only users
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tambahan kolom untuk sinkronisasi data dari SSO (opsional)
-- ALTER TABLE pengguna ADD COLUMN IF NOT EXISTS keycloak_id TEXT;
-- ALTER TABLE pengguna ADD COLUMN IF NOT EXISTS nip TEXT;
-- ALTER TABLE pengguna ADD COLUMN IF NOT EXISTS nik TEXT;
-- ALTER TABLE pengguna ADD COLUMN IF NOT EXISTS npsn TEXT;
```

#### Tabel `sesi_login` (Session Management)

```sql
CREATE TABLE IF NOT EXISTS sesi_login (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    id_pengguna UUID NOT NULL REFERENCES pengguna(id_pengguna) ON DELETE CASCADE,
    id_sesi TEXT UNIQUE NOT NULL,
    ip TEXT,
    user_agent TEXT,
    kadaluarsa TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sesi_login_id_sesi ON sesi_login(id_sesi);
CREATE INDEX IF NOT EXISTS idx_sesi_login_kadaluarsa ON sesi_login(kadaluarsa);
```

### 2. Environment Variables

Tambahkan di file `.env`:

```env
# Keycloak Configuration
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=dinas-pendidikan
KEYCLOAK_CLIENT_ID=localhost-8070-website-dinas-pendidikan
KEYCLOAK_REDIRECT_URI=http://localhost:8070/callback

# Database Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5433
POSTGRES_DB=dinas_pendidikan
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres123

# Session Configuration
SESSION_SECRET=your-secret-key-min-32-chars
```

### 3. Dependencies

**Go:**
```bash
go get github.com/golang-jwt/jwt/v5
go get github.com/lib/pq
go get golang.org/x/crypto/bcrypt
```

**Tidak perlu library JavaScript tambahan** - gunakan native browser APIs.

---

## 🔧 Konfigurasi Keycloak Client

### Step 1: Akses Keycloak Admin Console

1. Buka browser: **http://localhost:8080/admin** (atau sesuai URL Keycloak Anda)
2. Login dengan credentials admin
3. Pilih Realm: **dinas-pendidikan**

### Step 2: Create Client Baru

1. Klik **Clients** di sidebar
2. Klik **Create client**
3. Isi form:

**General Settings:**
```
Client type: OpenID Connect
Client ID: localhost-8070-website-dinas-pendidikan
Name: Website Dinas Pendidikan (Client Port 8070)
```

### Step 3: Capability Config

**PENTING - Setting berikut harus benar:**

```
Client authentication: OFF  ← Public client (penting!)
Authorization: OFF
```

**Authentication flow (centang yang diperlukan):**
- ✅ **Standard flow** (Authorization Code) ← WAJIB!
- ✅ **Direct access grants**
- ❌ Implicit flow
- ❌ Service accounts

### Step 4: Login Settings

```
Root URL: http://localhost:8070
Home URL: http://localhost:8070/

Valid redirect URIs:
  - http://localhost:8070/callback
  - http://localhost:8070/oauth/callback
  - http://localhost:8070/*

Valid post logout redirect URIs:
  - http://localhost:8070
  - http://localhost:8070/*

Web origins:
  - http://localhost:8070
```

### Step 5: Advanced Settings (Opsional)

```
PKCE Code Challenge Method: S256 (Recommended untuk keamanan)
Access Token Lifespan: 5 minutes (default)
SSO Session Idle: 30 minutes
SSO Session Max: 10 hours
```

### Verifikasi Client Sudah Benar

Cek kembali:
- [x] Client authentication = **OFF**
- [x] Standard flow = **ON**
- [x] Redirect URIs sudah mencakup `/callback`
- [x] Web origins sama dengan domain aplikasi

---

## 💻 Implementasi Backend

### File Structure

```
api/
├── main_handler.go           # Main handler & routing
├── keycloak_helpers.go       # Keycloak integration functions
├── sso_handlers.go           # SSO-specific handlers (baru)
├── session/
│   └── session.go            # Session management
└── static/
    └── sso-handler.js        # Frontend SSO handler (embed)
```

### 1. Keycloak Helper Functions (`keycloak_helpers.go`)

```go
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

// Keycloak configuration getters
func getKeycloakBaseURL() string {
	if url := os.Getenv("KEYCLOAK_BASE_URL"); url != "" {
		return url
	}
	return "http://localhost:8080"
}

func getKeycloakRealm() string {
	if realm := os.Getenv("KEYCLOAK_REALM"); realm != "" {
		return realm
	}
	return "dinas-pendidikan"
}

func getKeycloakClientID() string {
	if clientID := os.Getenv("KEYCLOAK_CLIENT_ID"); clientID != "" {
		return clientID
	}
	return "localhost-8070-website-dinas-pendidikan"
}

func getKeycloakRedirectURI() string {
	if uri := os.Getenv("KEYCLOAK_REDIRECT_URI"); uri != "" {
		return uri
	}
	return "http://localhost:8070/callback"
}

// redirectToKeycloakLogin - Redirect user ke Keycloak untuk login
func redirectToKeycloakLogin(w http.ResponseWriter, r *http.Request, withPromptNone bool) {
	keycloakBaseURL := getKeycloakBaseURL()
	realm := getKeycloakRealm()
	clientID := getKeycloakClientID()
	redirectURI := getKeycloakRedirectURI()

	// Generate state (CSRF protection)
	state, _ := helpers.GenerateRandomString(32)
	
	// Generate PKCE code verifier & challenge
	codeVerifier, _ := helpers.GenerateRandomString(43)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Store in cookies (5 minutes expiry)
	helpers.SetCookie(w, r, "oauth_state", state, 300)
	helpers.SetCookie(w, r, "oauth_code_verifier", codeVerifier, 300)

	// Build authorization URL
	params := url.Values{}
	params.Add("client_id", clientID)
	params.Add("redirect_uri", redirectURI)
	params.Add("response_type", "code")
	params.Add("scope", "openid email profile")
	params.Add("state", state)
	params.Add("code_challenge", codeChallenge)
	params.Add("code_challenge_method", "S256")

	if withPromptNone {
		params.Add("prompt", "none") // Auto-login
	}

	authURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth?%s",
		keycloakBaseURL, realm, params.Encode())

	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// KeycloakTokenResponse - Response dari Keycloak token endpoint
type KeycloakTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// exchangeKeycloakCode - Exchange authorization code untuk access token
func exchangeKeycloakCode(w http.ResponseWriter, r *http.Request, code string) (*KeycloakTokenResponse, error) {
	keycloakBaseURL := getKeycloakBaseURL()
	realm := getKeycloakRealm()
	clientID := getKeycloakClientID()
	redirectURI := getKeycloakRedirectURI()

	// Get code_verifier from cookie
	codeVerifier, err := helpers.GetCookie(r, "oauth_code_verifier")
	if err != nil || codeVerifier == "" {
		return nil, fmt.Errorf("missing code verifier")
	}
	
	// Delete verifier cookie (single use)
	helpers.DeleteCookie(w, "oauth_code_verifier")

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		keycloakBaseURL, realm)

	// Prepare form data
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientID)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("code_verifier", codeVerifier)

	// Send POST request
	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s - %s", resp.Status, string(body))
	}

	// Parse response
	var tokenResp KeycloakTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// getUserInfoFromIDToken - Extract user info dari ID token JWT
func getUserInfoFromIDToken(idToken string) (map[string]interface{}, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode payload (base64url)
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decodedBytes, err := helpers.Base64URLDecode(payload)
	if err != nil {
		return nil, err
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decodedBytes, &claims); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"sub":                claims["sub"],
		"email":              claims["email"],
		"name":               claims["name"],
		"preferred_username": claims["preferred_username"],
		"email_verified":     claims["email_verified"],
	}, nil
}
```

### 2. OAuth Callback Handler (`main_handler.go`)

```go
// handleOAuthCallback - Handle callback dari Keycloak
func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔐 OAuth Callback received")
	
	// Get code dan state
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	// Check error dari Keycloak
	if errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		log.Printf("❌ OAuth error: %s - %s", errorParam, errorDesc)

		if errorParam == "login_required" || errorParam == "interaction_required" {
			// Redirect ke login form
			redirectToKeycloakLogin(w, r, false)
			return
		}

		http.Error(w, "OAuth Error: "+errorParam, http.StatusBadRequest)
		return
	}

	// Verify state (CSRF protection)
	storedState, err := helpers.GetCookie(r, "oauth_state")
	if err != nil || state != storedState {
		log.Printf("❌ State mismatch")
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	helpers.DeleteCookie(w, "oauth_state")

	// Verify code
	if code == "" {
		http.Error(w, "Missing code", http.StatusBadRequest)
		return
	}

	// Exchange code untuk access token
	tokenData, err := exchangeKeycloakCode(w, r, code)
	if err != nil {
		log.Printf("❌ Failed to exchange code: %v", err)
		http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
		return
	}

	// Get user info dari ID token
	userInfo, err := getUserInfoFromIDToken(tokenData.IDToken)
	if err != nil {
		log.Printf("❌ Failed to get user info: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Extract email
	email, ok := userInfo["email"].(string)
	if !ok || email == "" {
		http.Error(w, "Email not found", http.StatusBadRequest)
		return
	}

	log.Printf("✅ User info: email=%s, name=%v", email, userInfo["name"])

	// Create session
	sessionID, success := createSessionFromEmail(r, email)
	if !success || sessionID == "" {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set cookies
	helpers.SetCookie(w, r, "client_dinas_session", sessionID, 86400)
	helpers.SetCookie(w, r, "sso_access_token", tokenData.AccessToken, 86400)
	helpers.SetCookie(w, r, "sso_id_token", tokenData.IDToken, 86400)

	log.Printf("✅ Session created, redirecting to dashboard")
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// createSessionFromEmail - Create session berdasarkan email
func createSessionFromEmail(r *http.Request, email string) (string, bool) {
	db, err := connectPostgreSQL()
	if err != nil {
		log.Printf("❌ Failed to connect to DB: %v", err)
		return "", false
	}
	defer db.Close()

	// Get user by email
	var userID string
	query := `SELECT id_pengguna FROM pengguna WHERE email = $1 AND aktif = true`
	err = db.QueryRow(query, email).Scan(&userID)
	if err != nil {
		log.Printf("❌ User not found: %s", email)
		return "", false
	}

	// Generate session ID
	sessionID, _ := helpers.GenerateSessionID()
	expiresAt := time.Now().Add(24 * time.Hour)

	// Insert session
	insertQuery := `INSERT INTO sesi_login (id_pengguna, id_sesi, ip, user_agent, kadaluarsa) 
		VALUES ($1, $2, $3, $4, $5)`
	_, err = db.Exec(insertQuery, userID, sessionID, r.RemoteAddr, r.Header.Get("User-Agent"), expiresAt)
	if err != nil {
		log.Printf("❌ Failed to create session: %v", err)
		return "", false
	}

	return sessionID, true
}
```

### 3. Routing Setup (`main_handler.go`)

```go
func Handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch path {
	case "/", "/home":
		// Check authorization code dari Keycloak
		code := r.URL.Query().Get("code")
		if code != "" {
			http.Redirect(w, r, "/callback?"+r.URL.RawQuery, http.StatusSeeOther)
			return
		}

		// Check session
		if isAuthenticated(r) {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}

		// Redirect ke Keycloak dengan prompt=none (auto-login)
		redirectToKeycloakLogin(w, r, true)

	case "/callback", "/oauth/callback":
		handleOAuthCallback(w, r)
		return

	case "/login":
		if r.Method == "POST" {
			LoginPostHandler(w, r)
		} else {
			LoginPageHandler(w, r)
		}
		return

	case "/logout":
		LogoutHandler(w, r)
		return

	// ... routes lainnya
	}
}
```

---

## 🎨 Implementasi Frontend

### Halaman Login dengan Tombol SSO

Update `renderLoginPage()` untuk menambahkan tombol SSO:

```go
func renderLoginPage(w http.ResponseWriter, errorMsg, email string) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Dinas Pendidikan DKI Jakarta</title>
    <style>
        /* ... styles ... */
        .btn-sso {
            width: 100%%;
            padding: 14px;
            background: linear-gradient(135deg, #4f46e5 0%%, #4338ca 100%%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            text-decoration: none;
        }
        .btn-sso:hover {
            background: linear-gradient(135deg, #4338ca 0%%, #3730a3 100%%);
            transform: translateY(-2px);
            box-shadow: 0 10px 15px -3px rgba(79, 70, 229, 0.3);
        }
        .btn-sso svg {
            width: 20px;
            height: 20px;
            margin-right: 10px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <img src="/logo.png" alt="Logo Dinas Pendidikan">
            <h1>Dinas Pendidikan</h1>
            <p>Provinsi DKI Jakarta</p>
        </div>

        <!-- Form login biasa -->
        <form id="loginForm" method="POST" action="/login">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required value="%s">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn-primary">Masuk</button>
        </form>
        
        <!-- Divider -->
        <div style="text-align: center; margin: 20px 0; position: relative;">
            <hr style="border: 0; border-top: 1px solid #e2e8f0;">
            <span style="position: absolute; top: -10px; left: 50%%; transform: translateX(-50%%); background: white; padding: 0 10px; color: #64748b; font-size: 14px;">atau</span>
        </div>

        <!-- Tombol SSO -->
        <a href="/sso/authorize" class="btn-sso" id="ssoLoginBtn">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>
            </svg>
            Login dengan SSO
        </a>

        <div class="link-text">
            Belum punya akun? <a href="/register">Daftar di sini</a>
        </div>
    </div>

    <script>
        // SSO button handler
        document.getElementById('ssoLoginBtn').addEventListener('click', function(e) {
            e.preventDefault();
            console.log('🔐 Redirecting to SSO login...');
            // Redirect ke Keycloak
            window.location.href = '/'; // Will trigger auto-redirect to Keycloak
        });

        // Form login handler (keep existing code)
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            // ... existing login code ...
        });
    </script>
</body>
</html>`, email)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
```

### SSO Authorization Endpoint

Tambahkan endpoint `/sso/authorize` untuk initiate SSO flow:

```go
case "/sso/authorize":
	// Redirect ke Keycloak untuk SSO login
	log.Printf("🔐 SSO authorize requested, redirecting to Keycloak")
	redirectToKeycloakLogin(w, r, false) // false = tampilkan form login
	return
```

---

## 📊 Menampilkan Data User

### 1. Fetch User Info dari Session

```go
// getUserFromSession - Get user data berdasarkan session
func getUserFromSession(r *http.Request) (map[string]interface{}, error) {
	// Get session ID from cookie
	sessionID, err := helpers.GetCookie(r, "client_dinas_session")
	if err != nil {
		return nil, err
	}

	db, err := connectPostgreSQL()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// Query user data via session
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
		return nil, err
	}

	user = map[string]interface{}{
		"id_pengguna":  idPengguna,
		"email":        email,
		"nama_lengkap": namaLengkap,
		"peran":        peran,
		"aktif":        aktif,
	}

	return user, nil
}
```

### 2. API Endpoint untuk Get Profile

```go
func handleGetProfileAPI(w http.ResponseWriter, r *http.Request) {
	user, err := getUserFromSession(r)
	if err != nil {
		helpers.WriteError(w, http.StatusUnauthorized, "Session tidak valid")
		return
	}

	helpers.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"user":    user,
	})
}
```

### 3. Frontend: Display User Info

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

            // Display user info
            document.getElementById('userName').textContent = user.nama_lengkap;
            document.getElementById('userEmail').textContent = user.email;
            document.getElementById('userRole').textContent = user.peran;
        } else {
            // Session expired, redirect to login
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Failed to load user info:', error);
    }
}

// Call saat page load
document.addEventListener('DOMContentLoaded', loadUserInfo);
```

---

## 🚪 Logout Handling

### Centralized Logout (Logout dari Keycloak)

Untuk logout dari semua aplikasi sekaligus:

```go
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("🚪 Logout requested")

	// Get session and access token
	sessionID, _ := helpers.GetCookie(r, "client_dinas_session")
	accessToken, _ := helpers.GetCookie(r, "sso_access_token")
	idToken, _ := helpers.GetCookie(r, "sso_id_token")

	// Delete local session from database
	if sessionID != "" {
		db, err := connectPostgreSQL()
		if err == nil {
			_, _ = db.Exec("DELETE FROM sesi_login WHERE id_sesi = $1", sessionID)
			db.Close()
		}
	}

	// Clear all cookies
	helpers.ClearCookie(w, r, "client_dinas_session")
	helpers.ClearCookie(w, r, "sso_access_token")
	helpers.ClearCookie(w, r, "sso_id_token")
	helpers.ClearCookie(w, r, "sso_token_expires")

	// Logout dari Keycloak (centralized logout)
	if idToken != "" || accessToken != "" {
		keycloakBaseURL := getKeycloakBaseURL()
		realm := getKeycloakRealm()
		
		// Build logout URL
		logoutURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout", keycloakBaseURL, realm)
		
		params := url.Values{}
		if idToken != "" {
			params.Add("id_token_hint", idToken)
		}
		params.Add("post_logout_redirect_uri", "http://localhost:8070")
		
		fullLogoutURL := logoutURL + "?" + params.Encode()
		
		log.Printf("🔄 Redirecting to Keycloak logout: %s", fullLogoutURL)
		http.Redirect(w, r, fullLogoutURL, http.StatusSeeOther)
		return
	}

	// Fallback: redirect to home
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
```

### Frontend Logout Button

```html
<button id="logoutBtn" onclick="handleLogout()">Logout</button>

<script>
async function handleLogout() {
    if (confirm('Apakah Anda yakin ingin logout?')) {
        try {
            const response = await fetch('/api/logout', {
                method: 'POST',
                headers: {
                    'Accept': 'application/json'
                }
            });

            if (response.ok) {
                // Redirect ke logout endpoint (akan logout dari Keycloak juga)
                window.location.href = '/logout';
            }
        } catch (error) {
            console.error('Logout failed:', error);
            // Tetap redirect ke logout
            window.location.href = '/logout';
        }
    }
}
</script>
```

---

## 🧪 Testing

### 1. Test SSO Login Flow

1. **Buka aplikasi** (incognito window):
   ```
   http://localhost:8070
   ```

2. **Klik tombol "Login dengan SSO"**
   - Should redirect to Keycloak login page

3. **Login dengan akun yang ada di Keycloak**
   - Email: `admin@disdik.jakarta.go.id`
   - Password: sesuai database

4. **Setelah login:**
   - Should redirect back to `/callback?code=...`
   - Should auto-login dan redirect ke `/dashboard`
   - Check cookies: `client_dinas_session`, `sso_access_token`

### 2. Test Auto-Login (SSO Session)

1. **Jangan logout**, buka tab baru
2. **Akses aplikasi lagi**: `http://localhost:8070`
3. **Expected:** Langsung redirect ke dashboard (no login prompt)

### 3. Test Centralized Logout

1. **Klik Logout** di aplikasi
2. **Expected:**
   - Redirect ke halaman home Keycloak
   - Cookie terhapus
   - Session terhapus di database

3. **Buka aplikasi lagi**
4. **Expected:** Harus login ulang

### 4. Test User Data Display

1. **Login dengan SSO**
2. **Buka Developer Console (F12)**
3. **Run:**
   ```javascript
   fetch('/api/profile').then(r => r.json()).then(console.log)
   ```
4. **Expected:** Menampilkan data user lengkap

---

## 🔍 Troubleshooting

### Issue 1: "unauthorized_client" saat OAuth callback

**Penyebab:**
- Client authentication masih ON (harus OFF untuk public client)
- Client ID tidak sesuai

**Solution:**
1. Buka Keycloak Admin Console
2. Pilih client Anda
3. Pastikan **Client authentication = OFF**
4. Save dan restart aplikasi

---

### Issue 2: "Invalid redirect_uri"

**Penyebab:**
- Redirect URI tidak terdaftar di Keycloak

**Solution:**
1. Buka Keycloak Admin Console
2. Pilih client → Settings
3. Tambahkan di **Valid Redirect URIs**:
   ```
   http://localhost:8070/callback
   http://localhost:8070/oauth/callback
   http://localhost:8070/*
   ```

---

### Issue 3: User tidak ditemukan setelah SSO login

**Penyebab:**
- Email di Keycloak berbeda dengan email di database
- User tidak ada di tabel `pengguna`

**Solution:**
1. **Check email di Keycloak:**
   ```
   Keycloak Admin → Users → Cari user → Email
   ```

2. **Check database:**
   ```sql
   SELECT * FROM pengguna WHERE email = 'email@example.com';
   ```

3. **Buat user jika belum ada:**
   ```sql
   INSERT INTO pengguna (email, nama_lengkap, peran, aktif)
   VALUES ('email@example.com', 'Nama User', 'user', true);
   ```

---

### Issue 4: Token expired / Session expired

**Penyebab:**
- Access token Keycloak sudah expired (default 5 menit)
- Session database sudah expired

**Solution:**
1. **Implement token refresh** (advanced):
   - Simpan `refresh_token` dari Keycloak
   - Gunakan refresh token untuk mendapatkan access token baru

2. **Atau logout dan login ulang**

---

### Issue 5: CORS error saat call Keycloak

**Penyebab:**
- Web origins tidak dikonfigurasi di Keycloak

**Solution:**
1. Buka Keycloak Admin Console
2. Pilih client → Settings
3. Set **Web origins**:
   ```
   http://localhost:8070
   ```

---

## 📝 Checklist Implementasi

Gunakan checklist ini untuk memastikan implementasi SSO Anda lengkap:

### Keycloak Setup
- [ ] Client sudah dibuat di Keycloak
- [ ] Client authentication = OFF
- [ ] Standard flow = ON
- [ ] Valid redirect URIs sudah benar
- [ ] Web origins sudah dikonfigurasi
- [ ] PKCE Code Challenge Method = S256

### Database
- [ ] Tabel `pengguna` sudah ada
- [ ] Tabel `sesi_login` sudah ada
- [ ] User test sudah dibuat dengan email yang sama di Keycloak

### Environment
- [ ] `.env` file sudah dikonfigurasi
- [ ] KEYCLOAK_BASE_URL benar
- [ ] KEYCLOAK_REALM = `dinas-pendidikan`
- [ ] KEYCLOAK_CLIENT_ID sesuai dengan client di Keycloak
- [ ] KEYCLOAK_REDIRECT_URI benar

### Backend
- [ ] `keycloak_helpers.go` sudah dibuat
- [ ] `redirectToKeycloakLogin()` berfungsi
- [ ] `exchangeKeycloakCode()` berfungsi
- [ ] `handleOAuthCallback()` berfungsi
- [ ] `createSessionFromEmail()` berfungsi
- [ ] Routing `/callback` sudah ada
- [ ] Routing `/logout` handle centralized logout

### Frontend
- [ ] Tombol "Login dengan SSO" sudah ada di halaman login
- [ ] Tombol SSO redirect ke `/sso/authorize`
- [ ] User info ditampilkan setelah login
- [ ] Logout button berfungsi

### Testing
- [ ] SSO login berhasil
- [ ] Auto-login berhasil (prompt=none)
- [ ] User data tampil dengan benar
- [ ] Centralized logout berhasil
- [ ] Session management berfungsi

---

## 🎓 Kesimpulan

Setelah mengikuti panduan ini, aplikasi Anda sudah:

✅ **Bisa menerima SSO** dari website utama (Keycloak)  
✅ **Menampilkan data user** dari database pusat  
✅ **Logout dengan benar** (centralized logout)  
✅ **Auto-login** jika user sudah login di aplikasi lain  

### Next Steps (Optional)

1. **Implement token refresh** untuk session yang lebih panjang
2. **Add role-based authorization** (RBAC)
3. **Sinkronisasi data user** otomatis dari Keycloak
4. **Multi-factor authentication** (MFA/2FA)
5. **Audit logging** untuk security

---

## 📚 Referensi

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [OpenID Connect Specification](https://openid.net/specs/openid-connect-core-1_0.html)

---

**Dibuat dengan ❤️ untuk Dinas Pendidikan DKI Jakarta**

Jika ada pertanyaan atau butuh bantuan, silakan hubungi tim IT Pusdatin.
