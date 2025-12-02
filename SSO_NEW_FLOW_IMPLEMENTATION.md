# 🔐 Implementasi SSO Flow Baru - Client Website (localhost:8070)

**Update Flow:** Portal SSO redirect tanpa token → Client check session → Auto-login via Keycloak

---

## 📋 Daftar Isi

1. [Perbedaan Flow Lama vs Baru](#perbedaan-flow-lama-vs-baru)
2. [Arsitektur Flow Baru](#arsitektur-flow-baru)
3. [Diagram Flow Lengkap](#diagram-flow-lengkap)
4. [Implementasi Backend (Go)](#implementasi-backend-go)
5. [Implementasi Frontend (JavaScript)](#implementasi-frontend-javascript)
6. [Environment Variables](#environment-variables)
7. [Testing](#testing)

---

## Perbedaan Flow Lama vs Baru

### ❌ **Flow Lama (SSO Simple)**
```
Portal SSO → Client (dengan sso_token di URL)
localhost:3000 → localhost:8070/?sso_token=ABC123&sso_id_token=XYZ789
```
**Masalah:** Token terexpose di URL

### ✅ **Flow Baru (Standard OIDC)**
```
Portal SSO → Client (tanpa token)
localhost:3000 → localhost:8070

Client cek session → jika tidak ada → redirect ke Keycloak
localhost:8070 → localhost:8080/auth (dengan prompt=none untuk auto-login)
```
**Keuntungan:**
- ✅ Token tidak terexpose di URL
- ✅ Auto-login untuk semua website
- ✅ Centralized logout
- ✅ Standard OIDC flow

---

## Arsitektur Flow Baru

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│  Portal SSO     │         │  Client Website  │         │  Keycloak IdP   │
│ (localhost:3000)│         │ (localhost:8070) │         │ (localhost:8080)│
└────────┬────────┘         └────────┬─────────┘         └────────┬────────┘
         │                            │                            │
         │ 1. User klik aplikasi      │                            │
         │    (tanpa token)           │                            │
         ├───────────────────────────►│                            │
         │  URL: localhost:8070       │                            │
         │                            │                            │
         │                            │ 2. Cek session lokal       │
         │                            │    (cookie/sessionStorage) │
         │                            │                            │
         │                            │ 3. Session tidak ada       │
         │                            │    Redirect ke Keycloak    │
         │                            │    dengan prompt=none      │
         │                            ├───────────────────────────►│
         │                            │                            │
         │                            │ 4. Keycloak cek SSO cookie │
         │                            │    (session Keycloak)      │
         │                            │                            │
         │                            │◄─── 5a. Ada session ───────┤
         │                            │     Return auth code       │
         │                            │     (auto-login)           │
         │                            │                            │
         │                            │ 6. Exchange code → token   │
         │                            ├───────────────────────────►│
         │                            │◄───────────────────────────┤
         │                            │    Access Token            │
         │                            │                            │
         │                            │ 7. Create session lokal    │
         │                            │    Set cookie              │
         │                            │                            │
         │                            │ 8. Tampil Dashboard        │
         │                            │                            │
         │                            │                            │
         │                     ATAU   │                            │
         │                            │                            │
         │                            │◄─ 5b. Tidak ada session ───┤
         │                            │    Error: login_required   │
         │                            │                            │
         │                            │ 6. Redirect ke Keycloak    │
         │                            │    TANPA prompt=none       │
         │                            │    (tampilkan form login)  │
         │                            ├───────────────────────────►│
         │                            │                            │
         │                            │◄─── 7. Login Form ─────────┤
         │                            │                            │
```

---

## Diagram Flow Lengkap

### 🔐 **Scenario 1: User Belum Login di Keycloak**

```
User                   Client (8070)        Keycloak          Portal SSO (3000)
 │                         │                    │                   │
 ├─ 1. Klik Card ─────────────────────────────────────────────────►│
 │    di Portal SSO        │                    │                   │
 │                         │                    │                   │
 ├─ 2. Redirect (tanpa token)                   │                   │
 │    localhost:8070       ◄────────────────────────────────────────┤
 │                         │                    │                   │
 ├─ 3. Akses Client ──────►│                    │                   │
 │    localhost:8070       │                    │                   │
 │                         │                    │                   │
 │                         │ 4. Cek session     │                   │
 │                         │    - Cookie?       │                   │
 │                         │    - SessionStorage?                   │
 │                         │    → TIDAK ADA     │                   │
 │                         │                    │                   │
 │                         │ 5. Redirect dengan │                   │
 │                         │    prompt=none     │                   │
 │◄────────────────────────┤                    │                   │
 │  Redirect ke Keycloak:  │                    │                   │
 │  /auth?prompt=none...   │                    │                   │
 │                         │                    │                   │
 ├─ 6. Request ke Keycloak ───────────────────►│                   │
 │    dengan prompt=none   │                    │                   │
 │                         │                    │                   │
 │                         │                    │ 7. Cek SSO Cookie │
 │                         │                    │    → TIDAK ADA    │
 │                         │                    │                   │
 │◄───────────── 8. Error: login_required ──────┤                   │
 │    (redirect dengan error param)             │                   │
 │                         │                    │                   │
 ├─ 9. Back to Client ────►│                    │                   │
 │    dengan ?error=login_required              │                   │
 │                         │                    │                   │
 │                         │ 10. Detect error   │                   │
 │                         │     Redirect tanpa │                   │
 │                         │     prompt=none    │                   │
 │◄────────────────────────┤                    │                   │
 │  Redirect ke Keycloak:  │                    │                   │
 │  /auth (tanpa prompt)   │                    │                   │
 │                         │                    │                   │
 ├─ 11. Request Keycloak ────────────────────►│                   │
 │    (FORM LOGIN MUNCUL)  │                    │                   │
 │                         │                    │                   │
 ├─ 12. User login ───────────────────────────►│                   │
 │    (input username/pass)│                    │                   │
 │                         │                    │                   │
 │◄──────────── 13. Authorization Code ─────────┤                   │
 │    (redirect ke 8070/?code=ABC123)           │                   │
 │                         │                    │                   │
 ├─ 14. Send code ────────►│                    │                   │
 │                         │                    │                   │
 │                         │ 15. Exchange code  │                   │
 │                         ├───────────────────►│                   │
 │                         │                    │                   │
 │                         │◄─ 16. Access Token ┤                   │
 │                         │                    │                   │
 │                         │ 17. Create session │                   │
 │                         │     Set cookie     │                   │
 │                         │                    │                   │
 │◄─ 18. Redirect Dashboard┤                    │                   │
 │    (Logged In)          │                    │                   │
```

---

### 🔄 **Scenario 2: User Sudah Login di Keycloak (Auto-Login)**

```
User                   Client (8070)        Keycloak          Portal SSO (3000)
 │                         │                    │                   │
 ├─ 1. Klik Card ─────────────────────────────────────────────────►│
 │    di Portal SSO        │                    │                   │
 │    (user sudah login)   │                    │                   │
 │                         │                    │                   │
 ├─ 2. Redirect (tanpa token)                   │                   │
 │    localhost:8070       ◄────────────────────────────────────────┤
 │                         │                    │                   │
 ├─ 3. Akses Client ──────►│                    │                   │
 │                         │                    │                   │
 │                         │ 4. Cek session     │                   │
 │                         │    → TIDAK ADA     │                   │
 │                         │                    │                   │
 │                         │ 5. Redirect dengan │                   │
 │                         │    prompt=none     │                   │
 │◄────────────────────────┤                    │                   │
 │                         │                    │                   │
 ├─ 6. Request Keycloak ─────────────────────►│                   │
 │    dengan prompt=none   │                    │                   │
 │                         │                    │                   │
 │                         │                    │ 7. Cek Cookie     │
 │                         │                    │    ✅ ADA SESSION │
 │                         │                    │                   │
 │◄───────────── 8. Authorization Code ──────────┤                   │
 │    (redirect auto, tanpa form login!)        │                   │
 │                         │                    │                   │
 ├─ 9. Send code ─────────►│                    │                   │
 │                         │                    │                   │
 │                         │ 10. Exchange code  │                   │
 │                         ├───────────────────►│                   │
 │                         │                    │                   │
 │                         │◄─ 11. Access Token ┤                   │
 │                         │                    │                   │
 │                         │ 12. Create session │                   │
 │                         │     Set cookie     │                   │
 │                         │                    │                   │
 │◄─ 13. Redirect Dashboard┤                    │                   │
 │    (Auto Logged In!)    │                    │                   │
 │    TANPA FORM LOGIN!    │                    │                   │
```

**⚡ Kunci Auto-Login:** Parameter `prompt=none` membuat Keycloak cek session tanpa tampilkan form!

---

## Implementasi Backend (Go)

### 1. **Environment Variables**

Tambahkan ke `.env`:

```bash
# Keycloak Configuration
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=dinas-pendidikan
KEYCLOAK_CLIENT_ID=localhost-8070-website-dinas-pendidikan
KEYCLOAK_REDIRECT_URI=http://localhost:8070/callback
```

### 2. **Helper Functions di `main_handler.go`**

```go
// getKeycloakBaseURL returns KEYCLOAK_BASE_URL from environment
func getKeycloakBaseURL() string {
	if url := os.Getenv("KEYCLOAK_BASE_URL"); url != "" {
		return url
	}
	return "http://localhost:8080" // default
}

// getKeycloakRealm returns KEYCLOAK_REALM from environment
func getKeycloakRealm() string {
	if realm := os.Getenv("KEYCLOAK_REALM"); realm != "" {
		return realm
	}
	return "dinas-pendidikan" // default
}

// getKeycloakClientID returns KEYCLOAK_CLIENT_ID from environment
func getKeycloakClientID() string {
	if clientID := os.Getenv("KEYCLOAK_CLIENT_ID"); clientID != "" {
		return clientID
	}
	return "localhost-8070-website-dinas-pendidikan" // default
}

// getKeycloakRedirectURI returns KEYCLOAK_REDIRECT_URI from environment
func getKeycloakRedirectURI() string {
	if uri := os.Getenv("KEYCLOAK_REDIRECT_URI"); uri != "" {
		return uri
	}
	return "http://localhost:8070/callback" // default
}
```

### 3. **Update Root Handler (`/`)**

```go
case "/", "/home":
	// FLOW BARU: Check session, jika tidak ada redirect ke Keycloak dengan prompt=none
	
	// 1. Check apakah ada authorization code dari Keycloak callback
	code := r.URL.Query().Get("code")
	errorParam := r.URL.Query().Get("error")
	
	if code != "" {
		// Ada code, redirect ke /callback untuk process
		http.Redirect(w, r, "/callback?"+r.URL.RawQuery, http.StatusSeeOther)
		return
	}
	
	if errorParam != "" {
		// Ada error dari Keycloak (prompt=none gagal)
		if errorParam == "login_required" || errorParam == "interaction_required" {
			// User belum login di Keycloak, redirect ke login (tanpa prompt=none)
			redirectToKeycloakLogin(w, r, false) // false = tanpa prompt=none
			return
		}
		// Error lain, tampilkan pesan
		http.Error(w, "SSO Error: "+errorParam, http.StatusBadRequest)
		return
	}
	
	// 2. Check session lokal
	if isAuthenticated(r) {
		// Sudah login, redirect ke dashboard
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	
	// 3. Belum login, check Keycloak session dengan prompt=none
	redirectToKeycloakLogin(w, r, true) // true = dengan prompt=none
```

### 4. **Function: Redirect ke Keycloak**

```go
// redirectToKeycloakLogin redirects user ke Keycloak untuk login
// withPromptNone: true = auto-login (prompt=none), false = tampilkan form login
func redirectToKeycloakLogin(w http.ResponseWriter, r *http.Request, withPromptNone bool) {
	// Build authorization URL
	keycloakBaseURL := getKeycloakBaseURL()
	realm := getKeycloakRealm()
	clientID := getKeycloakClientID()
	redirectURI := getKeycloakRedirectURI()
	
	// Generate state untuk CSRF protection
	state, err := helpers.GenerateRandomString(32)
	if err != nil {
		log.Printf("ERROR generating state: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	// Store state di session/cookie untuk verify nanti
	helpers.SetCookie(w, r, "oauth_state", state, 300) // 5 minutes
	
	// Build auth URL
	params := url.Values{}
	params.Add("client_id", clientID)
	params.Add("redirect_uri", redirectURI)
	params.Add("response_type", "code")
	params.Add("scope", "openid email profile")
	params.Add("state", state)
	
	if withPromptNone {
		params.Add("prompt", "none") // ⚡ KUNCI AUTO-LOGIN
	}
	
	authURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth?%s",
		keycloakBaseURL, realm, params.Encode())
	
	log.Printf("🔐 Redirecting to Keycloak (prompt=none: %v): %s", withPromptNone, authURL)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}
```

### 5. **Handler: OAuth Callback (`/callback`)**

```go
case "/callback":
	// Handle callback dari Keycloak
	handleOAuthCallback(w, r)
	return

// handleOAuthCallback processes OAuth callback dari Keycloak
func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	// 1. Get code dan state dari query params
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")
	
	// Check error dari Keycloak
	if errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		log.Printf("❌ OAuth error: %s - %s", errorParam, errorDesc)
		
		if errorParam == "login_required" || errorParam == "interaction_required" {
			// Redirect ke Keycloak dengan form login (tanpa prompt=none)
			redirectToKeycloakLogin(w, r, false)
			return
		}
		
		http.Error(w, "OAuth Error: "+errorParam, http.StatusBadRequest)
		return
	}
	
	// 2. Verify state (CSRF protection)
	storedState, err := helpers.GetCookie(r, "oauth_state")
	if err != nil || state != storedState {
		log.Printf("❌ State mismatch or missing: stored=%s, received=%s", storedState, state)
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	
	// Clear state cookie
	helpers.DeleteCookie(w, "oauth_state")
	
	// 3. Verify code
	if code == "" {
		log.Printf("❌ Missing authorization code")
		http.Error(w, "Missing code", http.StatusBadRequest)
		return
	}
	
	log.Printf("✅ Received authorization code: %s...", code[:10])
	
	// 4. Exchange code untuk access token
	tokenData, err := exchangeCodeForToken(code)
	if err != nil {
		log.Printf("❌ Failed to exchange code: %v", err)
		http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
		return
	}
	
	log.Printf("✅ Token exchange successful")
	
	// 5. Get user info dari token (decode ID token)
	userInfo, err := getUserInfoFromToken(tokenData.IDToken)
	if err != nil {
		log.Printf("❌ Failed to get user info: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	
	log.Printf("✅ User info: email=%s, name=%s", userInfo["email"], userInfo["name"])
	
	// 6. Create session lokal
	email := userInfo["email"].(string)
	sessionID, err := createSessionFromEmail(email, r)
	if err != nil {
		log.Printf("❌ Failed to create session: %v", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	
	// 7. Set cookie
	helpers.SetCookie(w, r, "client_dinas_session", sessionID, 86400) // 24 hours
	
	log.Printf("✅ Session created: %s", sessionID)
	
	// 8. Redirect ke dashboard
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
```

### 6. **Function: Exchange Code for Token**

```go
// TokenResponse represents OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// exchangeCodeForToken exchanges authorization code untuk access token
func exchangeCodeForToken(code string) (*TokenResponse, error) {
	keycloakBaseURL := getKeycloakBaseURL()
	realm := getKeycloakRealm()
	clientID := getKeycloakClientID()
	redirectURI := getKeycloakRedirectURI()
	
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		keycloakBaseURL, realm)
	
	// Prepare form data
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientID)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	
	// Send POST request
	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s - %s", resp.Status, string(body))
	}
	
	// Parse response
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}
	
	return &tokenResp, nil
}
```

### 7. **Function: Get User Info from ID Token**

```go
// getUserInfoFromToken extracts user info dari ID token (JWT)
func getUserInfoFromToken(idToken string) (map[string]interface{}, error) {
	// Parse JWT token (tanpa verify signature untuk simplicity)
	// PRODUCTION: Harus verify signature dengan public key dari Keycloak
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}
	
	// Decode payload (part 2)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}
	
	// Parse JSON
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %v", err)
	}
	
	// Extract user info
	userInfo := map[string]interface{}{
		"sub":                claims["sub"],
		"email":              claims["email"],
		"name":               claims["name"],
		"preferred_username": claims["preferred_username"],
		"email_verified":     claims["email_verified"],
	}
	
	return userInfo, nil
}
```

---

## Implementasi Frontend (JavaScript)

### 1. **Update `sso-handler.js`**

Buat file baru atau update existing `api/static/sso-handler-new.js`:

```javascript
/**
 * SSO Handler - New Flow (Standard OIDC with prompt=none)
 * File: static/sso-handler-new.js
 */

console.log('🚀 SSO Handler (New Flow) initialized');

// Configuration
const SSO_CONFIG = {
    keycloakBaseUrl: 'http://localhost:8080',
    realm: 'dinas-pendidikan',
    clientId: 'localhost-8070-website-dinas-pendidikan',
    redirectUri: window.location.origin + '/callback'
};

/**
 * Check if user has local session
 */
function hasLocalSession() {
    // Check cookie
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'client_dinas_session' && value) {
            console.log('✅ Local session found');
            return true;
        }
    }
    
    console.log('❌ No local session');
    return false;
}

/**
 * Redirect ke Keycloak untuk login
 * @param {boolean} withPromptNone - true untuk auto-login, false untuk form login
 */
function redirectToKeycloak(withPromptNone = true) {
    // Generate state untuk CSRF protection
    const state = generateRandomString(32);
    sessionStorage.setItem('oauth_state', state);
    
    // Build authorization URL
    const params = new URLSearchParams({
        client_id: SSO_CONFIG.clientId,
        redirect_uri: SSO_CONFIG.redirectUri,
        response_type: 'code',
        scope: 'openid email profile',
        state: state
    });
    
    if (withPromptNone) {
        params.append('prompt', 'none'); // ⚡ Auto-login
        console.log('🔐 Redirecting to Keycloak with prompt=none (auto-login)');
    } else {
        console.log('🔐 Redirecting to Keycloak (form login)');
    }
    
    const authUrl = `${SSO_CONFIG.keycloakBaseUrl}/realms/${SSO_CONFIG.realm}/protocol/openid-connect/auth?${params.toString()}`;
    window.location.href = authUrl;
}

/**
 * Generate random string untuk state
 */
function generateRandomString(length) {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    let result = '';
    const values = new Uint8Array(length);
    crypto.getRandomValues(values);
    for (let i = 0; i < length; i++) {
        result += charset[values[i] % charset.length];
    }
    return result;
}

/**
 * Handle OAuth callback
 */
function handleOAuthCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const error = urlParams.get('error');
    const state = urlParams.get('state');
    
    if (error) {
        console.error('❌ OAuth error:', error);
        
        if (error === 'login_required' || error === 'interaction_required') {
            console.log('🔄 Auto-login failed, showing login form');
            // Redirect dengan form login (tanpa prompt=none)
            redirectToKeycloak(false);
            return;
        }
        
        alert('Error dari SSO: ' + error);
        return;
    }
    
    if (code) {
        console.log('✅ Authorization code received');
        
        // Verify state
        const storedState = sessionStorage.getItem('oauth_state');
        if (state !== storedState) {
            console.error('❌ State mismatch');
            alert('Invalid state. Silakan coba lagi.');
            return;
        }
        
        // Backend akan handle exchange code
        // Kita hanya perlu clear URL dan wait untuk redirect
        console.log('🔄 Processing authorization code...');
        
        return true;
    }
    
    return false;
}

/**
 * Initialize on page load
 */
document.addEventListener('DOMContentLoaded', function() {
    console.log('📋 Current URL:', window.location.href);
    
    // Jika di halaman callback, handle OAuth callback
    if (window.location.pathname === '/callback') {
        handleOAuthCallback();
        return;
    }
    
    // Jika bukan halaman login/public, check session
    const publicPages = ['/login', '/register', '/about'];
    if (!publicPages.includes(window.location.pathname)) {
        if (!hasLocalSession()) {
            console.log('🔄 No session, checking Keycloak...');
            // Backend akan handle redirect ke Keycloak
        }
    }
});
```

---

## Environment Variables

Update file `.env`:

```bash
# PostgreSQL Configuration (Database Utama)
POSTGRES_HOST=localhost
POSTGRES_PORT=5433
POSTGRES_DB=dinas_pendidikan
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres123

# Supabase Configuration (untuk session storage)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key

# Keycloak Configuration (NEW!)
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=dinas-pendidikan
KEYCLOAK_CLIENT_ID=localhost-8070-website-dinas-pendidikan
KEYCLOAK_REDIRECT_URI=http://localhost:8070/callback

# Server Configuration
PORT=8070
```

---

## Testing

### 1. **Test Auto-Login Flow**

```bash
# Terminal 1: Start Keycloak (jika belum running)
cd /path/to/keycloak
bin/kc.sh start-dev --http-port=8080

# Terminal 2: Start Portal SSO (jika belum running)
cd /path/to/portal-sso
npm run dev # atau yarn dev

# Terminal 3: Start Client Website
cd /path/to/client-dinas-pendidikan
go run dev.go
```

**Steps:**
1. Buka browser: `http://localhost:3000` (Portal SSO)
2. Login dengan user test (misal: `bagas123` / `password`)
3. Klik card aplikasi "Client Website 8070"
4. Portal SSO redirect ke: `http://localhost:8070` (TANPA token)
5. Client check session → tidak ada
6. Client redirect ke Keycloak dengan `prompt=none`
7. Keycloak detect session → auto-return authorization code
8. Client exchange code → dapat token
9. Client create session → set cookie
10. ✅ Dashboard muncul (TANPA form login!)

### 2. **Test Login Form Flow**

```bash
# Buka incognito/private window
```

**Steps:**
1. Akses langsung: `http://localhost:8070`
2. Client check session → tidak ada
3. Client redirect ke Keycloak dengan `prompt=none`
4. Keycloak detect tidak ada session → return error `login_required`
5. Client detect error → redirect ke Keycloak TANPA `prompt=none`
6. ✅ Form login Keycloak muncul
7. Login dengan user test
8. ✅ Dashboard muncul

### 3. **Test Logout Terpusat**

Implementasi logout handler:

```go
case "/logout":
	handleLogout(w, r)
	return

func handleLogout(w http.ResponseWriter, r *http.Request) {
	// 1. Get ID token untuk Keycloak logout
	idToken, _ := helpers.GetCookie(r, "sso_id_token")
	
	// 2. Clear session lokal
	sessionID, _ := helpers.GetCookie(r, "client_dinas_session")
	if sessionID != "" {
		deleteSession(sessionID)
	}
	
	// 3. Clear cookies
	helpers.DeleteCookie(w, "client_dinas_session")
	helpers.DeleteCookie(w, "sso_id_token")
	helpers.DeleteCookie(w, "sso_access_token")
	
	// 4. Redirect ke Keycloak logout
	if idToken != "" {
		keycloakBaseURL := getKeycloakBaseURL()
		realm := getKeycloakRealm()
		
		logoutParams := url.Values{}
		logoutParams.Add("id_token_hint", idToken)
		logoutParams.Add("post_logout_redirect_uri", "http://localhost:3000") // Portal SSO
		
		logoutURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout?%s",
			keycloakBaseURL, realm, logoutParams.Encode())
		
		http.Redirect(w, r, logoutURL, http.StatusSeeOther)
	} else {
		// Fallback jika tidak ada ID token
		http.Redirect(w, r, "http://localhost:3000", http.StatusSeeOther)
	}
}
```

---

## 🎯 Summary

### ✅ **Yang Berubah:**
1. Portal SSO redirect **TANPA token** (hanya plain URL)
2. Client website **cek session lokal** terlebih dahulu
3. Jika tidak ada session, redirect ke Keycloak dengan **`prompt=none`**
4. Keycloak auto-login jika ada session (SSO)
5. Jika tidak ada session, tampilkan form login

### ✅ **Keuntungan:**
- Token tidak terexpose di URL
- Auto-login untuk semua website
- Centralized logout
- Standard OIDC flow (lebih aman)

### 📚 **Next Steps:**
1. Update environment variables
2. Implement backend changes di `main_handler.go`
3. Update frontend `sso-handler.js`
4. Test flow lengkap
5. Deploy!

---

**Happy Coding! 🚀**
