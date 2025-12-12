package main

// ===============================================================================
// KEYCLOAK SSO HELPER
// ===============================================================================
// File ini berisi semua fungsi helper untuk integrasi SSO Keycloak.
// Dapat di-copy dan digunakan oleh website client lain.
//
// CARA PENGGUNAAN:
// 1. Copy file ini ke project Anda
// 2. Set environment variables (lihat section Configuration)
// 3. Panggil fungsi yang tersedia dari handler Anda
//
// FLOW SSO:
// [User] -> [Login Button] -> RedirectToKeycloak() -> [Keycloak Login]
//        <- [Dashboard]    <- HandleCallback()     <- [Callback URL]
// ===============================================================================

import (
	"client-dinas-pendidikan/pkg/helpers"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ===============================================================================
// SECTION 1: KONFIGURASI
// ===============================================================================
// Environment variables yang harus di-set:
// - KEYCLOAK_BASE_URL   : URL server Keycloak (e.g. http://localhost:8080)
// - KEYCLOAK_REALM      : Nama realm di Keycloak (e.g. dinas-pendidikan)
// - KEYCLOAK_CLIENT_ID  : Client ID yang terdaftar di Keycloak
// - KEYCLOAK_REDIRECT_URI: URL callback di website Anda (e.g. http://localhost:8070/callback)
// ===============================================================================

// KeycloakConfig menyimpan konfigurasi SSO Keycloak
// (Menggunakan nama berbeda untuk menghindari konflik dengan SSOConfig lama)
type KeycloakConfig struct {
	BaseURL     string // URL Keycloak (e.g. http://localhost:8080)
	Realm       string // Nama realm
	ClientID    string // Client ID
	RedirectURI string // Callback URL
}

// GetKeycloakConfig mengambil konfigurasi SSO dari environment variables
func GetKeycloakConfig() KeycloakConfig {
	return KeycloakConfig{
		BaseURL:     getEnvDefault("KEYCLOAK_BASE_URL", "http://localhost:8080"),
		Realm:       getEnvDefault("KEYCLOAK_REALM", "dinas-pendidikan"),
		ClientID:    getEnvDefault("KEYCLOAK_CLIENT_ID", "localhost-8070-website-dinas-pendidikan"),
		RedirectURI: getEnvDefault("KEYCLOAK_REDIRECT_URI", "http://localhost:8070/callback"),
	}
}

func getEnvDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// ===============================================================================
// SECTION 2: PKCE (Proof Key for Code Exchange)
// ===============================================================================
// PKCE adalah standar keamanan untuk OAuth 2.0 yang mencegah code interception.
// Wajib digunakan untuk Public Client (SPA, Mobile App, atau Web tanpa secret).
// ===============================================================================

// PKCE menyimpan code_verifier dan code_challenge
type PKCE struct {
	Verifier  string // Random string 43-128 chars (simpan di cookie/session)
	Challenge string // SHA256(Verifier) + Base64URL encode (kirim ke Keycloak)
}

// GeneratePKCE membuat PKCE verifier dan challenge
// PKCE (Proof Key for Code Exchange) adalah proteksi tambahan untuk OAuth
func GeneratePKCE() (*PKCE, error) {
	// 1. Generate random bytes untuk verifier (43 chars minimum)
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %v", err)
	}

	// 2. Encode ke base64url (safe characters)
	verifier := base64.RawURLEncoding.EncodeToString(randomBytes)

	// 3. Create challenge = Base64URL(SHA256(verifier))
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return &PKCE{
		Verifier:  verifier,
		Challenge: challenge,
	}, nil
}

// ===============================================================================
// SECTION 3: REDIRECT KE KEYCLOAK
// ===============================================================================
// Fungsi ini mengarahkan user ke halaman login Keycloak.
// Setelah login berhasil, Keycloak akan redirect kembali ke callback URL.
// ===============================================================================

// RedirectToKeycloakLogin mengarahkan user ke Keycloak untuk login
// 
// Parameter:
// - w, r: HTTP writer dan request
// - silentCheck: true = cek login tanpa tampilkan form (untuk auto-login)
//
// Contoh penggunaan:
//   // Dari handler login
//   func LoginHandler(w http.ResponseWriter, r *http.Request) {
//       RedirectToKeycloakLogin(w, r, false)
//   }
func RedirectToKeycloakLogin(w http.ResponseWriter, r *http.Request, silentCheck bool) {
	config := GetKeycloakConfig()

	// 1. Generate State (CSRF protection)
	stateBytes := make([]byte, 16)
	rand.Read(stateBytes)
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	// 2. Generate PKCE
	pkce, err := GeneratePKCE()
	if err != nil {
		log.Printf("ERROR: Failed to generate PKCE: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 3. Simpan state & verifier di cookie (akan divalidasi saat callback)
	helpers.SetCookie(w, r, "oauth_state", state, 300)          // 5 menit
	helpers.SetCookie(w, r, "oauth_code_verifier", pkce.Verifier, 300) // 5 menit

	// 4. Build authorization URL
	params := url.Values{
		"client_id":             {config.ClientID},
		"redirect_uri":          {config.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {"S256"},
	}

	// Silent check: Keycloak akan return error jika user belum login
	if silentCheck {
		params.Set("prompt", "none")
	}

	authURL := fmt.Sprintf("%s/sso-auth/realms/%s/protocol/openid-connect/auth?%s",
		config.BaseURL, config.Realm, params.Encode())

	log.Printf("🔐 Redirecting to Keycloak (silent=%v): %s", silentCheck, authURL)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// ===============================================================================
// SECTION 4: TOKEN RESPONSE
// ===============================================================================

// TokenResponse adalah response dari Keycloak setelah exchange code
type KeycloakTokenResp struct {
	AccessToken  string `json:"access_token"`  // Token untuk akses API
	TokenType    string `json:"token_type"`    // Biasanya "Bearer"
	ExpiresIn    int    `json:"expires_in"`    // Durasi token dalam detik
	RefreshToken string `json:"refresh_token"` // Token untuk refresh
	IDToken      string `json:"id_token"`      // JWT berisi info user
}

// ===============================================================================
// SECTION 5: EXCHANGE CODE UNTUK TOKEN
// ===============================================================================
// Setelah user login di Keycloak, kita dapat authorization code.
// Code ini ditukar dengan access token dan ID token.
// ===============================================================================

// ExchangeCodeForToken menukar authorization code dengan access token
//
// Parameter:
// - w, r: HTTP writer dan request
// - code: Authorization code dari callback URL
//
// Return:
// - TokenResponse berisi access_token, id_token, dll
// - error jika gagal
func ExchangeCodeForToken(w http.ResponseWriter, r *http.Request, code string) (*KeycloakTokenResp, error) {
	config := GetKeycloakConfig()

	// 1. Ambil code_verifier dari cookie
	codeVerifier, err := helpers.GetCookie(r, "oauth_code_verifier")
	if err != nil || codeVerifier == "" {
		return nil, fmt.Errorf("missing code verifier - pastikan cookie oauth_code_verifier tersimpan")
	}

	// 2. Hapus cookie verifier (hanya boleh dipakai sekali)
	helpers.DeleteCookie(w, "oauth_code_verifier")

	// 3. Prepare request ke token endpoint
	tokenURL := fmt.Sprintf("%s/sso-auth/realms/%s/protocol/openid-connect/token",
		config.BaseURL, config.Realm)

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {config.ClientID},
		"code":          {code},
		"redirect_uri":  {config.RedirectURI},
		"code_verifier": {codeVerifier}, // PKCE verifier
	}

	log.Printf("🔄 Exchanging code for token at: %s", tokenURL)

	// 4. Kirim POST request
	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// 5. Cek response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed (%d): %s", resp.StatusCode, string(body))
	}

	// 6. Parse response JSON
	var tokenResp KeycloakTokenResp
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	log.Printf("✅ Token exchange successful")
	return &tokenResp, nil
}

// ===============================================================================
// SECTION 6: PARSE ID TOKEN (JWT)
// ===============================================================================
// ID Token adalah JWT yang berisi informasi user.
// Kita parse untuk mendapatkan email, nama, dll.
// ===============================================================================

// UserInfo berisi informasi user dari SSO
type KeycloakUserInfo struct {
	Sub               string // Unique ID dari Keycloak
	Email             string // Email user
	Name              string // Nama lengkap
	PreferredUsername string // Username
	EmailVerified     bool   // Email sudah diverifikasi
}

// ParseIDToken mengekstrak informasi user dari ID Token
//
// Parameter:
// - idToken: JWT dari TokenResponse.IDToken
//
// Return:
// - UserInfo berisi data user
// - error jika token tidak valid
//
// CATATAN: Untuk production, sebaiknya verify signature token
// menggunakan public key dari Keycloak
func ParseIDToken(idToken string) (*KeycloakUserInfo, error) {
	// 1. Split JWT (format: header.payload.signature)
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// 2. Decode payload (bagian ke-2)
	payload := parts[1]
	
	// JWT menggunakan base64url, perlu padding
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	// 3. Parse JSON claims
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %v", err)
	}

	// 4. Extract user info
	userInfo := &KeycloakUserInfo{}
	
	if sub, ok := claims["sub"].(string); ok {
		userInfo.Sub = sub
	}
	if email, ok := claims["email"].(string); ok {
		userInfo.Email = email
	}
	if name, ok := claims["name"].(string); ok {
		userInfo.Name = name
	}
	if username, ok := claims["preferred_username"].(string); ok {
		userInfo.PreferredUsername = username
	}
	if verified, ok := claims["email_verified"].(bool); ok {
		userInfo.EmailVerified = verified
	}

	// Fallback: ambil identifier dari sub jika email/username kosong
	if userInfo.Email == "" && userInfo.PreferredUsername == "" {
		if userInfo.Sub != "" {
			parts := strings.Split(userInfo.Sub, ":")
			if len(parts) >= 3 {
				userInfo.PreferredUsername = parts[len(parts)-1]
			}
		}
	}

	log.Printf("✅ Parsed user info: email=%s, name=%s", userInfo.Email, userInfo.Name)
	return userInfo, nil
}

// ===============================================================================
// SECTION 7: LOGOUT
// ===============================================================================

// GetLogoutURL menghasilkan URL untuk logout dari Keycloak
//
// Parameter:
// - idToken: ID token untuk hint ke Keycloak
// - postLogoutRedirectURI: URL redirect setelah logout
//
// Return:
// - URL string untuk redirect ke Keycloak logout
func GetLogoutURL(idToken, postLogoutRedirectURI string) string {
	config := GetKeycloakConfig()
	
	params := url.Values{
		"client_id":                {config.ClientID},
		"post_logout_redirect_uri": {postLogoutRedirectURI},
	}
	
	if idToken != "" {
		params.Set("id_token_hint", idToken)
	}

	return fmt.Sprintf("%s/sso-auth/realms/%s/protocol/openid-connect/logout?%s",
		config.BaseURL, config.Realm, params.Encode())
}

// ===============================================================================
// SECTION 8: CALLBACK HANDLER
// ===============================================================================
// Handler untuk memproses callback dari Keycloak setelah login.
// ===============================================================================

// HandleOAuthCallback memproses callback dari Keycloak
// 
// Flow:
// 1. Validasi state (CSRF protection)
// 2. Exchange code untuk token
// 3. Parse ID token untuk dapat user info
// 4. Buat session lokal
// 5. Redirect ke dashboard
func HandleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔐 Processing OAuth callback...")

	// 1. Cek error dari Keycloak
	if errorParam := r.URL.Query().Get("error"); errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		log.Printf("❌ OAuth error: %s - %s", errorParam, errorDesc)

		// Handle silent check failure
		if errorParam == "login_required" || errorParam == "interaction_required" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		http.Error(w, fmt.Sprintf("OAuth error: %s", errorDesc), http.StatusBadRequest)
		return
	}

	// 2. Ambil code dan state
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// 3. Validasi state (CSRF protection)
	storedState, _ := helpers.GetCookie(r, "oauth_state")
	if state != storedState {
		log.Printf("❌ State mismatch: expected=%s, got=%s", storedState, state)
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	helpers.DeleteCookie(w, "oauth_state")

	// 4. Validasi code
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	log.Printf("✅ Received authorization code: %s...", code[:min(10, len(code))])

	// 5. Exchange code untuk token
	tokenResp, err := ExchangeCodeForToken(w, r, code)
	if err != nil {
		log.Printf("❌ Token exchange failed: %v", err)
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}

	// 6. Parse ID token
	userInfo, err := ParseIDToken(tokenResp.IDToken)
	if err != nil {
		log.Printf("❌ Failed to parse ID token: %v", err)
		http.Error(w, "Failed to parse token", http.StatusInternalServerError)
		return
	}

	// 7. Tentukan identifier (email atau username)
	identifier := userInfo.Email
	if identifier == "" {
		identifier = userInfo.PreferredUsername
	}
	if identifier == "" {
		http.Error(w, "No identifier found", http.StatusBadRequest)
		return
	}

	log.Printf("✅ User authenticated: %s (%s)", userInfo.Name, identifier)

	// 8. Buat session lokal (implementasi tergantung kebutuhan Anda)
	sessionID, ok := createSessionFromIdentifier(r, identifier)
	if !ok || sessionID == "" {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// 9. Set cookies
	helpers.SetCookie(w, r, "client_dinas_session", sessionID, 86400)
	helpers.SetCookie(w, r, "sso_access_token", tokenResp.AccessToken, tokenResp.ExpiresIn)
	helpers.SetCookie(w, r, "sso_id_token", tokenResp.IDToken, tokenResp.ExpiresIn)
	helpers.SetCookie(w, r, "sso_check_time", fmt.Sprintf("%d", time.Now().Unix()), 3600)

	log.Printf("✅ Session created successfully")

	// 10. Redirect ke dashboard
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// ===============================================================================
// SECTION 9: VALIDATE SESSION (OPTIONAL)
// ===============================================================================

// ValidateAccessToken memeriksa apakah access token masih valid
// dengan memanggil userinfo endpoint Keycloak
func ValidateAccessToken(accessToken string) bool {
	if accessToken == "" {
		return false
	}

	config := GetKeycloakConfig()
	userInfoURL := fmt.Sprintf("%s/sso-auth/realms/%s/protocol/openid-connect/userinfo",
		config.BaseURL, config.Realm)

	req, _ := http.NewRequest("GET", userInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("⚠️ Failed to validate token: %v", err)
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// ===============================================================================
// SECTION 10: HELPER FUNCTIONS
// ===============================================================================

// min returns minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ===============================================================================
// LEGACY FUNCTIONS (untuk backward compatibility)
// Fungsi-fungsi di bawah ini memanggil fungsi baru di atas
// ===============================================================================

// getKeycloakBaseURL - Legacy, gunakan GetKeycloakConfig().BaseURL
func getKeycloakBaseURL() string {
	return GetKeycloakConfig().BaseURL
}

// getKeycloakRealm - Legacy, gunakan GetKeycloakConfig().Realm
func getKeycloakRealm() string {
	return GetKeycloakConfig().Realm
}

// getKeycloakClientID - Legacy, gunakan GetKeycloakConfig().ClientID
func getKeycloakClientID() string {
	return GetKeycloakConfig().ClientID
}

// getKeycloakRedirectURI - Legacy, gunakan GetKeycloakConfig().RedirectURI
func getKeycloakRedirectURI() string {
	return GetKeycloakConfig().RedirectURI
}

// redirectToKeycloakLogin - Legacy, gunakan RedirectToKeycloakLogin
func redirectToKeycloakLogin(w http.ResponseWriter, r *http.Request, silentCheck bool) {
	RedirectToKeycloakLogin(w, r, silentCheck)
}

// redirectToKeycloakLogout - Legacy, gunakan GetLogoutURL
func redirectToKeycloakLogout(w http.ResponseWriter, r *http.Request, idToken, redirectURI string) {
	logoutURL := GetLogoutURL(idToken, redirectURI)
	http.Redirect(w, r, logoutURL, http.StatusSeeOther)
}

// KeycloakTokenResponse - Legacy, gunakan TokenResponse
type KeycloakTokenResponse = TokenResponse

// exchangeKeycloakCode - Legacy, gunakan ExchangeCodeForToken
func exchangeKeycloakCode(w http.ResponseWriter, r *http.Request, code string) (*KeycloakTokenResp, error) {
	return ExchangeCodeForToken(w, r, code)
}

// getUserInfoFromIDToken - Legacy, gunakan ParseIDToken dan konversi ke map
func getUserInfoFromIDToken(idToken string) (map[string]interface{}, error) {
	userInfo, err := ParseIDToken(idToken)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"sub":                userInfo.Sub,
		"email":              userInfo.Email,
		"name":               userInfo.Name,
		"preferred_username": userInfo.PreferredUsername,
		"email_verified":     userInfo.EmailVerified,
	}, nil
}

// handleOAuthCallback - Legacy, gunakan HandleOAuthCallback
func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	HandleOAuthCallback(w, r)
}
