package main

import (
	"client-dinas-pendidikan/pkg/helpers"
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

// ============================================
// KEYCLOAK CONFIGURATION HELPERS
// ============================================

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

// ============================================
// REDIRECT TO KEYCLOAK FOR LOGIN
// ============================================

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

	// Generate PKCE Code Verifier & Challenge
	codeVerifier, err := helpers.GenerateRandomString(43) // Min 43 chars for PKCE
	if err != nil {
		log.Printf("ERROR generating code verifier: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	// Create Code Challenge (S256)
	// Challenge = Base64Url(SHA256(Verifier))
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Store state & code_verifier di cookie
	helpers.SetCookie(w, r, "oauth_state", state, 300) // 5 minutes
	helpers.SetCookie(w, r, "oauth_code_verifier", codeVerifier, 300) // 5 minutes

	// Build auth URL
	params := url.Values{}
	params.Add("client_id", clientID)
	params.Add("redirect_uri", redirectURI)
	params.Add("response_type", "code")
	params.Add("scope", "openid email profile")
	params.Add("state", state)
	
	// Add PKCE parameters
	params.Add("code_challenge", codeChallenge)
	params.Add("code_challenge_method", "S256")

	if withPromptNone {
		params.Add("prompt", "none") // ⚡ KUNCI AUTO-LOGIN
	}

	authURL := fmt.Sprintf("%s/sso-auth/realms/%s/protocol/openid-connect/auth?%s",
		keycloakBaseURL, realm, params.Encode())

	log.Printf("🔐 Redirecting to Keycloak (prompt=none: %v, PKCE: yes): %s", withPromptNone, authURL)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// redirectToKeycloakLogout redirects user ke Keycloak untuk logout
func redirectToKeycloakLogout(w http.ResponseWriter, r *http.Request, idToken string, postLogoutRedirectURI string) {
	keycloakBaseURL := getKeycloakBaseURL()
	realm := getKeycloakRealm()
	clientID := getKeycloakClientID()

	// Build logout URL
	// Format: /realms/{realm-name}/protocol/openid-connect/logout
	logoutURL := fmt.Sprintf("%s/sso-auth/realms/%s/protocol/openid-connect/logout?client_id=%s&post_logout_redirect_uri=%s&id_token_hint=%s",
		keycloakBaseURL, realm, clientID, url.QueryEscape(postLogoutRedirectURI), idToken)

	log.Printf("👋 Redirecting to Keycloak Logout: %s", logoutURL)
	http.Redirect(w, r, logoutURL, http.StatusSeeOther)
}

// ============================================
// TOKEN EXCHANGE (NEW KEYCLOAK FLOW)
// ============================================

// KeycloakTokenResponse represents OAuth token response from Keycloak
type KeycloakTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// exchangeKeycloakCode exchanges authorization code untuk access token (Keycloak specific)
func exchangeKeycloakCode(w http.ResponseWriter, r *http.Request, code string) (*KeycloakTokenResponse, error) {
	keycloakBaseURL := getKeycloakBaseURL()
	realm := getKeycloakRealm()
	clientID := getKeycloakClientID()
	redirectURI := getKeycloakRedirectURI()

	// Retrieve code_verifier from cookie
	codeVerifier, err := helpers.GetCookie(r, "oauth_code_verifier")
	if err != nil || codeVerifier == "" {
		return nil, fmt.Errorf("missing code verifier in cookie")
	}
	
	// Delete verifier cookie (single use)
	helpers.DeleteCookie(w, "oauth_code_verifier")

	tokenURL := fmt.Sprintf("%s/sso-auth/realms/%s/protocol/openid-connect/token",
		keycloakBaseURL, realm)

	log.Printf("🔄 Exchanging authorization code for token...")
	log.Printf("   Token URL: %s", tokenURL)
	log.Printf("   Client ID: %s", clientID)
	log.Printf("   Redirect URI: %s", redirectURI)

	// Prepare form data
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientID)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("code_verifier", codeVerifier) // PKCE required

	// Send POST request
	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("❌ Token exchange failed: %s - %s", resp.Status, string(body))
		return nil, fmt.Errorf("token exchange failed: %s - %s", resp.Status, string(body))
	}

	// Parse response
	var tokenResp KeycloakTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	log.Printf("✅ Token exchange successful")
	return &tokenResp, nil
}


// ============================================
// GET USER INFO FROM ID TOKEN
// ============================================

// getUserInfoFromIDToken extracts user info dari ID token (JWT)
// PRODUCTION: Harus verify signature dengan public key dari Keycloak
func getUserInfoFromIDToken(idToken string) (map[string]interface{}, error) {
	// Parse JWT token (tanpa verify signature untuk simplicity)
	// Format JWT: header.payload.signature
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode payload (part 2)
	// JWT uses base64url encoding (RFC 4648), which is different from standard base64
	payload := parts[1]
	
	// Add padding if necessary (base64 requires padding)
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	// Decode menggunakan URL encoding
	decodedBytes, err := helpers.Base64URLDecode(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	// Parse JSON
	var claims map[string]interface{}
	if err := json.Unmarshal(decodedBytes, &claims); err != nil {
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

	// Fallback: Extract identifier from 'sub' if email/preferred_username is missing
	// Format sub: f:cf34bae9-2c14-4a1e-bb37-06e8ec56a40a:111111
	if userInfo["email"] == nil && userInfo["preferred_username"] == nil {
		if sub, ok := claims["sub"].(string); ok {
			parts := strings.Split(sub, ":")
			if len(parts) >= 3 {
				identifier := parts[len(parts)-1] // Ambil bagian terakhir (111111)
				userInfo["preferred_username"] = identifier
				log.Printf("⚠️ Using identifier from 'sub' claim: %s", identifier)
			}
		}
	}

	log.Printf("🔍 DEBUG: Full Claims from ID Token: %+v", claims)
	log.Printf("✅ User info extracted from ID token: email=%v, preferred_username=%v", userInfo["email"], userInfo["preferred_username"])
	return userInfo, nil
}

// ============================================
// HANDLE OAUTH CALLBACK
// ============================================

// handleOAuthCallback processes OAuth callback dari Keycloak
func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔐 OAuth Callback: Processing callback from Keycloak")
	
	// 1. Get code dan state dari query params
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	// Check error dari Keycloak
	if errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		log.Printf("❌ OAuth error: %s - %s", errorParam, errorDesc)

		// Handle Silent SSO failure (login_required)
		if errorParam == "login_required" || errorParam == "interaction_required" {
			log.Printf("ℹ️ Silent SSO check failed (user not logged in), redirecting to login page...")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		http.Error(w, fmt.Sprintf("OAuth error: %s", errorDesc), http.StatusBadRequest)
		return
	}

	// 2. Verify state (CSRF protection)
	storedState, err := helpers.GetCookie(r, "oauth_state")
	
	// DEBUG: Log all cookies
	log.Printf("🍪 DEBUG: Cookies received in callback:")
	for _, c := range r.Cookies() {
		log.Printf("   - %s: %s", c.Name, c.Value)
	}
	log.Printf("🔍 DEBUG: State check - Received: %s, Stored: %s", state, storedState)

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

	log.Printf("✅ Received authorization code: %s...", code[:min(10, len(code))])

	// 4. Exchange code untuk access token
	tokenData, err := exchangeKeycloakCode(w, r, code)
	if err != nil {
		log.Printf("❌ Failed to exchange code: %v", err)
		http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
		return
	}

	log.Printf("✅ Token exchange successful")

	// 5. Get user info dari ID token
	userInfo, err := getUserInfoFromIDToken(tokenData.IDToken)
	if err != nil {
		log.Printf("❌ Failed to get user info: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Extract identifier (email or preferred_username)
	identifier, ok := userInfo["email"].(string)
	if !ok || identifier == "" {
		// Fallback to preferred_username
		if u, ok := userInfo["preferred_username"].(string); ok {
			identifier = u
		}
	}

	if identifier == "" {
		log.Printf("❌ Identifier (email/username) not found in user info")
		http.Error(w, "Email/Username not found", http.StatusBadRequest)
		return
	}

	log.Printf("✅ User info from Keycloak: identifier=%s, name=%v", identifier, userInfo["name"])
	log.Printf("🔍 Attempting to find user in local DB with identifier: %s", identifier)

	// 6. Create session lokal
	sessionID, success := createSessionFromIdentifier(r, identifier)
	if !success || sessionID == "" {
		log.Printf("❌ Failed to create session for identifier: %s", identifier)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// 7. Set cookies
	helpers.SetCookie(w, r, "client_dinas_session", sessionID, 86400)     // 24 hours
	helpers.SetCookie(w, r, "sso_access_token", tokenData.AccessToken, 86400)
	helpers.SetCookie(w, r, "sso_id_token", tokenData.IDToken, 86400)
	// Set waktu check terakhir untuk mencegah redirect loop
	helpers.SetCookie(w, r, "sso_check_time", fmt.Sprintf("%d", time.Now().Unix()), 3600)

	log.Printf("✅ Session created: %s", sessionID)

	// 8. Redirect ke dashboard
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
