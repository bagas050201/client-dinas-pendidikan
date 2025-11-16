package api

import (
	"client-dinas-pendidikan/internal"
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

// SSOConfig menyimpan konfigurasi SSO
type SSOConfig struct {
	SSOServerURL string
	ClientID     string
	RedirectURI  string
	StateSecret  string // Untuk validasi state
}

// getSSOConfig mengambil konfigurasi SSO dari environment variables
// Auto-detect environment berdasarkan request host jika tidak di-set
func getSSOConfig() SSOConfig {
	// Cek environment variable terlebih dahulu
	ssoServerURL := os.Getenv("SSO_SERVER_URL")

	// Jika tidak di-set, auto-detect berdasarkan request host
	// Untuk development: default ke localhost:8080
	// Untuk production: default ke production URL
	if ssoServerURL == "" {
		// Default untuk development (lebih aman)
		// User harus set SSO_SERVER_URL untuk production
		ssoServerURL = "http://localhost:8080"
	}

	// Pastikan URL memiliki protocol
	if !strings.HasPrefix(ssoServerURL, "http://") && !strings.HasPrefix(ssoServerURL, "https://") {
		// Auto-detect: jika localhost, gunakan http, else https
		if strings.Contains(ssoServerURL, "localhost") {
			ssoServerURL = "http://" + ssoServerURL
		} else {
			ssoServerURL = "https://" + ssoServerURL
		}
	}

	// Default callback URL
	redirectURI := getEnvOrDefault("SSO_REDIRECT_URI", "")
	if redirectURI == "" {
		// Auto-detect berdasarkan SSO server URL
		if strings.Contains(ssoServerURL, "localhost") {
			redirectURI = "http://localhost:8070/api/callback"
		} else {
			redirectURI = "https://client-dinas-pendidikan.vercel.app/api/callback"
		}
	}

	return SSOConfig{
		SSOServerURL: ssoServerURL,
		ClientID:     getEnvOrDefault("SSO_CLIENT_ID", "client-dinas-pendidikan"),
		RedirectURI:  redirectURI,
		StateSecret:  getEnvOrDefault("SSO_STATE_SECRET", ""),
	}
}

// getEnvOrDefault mengambil environment variable atau return default value
func getEnvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// SSOAuthorizeHandler menangani request untuk memulai SSO flow
// Redirect ke SSO authorize endpoint: http://localhost:8080/apps/access?client_id=client-dinas-pendidikan
func SSOAuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	config := getSSOConfig()
	if config.ClientID == "" {
		log.Println("ERROR: SSO_CLIENT_ID tidak di-set")
		helpers.WriteError(w, http.StatusInternalServerError, "Konfigurasi SSO tidak lengkap")
		return
	}

	// Generate state untuk CSRF protection
	state, err := generateState()
	if err != nil {
		log.Printf("ERROR generating state: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal memulai proses SSO")
		return
	}

	// Simpan state di cookie untuk validasi saat callback
	helpers.SetCookie(w, "sso_state", state, 600) // 10 menit

	// Build authorize URL sesuai format SSO server
	// Format: http://localhost:8080/apps/access?client_id=client-dinas-pendidikan
	authorizeURL := fmt.Sprintf("%s/apps/access", config.SSOServerURL)
	params := url.Values{}
	params.Set("client_id", config.ClientID)
	params.Set("state", state) // Optional: tambahkan state jika SSO support

	authorizeURLWithParams := fmt.Sprintf("%s?%s", authorizeURL, params.Encode())

	log.Printf("✅ Redirecting to SSO: %s", authorizeURLWithParams)
	http.Redirect(w, r, authorizeURLWithParams, http.StatusFound)
}

// SSOCallbackHandler menangani callback dari SSO setelah user login
// Flow:
// 1. Terima authorization code dari query parameter
// 2. Validasi state parameter
// 3. Exchange code ke access token
// 4. Ambil user info dari SSO
// 5. Buat session user di client
// 6. Redirect ke dashboard
func SSOCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Log request untuk debugging
	log.Printf("📥 SSO Callback received:")
	log.Printf("   Method: %s", r.Method)
	log.Printf("   URL: %s", r.URL.String())
	log.Printf("   Host: %s", r.Host)
	log.Printf("   RemoteAddr: %s", r.RemoteAddr)

	// Parse query parameters
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")
	errorDescription := r.URL.Query().Get("error_description")

	log.Printf("   Code: %s", func() string {
		if code != "" {
			return code[:min(10, len(code))] + "..."
		}
		return "(empty)"
	}())
	log.Printf("   State: %s", func() string {
		if state != "" {
			return state[:min(10, len(state))] + "..."
		}
		return "(empty)"
	}())
	log.Printf("   Error: %s", errorParam)

	// Handle error dari SSO
	if errorParam != "" {
		log.Printf("ERROR from SSO: %s - %s", errorParam, errorDescription)
		http.Redirect(w, r, "/login?error=sso_error&message="+url.QueryEscape(errorDescription), http.StatusSeeOther)
		return
	}

	// Validasi code
	if code == "" {
		log.Println("ERROR: Authorization code tidak ditemukan")
		http.Redirect(w, r, "/login?error=missing_code", http.StatusSeeOther)
		return
	}

	// Validasi state (optional, jika SSO mengirim state)
	if state != "" {
		stateCookie, err := helpers.GetCookie(r, "sso_state")
		if err == nil && stateCookie != "" {
			if state != stateCookie {
				log.Printf("ERROR: State mismatch. Expected: %s, Got: %s", stateCookie, state)
				http.Redirect(w, r, "/login?error=state_mismatch", http.StatusSeeOther)
				return
			}
			// Clear state cookie setelah digunakan
			helpers.ClearCookie(w, "sso_state")
		}
	}

	// Exchange code ke access token (tanpa PKCE)
	config := getSSOConfig()
	log.Printf("🔄 Exchanging code to token:")
	log.Printf("   SSO Server URL: %s", config.SSOServerURL)
	log.Printf("   Redirect URI: %s", config.RedirectURI)
	log.Printf("   Client ID: %s", config.ClientID)
	log.Printf("   Code: %s...", code[:min(10, len(code))])
	tokenResponse, err := exchangeCodeForToken(code, config)
	if err != nil {
		log.Printf("❌ ERROR exchanging code for token: %v", err)
		// Redirect dengan error message yang lebih detail
		errorMsg := url.QueryEscape(fmt.Sprintf("Gagal menukar authorization code: %v", err))
		http.Redirect(w, r, "/login?error=token_exchange_failed&message="+errorMsg, http.StatusSeeOther)
		return
	}
	log.Printf("✅ Token exchange berhasil: token_type=%s, expires_in=%d", tokenResponse.TokenType, tokenResponse.ExpiresIn)

	// Simpan access token di cookie (untuk digunakan di protected routes)
	// Token expires dalam expires_in detik (default 3600 = 1 jam)
	tokenExpiresIn := tokenResponse.ExpiresIn
	if tokenExpiresIn == 0 {
		tokenExpiresIn = 3600 // Default 1 jam
	}
	helpers.SetCookie(w, "sso_access_token", tokenResponse.AccessToken, tokenExpiresIn)

	// Simpan token expires timestamp (current time + expires_in)
	tokenExpiresAt := time.Now().Unix() + int64(tokenExpiresIn)
	helpers.SetCookie(w, "sso_token_expires", fmt.Sprintf("%d", tokenExpiresAt), tokenExpiresIn)

	log.Printf("✅ Token saved: expires in %d seconds", tokenExpiresIn)

	// Ambil user info dari SSO (opsional, untuk mendapatkan email dan nama)
	userInfo, err := getUserInfoFromSSO(tokenResponse.AccessToken, config)
	if err != nil {
		log.Printf("WARNING: Error getting user info: %v, akan lanjutkan tanpa user info", err)
		// Tetap lanjutkan, redirect ke dashboard
		// User info bisa diambil nanti jika diperlukan
	} else {
		// Buat atau update user di database client
		userEmail := userInfo.Email
		if userEmail != "" {
			// Cari atau buat user di database
			userID, err := findOrCreateUser(userInfo)
			if err != nil {
				log.Printf("WARNING: Error finding/creating user: %v", err)
			} else {
				// Buat session di database client
				sessionID, err := internal.CreateSession(userID, r)
				if err != nil {
					log.Printf("WARNING: Error creating session: %v", err)
				} else {
					// Set cookie session dengan nama yang berbeda dari SSO server
					// PENTING: Gunakan cookie name yang berbeda untuk mencegah shared cookie
					// SSO server menggunakan "sso_admin_session", client website menggunakan "client_dinas_session"
					helpers.SetCookie(w, "client_dinas_session", sessionID, 86400) // 24 jam
					log.Printf("✅ User session created: %s, session: %s", userEmail, sessionID)
				}
			}
		}
	}

	// Redirect ke dashboard
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/dashboard"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// TokenResponse menyimpan response dari token exchange
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// UserInfo menyimpan informasi user dari SSO
type UserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
}

// generatePKCE menghasilkan code_verifier dan code_challenge untuk PKCE
func generatePKCE() (codeVerifier string, codeChallenge string, err error) {
	// Generate random 32-byte code_verifier menggunakan crypto/rand
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", fmt.Errorf("gagal generate random bytes: %v", err)
	}

	// Base64URL encode code_verifier (tanpa padding)
	codeVerifier = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(randomBytes)

	// Generate code_challenge: SHA256(code_verifier) kemudian base64URL encode
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])

	return codeVerifier, codeChallenge, nil
}

// generateState menghasilkan random state untuk CSRF protection
func generateState() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("gagal generate state: %v", err)
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(randomBytes), nil
}

// exchangeCodeForToken menukar authorization code dengan access token
// POST ke https://sso-dinas-pendidikan.vercel.app/api/token
// Atau http://localhost:8080/api/token untuk development
func exchangeCodeForToken(code string, config SSOConfig) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/api/token", config.SSOServerURL)
	log.Printf("📡 Token URL: %s", tokenURL)

	// Prepare form data sesuai requirement
	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", code)
	formData.Set("redirect_uri", config.RedirectURI)
	formData.Set("client_id", config.ClientID)
	// Sistem SSO baru lebih sederhana - tidak menggunakan PKCE

	// Log request details untuk debugging
	requestBody := formData.Encode()
	log.Printf("📤 Request to SSO:")
	log.Printf("   URL: %s", tokenURL)
	log.Printf("   Method: POST")
	log.Printf("   Content-Type: application/x-www-form-urlencoded")
	log.Printf("   Body: grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s",
		code[:min(10, len(code))]+"...", config.RedirectURI, config.ClientID)
	log.Printf("   Full body length: %d bytes", len(requestBody))

	// Create POST request
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("gagal membuat request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("❌ Network error: %v", err)
		return nil, fmt.Errorf("gagal memanggil SSO server: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	log.Printf("📥 Response from SSO:")
	log.Printf("   Status: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	log.Printf("   Content-Type: %s", resp.Header.Get("Content-Type"))
	log.Printf("   Body: %s", string(bodyBytes))
	log.Printf("   Body length: %d bytes", len(bodyBytes))

	if resp.StatusCode != http.StatusOK {
		// Log error detail untuk debugging
		log.Printf("❌ Token exchange failed:")
		log.Printf("   Request URL: %s", tokenURL)
		log.Printf("   Status: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
		log.Printf("   Response Body: %s", string(bodyBytes))

		// Coba parse error response jika ada
		var errorResp map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &errorResp); err == nil {
			if errorMsg, ok := errorResp["error"].(string); ok {
				errorDesc := ""
				if desc, ok := errorResp["error_description"].(string); ok {
					errorDesc = desc
				} else if desc, ok := errorResp["error_description"].(interface{}); ok {
					errorDesc = fmt.Sprintf("%v", desc)
				}
				return nil, fmt.Errorf("%s: %s", errorMsg, errorDesc)
			}
		}

		// Jika response bukan JSON (misalnya 404 dari Vercel), return error dengan body
		return nil, fmt.Errorf("token exchange gagal: status %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResponse TokenResponse
	if err := json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
		log.Printf("❌ ERROR parsing token response: %v, Body: %s", err, string(bodyBytes))
		return nil, fmt.Errorf("gagal parse token response: %v", err)
	}

	if tokenResponse.AccessToken == "" {
		return nil, fmt.Errorf("access_token tidak ditemukan di response")
	}

	return &tokenResponse, nil
}

// min helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// getUserInfoFromSSO mengambil informasi user dari SSO menggunakan access token
// GET https://sso-dinas-pendidikan.vercel.app/api/userinfo
// Atau http://localhost:8080/api/userinfo untuk development
func getUserInfoFromSSO(accessToken string, config SSOConfig) (*UserInfo, error) {
	userInfoURL := fmt.Sprintf("%s/api/userinfo", config.SSOServerURL)

	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("gagal membuat request: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gagal memanggil SSO server: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR SSO userinfo response: Status %d, Body: %s", resp.StatusCode, string(bodyBytes))
		return nil, fmt.Errorf("userinfo request gagal: status %d", resp.StatusCode)
	}

	// Log raw response untuk debugging
	log.Printf("📥 SSO userinfo raw response: %s", string(bodyBytes))

	var userInfo UserInfo
	if err := json.Unmarshal(bodyBytes, &userInfo); err != nil {
		log.Printf("ERROR parsing userinfo response: %v, Body: %s", err, string(bodyBytes))
		return nil, fmt.Errorf("gagal parse userinfo response: %v", err)
	}

	// Log user info untuk debugging
	log.Printf("📋 User info from SSO (parsed):")
	log.Printf("   Email: %s", userInfo.Email)
	log.Printf("   Name: %s", userInfo.Name)
	log.Printf("   Sub: %s", userInfo.Sub)

	// Jika Name kosong, coba parse dari response langsung (mungkin field berbeda)
	if userInfo.Name == "" {
		var rawResponse map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &rawResponse); err == nil {
			// Coba berbagai field name yang mungkin
			if name, ok := rawResponse["nama_lengkap"].(string); ok && name != "" {
				userInfo.Name = name
				log.Printf("   ✅ Found name from 'nama_lengkap': %s", name)
			} else if name, ok := rawResponse["full_name"].(string); ok && name != "" {
				userInfo.Name = name
				log.Printf("   ✅ Found name from 'full_name': %s", name)
			} else if name, ok := rawResponse["nama"].(string); ok && name != "" {
				userInfo.Name = name
				log.Printf("   ✅ Found name from 'nama': %s", name)
			} else {
				log.Printf("   ⚠️  Name not found in response. Available fields: %v", getMapKeys(rawResponse))
			}
		}
	}

	return &userInfo, nil
}

// findOrCreateUser mencari user di database atau membuat baru jika tidak ada
func findOrCreateUser(userInfo *UserInfo) (interface{}, error) {
	supabaseURL := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_KEY")
	if supabaseURL == "" || supabaseKey == "" {
		return nil, fmt.Errorf("SUPABASE_URL atau SUPABASE_KEY tidak di-set")
	}

	// Cari user berdasarkan email
	emailEncoded := url.QueryEscape(userInfo.Email)
	apiURL := fmt.Sprintf("%s/rest/v1/pengguna?email=eq.%s&select=*", supabaseURL, emailEncoded)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("gagal membuat request: %v", err)
	}

	req.Header.Set("apikey", supabaseKey)
	req.Header.Set("Authorization", "Bearer "+supabaseKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gagal memanggil Supabase: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR Supabase response: Status %d, Body: %s", resp.StatusCode, string(bodyBytes))
		return nil, fmt.Errorf("gagal query user: status %d", resp.StatusCode)
	}

	var users []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &users); err != nil {
		return nil, fmt.Errorf("gagal parse response: %v", err)
	}

	// Jika user sudah ada, update nama dari SSO jika berbeda
	if len(users) > 0 {
		existingUser := users[0]
		userID := existingUser["id_pengguna"]
		if userID == nil {
			// Fallback ke id jika id_pengguna tidak ada
			userID = existingUser["id"]
		}

		// Update nama_lengkap dari SSO jika berbeda
		existingName, _ := existingUser["nama_lengkap"].(string)
		if userInfo.Name != "" && existingName != userInfo.Name {
			log.Printf("🔄 Updating user name from SSO: %s -> %s", existingName, userInfo.Name)
			// Update nama di database
			userIDEncoded := url.QueryEscape(fmt.Sprintf("%v", userID))
			updateURL := fmt.Sprintf("%s/rest/v1/pengguna?id_pengguna=eq.%s", supabaseURL, userIDEncoded)

			updateData := map[string]interface{}{
				"nama_lengkap": userInfo.Name,
			}
			updateJSON, _ := json.Marshal(updateData)

			updateReq, err := http.NewRequest("PATCH", updateURL, strings.NewReader(string(updateJSON)))
			if err == nil {
				updateReq.Header.Set("apikey", supabaseKey)
				updateReq.Header.Set("Authorization", "Bearer "+supabaseKey)
				updateReq.Header.Set("Content-Type", "application/json")
				updateReq.Header.Set("Prefer", "return=representation")

				updateResp, err := http.DefaultClient.Do(updateReq)
				if err == nil {
					updateResp.Body.Close()
					log.Printf("✅ User name updated: %s", userInfo.Name)
				}
			}
		}

		return userID, nil
	}

	// Jika user belum ada, buat baru
	userData := map[string]interface{}{
		"email":        userInfo.Email,
		"nama_lengkap": userInfo.Name,
		"aktif":        true,
		"peran":        "user", // Default role
	}

	userJSON, _ := json.Marshal(userData)
	apiURL = fmt.Sprintf("%s/rest/v1/pengguna", supabaseURL)

	req, err = http.NewRequest("POST", apiURL, strings.NewReader(string(userJSON)))
	if err != nil {
		return nil, fmt.Errorf("gagal membuat request: %v", err)
	}

	req.Header.Set("apikey", supabaseKey)
	req.Header.Set("Authorization", "Bearer "+supabaseKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "return=representation")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gagal membuat user: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ = io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Printf("ERROR Supabase create user response: Status %d, Body: %s", resp.StatusCode, string(bodyBytes))
		return nil, fmt.Errorf("gagal membuat user: status %d", resp.StatusCode)
	}

	var newUsers []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &newUsers); err != nil {
		return nil, fmt.Errorf("gagal parse response: %v", err)
	}

	if len(newUsers) == 0 {
		return nil, fmt.Errorf("user tidak dibuat")
	}

	log.Printf("✅ User created: %s (nama: %s)", userInfo.Email, userInfo.Name)
	// Return id_pengguna jika ada, fallback ke id
	userID := newUsers[0]["id_pengguna"]
	if userID == nil {
		userID = newUsers[0]["id"]
	}
	return userID, nil
}
