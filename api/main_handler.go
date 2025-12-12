package main

import (
	"bytes"
	"client-dinas-pendidikan/pkg/helpers"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
)

//go:embed logo.png
var LogoData []byte

//go:embed static/sso-handler.js
var SSOHandlerJS []byte

// Dummy functions untuk backward compatibility dengan kode lama
// (fungsi-fungsi ini sudah tidak digunakan di flow SSO baru yang pakai Keycloak)
func getSupabaseURL() string {
	return "" // Not used anymore
}

func getSupabaseKey() string {
	return "" // Not used anymore
}

func getJWTPublicKey() string {
	return "" // Not used anymore - sekarang pakai Keycloak
}

// PostgreSQL connection functions
func getPostgresHost() string {
	if host := os.Getenv("POSTGRES_HOST"); host != "" {
		return host
	}
	return "localhost" // default
}

func getPostgresPort() string {
	if port := os.Getenv("POSTGRES_PORT"); port != "" {
		return port
	}
	return "5433" // default
}

func getPostgresDB() string {
	if db := os.Getenv("POSTGRES_DB"); db != "" {
		return db
	}
	return "dinas_pendidikan" // default
}

func getPostgresUser() string {
	if user := os.Getenv("POSTGRES_USER"); user != "" {
		return user
	}
	return "postgres" // default
}

func getPostgresPassword() string {
	if password := os.Getenv("POSTGRES_PASSWORD"); password != "" {
		return password
	}
	return "postgres123" // default
}

// connectPostgreSQL creates a connection to local PostgreSQL database
func connectPostgreSQL() (*sql.DB, error) {
	host := getPostgresHost()
	port := getPostgresPort()
	dbname := getPostgresDB()
	user := getPostgresUser()
	password := getPostgresPassword()

	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to open PostgreSQL connection: %v", err)
	}

	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("failed to ping PostgreSQL database: %v", err)
	}

	return db, nil
}

// parseRSAPublicKey parses RSA public key from PEM format
func parseRSAPublicKey(publicKeyStr string) (*rsa.PublicKey, error) {
	// Try to parse as PEM format
	block, _ := pem.Decode([]byte(publicKeyStr))
	if block != nil {
		// PEM format detected
		if block.Type == "PUBLIC KEY" {
			// PKIX format
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			rsaPub, ok := pub.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("key is not RSA public key")
			}
			return rsaPub, nil
		} else if block.Type == "RSA PUBLIC KEY" {
			// PKCS1 format
			pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return pub, nil
		}
	}

	// If not PEM, try to parse as raw bytes (base64 encoded)
	// This is less common but might be needed
	keyBytes, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err == nil {
		pub, err := x509.ParsePKIXPublicKey(keyBytes)
		if err == nil {
			rsaPub, ok := pub.(*rsa.PublicKey)
			if ok {
				return rsaPub, nil
			}
		}
	}

	return nil, fmt.Errorf("unable to parse RSA public key")
}

// getSessionSecret returns SESSION_SECRET from environment
func getSessionSecret() string {
	return os.Getenv("SESSION_SECRET")
}

// Handler is the single entrypoint for Vercel
func Handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Serve logo
	if path == "/logo.png" {
		w.Header().Set("Content-Type", "image/png")
		w.Write(LogoData)
		return
	}

	// Serve static JavaScript files
	if path == "/static/sso-handler.js" || path == "/sso-handler.js" {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Write(SSOHandlerJS)
		return
	}

	// API routes
	if strings.HasPrefix(path, "/api/") {
		handleAPI(w, r)
		return
	}

	// Static pages - menggunakan handler baru yang modular
	switch path {
	case "/", "/home":
		// ============================================
		// FLOW BARU: Standard OIDC dengan Keycloak
		// ============================================
		// 1. Portal SSO redirect tanpa token (hanya plain URL)
		// 2. Check session lokal
		// 3. Jika tidak ada, redirect ke Keycloak dengan prompt=none (auto-login)
		// 4. Keycloak return authorization code jika ada session
		// 5. Exchange code untuk token
		
		// Check apakah ada authorization code dari Keycloak callback
		code := r.URL.Query().Get("code")
		errorParam := r.URL.Query().Get("error")
		
		if code != "" {
			// Ada code dari Keycloak, redirect ke callback handler
			log.Printf("🔐 Authorization code received, redirecting to /callback")
			http.Redirect(w, r, "/callback?"+r.URL.RawQuery, http.StatusSeeOther)
			return
		}
		
		if errorParam != "" {
			// Ada error dari Keycloak (prompt=none gagal)
			if errorParam == "login_required" || errorParam == "interaction_required" {
				// User belum login di Keycloak, redirect ke login (tanpa prompt=none)
				log.Printf("🔄 Auto-login failed (%s), redirecting to Keycloak login form", errorParam)

				// Clear local cookies to ensure clean state
				helpers.ClearCookie(w, r, "client_dinas_session")
				helpers.ClearCookie(w, r, "sso_access_token")
				helpers.ClearCookie(w, r, "sso_id_token")
				helpers.ClearCookie(w, r, "sso_token_expires")
				helpers.ClearCookie(w, r, "session_id")

				redirectToKeycloakLogin(w, r, false) // false = tanpa prompt=none
				return
			}
			// Error lain, tampilkan pesan
			errorDesc := r.URL.Query().Get("error_description")
			log.Printf("❌ OAuth error: %s - %s", errorParam, errorDesc)
			http.Error(w, "SSO Error: "+errorParam, http.StatusBadRequest)
			return
		}
		
		// Check session lokal
		if isAuthenticated(r) {
			// Sudah login, redirect ke dashboard
			log.Printf("✅ User already authenticated, redirecting to dashboard")
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
		
		// Belum login, mulai flow True SSO (Silent Check)
		// Redirect ke /auth/check untuk melakukan pengecekan session di background
		log.Printf("🔄 No local session found, starting True SSO check...")
		http.Redirect(w, r, "/auth/check", http.StatusSeeOther)

	case "/sso-check":
		// Endpoint khusus untuk Silent SSO Check
		// Redirect ke Keycloak dengan prompt=none
		log.Printf("🕵️ Performing Silent SSO Check (prompt=none)...")
		redirectToKeycloakLogin(w, r, true) // true = dengan prompt=none

	case "/login-manual":
		// Endpoint untuk login manual (jika silent check gagal)
		// Redirect ke Keycloak TANPA prompt=none (tampilkan form login)
		log.Printf("👤 Performing Manual Login (Standard SSO)...")
		redirectToKeycloakLogin(w, r, false) // false = tanpa prompt=none

	case "/login":
		// SSO Only: Tampilkan halaman login dengan tombol SSO
		LoginPageHandler(w, r)
		return
	case "/dashboard":
		// Gunakan handler baru untuk dashboard
		DashboardHandler(w, r)
		return
	// Halaman info-dinas, about, services, news dihapus - hanya SSO
	case "/profile":
		// Gunakan handler baru untuk profile (GET dan POST)
		ProfileHandler(w, r)
		return
	case "/logout":
		// Gunakan handler baru untuk logout
		LogoutHandler(w, r)
		return
	case "/sso/authorize":
		// Handler untuk memulai SSO flow
		SSOAuthorizeHandler(w, r)
		return
	case "/oauth/callback":
		// Handler untuk callback dari OAuth/OIDC (endpoint baru)
		handleOAuthCallback(w, r)
		return
	case "/callback":
		// Handler untuk callback dari OAuth/OIDC (kompatibilitas)
		handleOAuthCallback(w, r)
		return
	case "/auth/check":
		// Route: Silent Check (sesuai panduan)
		handleAuthCheck(w, r)
		return
	case "/auth/validate":
		// Route: Validasi Session (Sync Logout)
		handleAuthValidate(w, r)
		return
	default:
		http.NotFound(w, r)
	}
}

// handleAPI handles API endpoints
func handleAPI(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method

	switch {
	case path == "/oauth/callback" && method == "GET":
		// Handler untuk callback dari SSO (endpoint baru: /oauth/callback)
		SSOCallbackHandler(w, r)
	case path == "/api/callback" && method == "GET":
		// Handler untuk callback dari SSO (support /api/callback untuk kompatibilitas)
		SSOCallbackHandler(w, r)
	// Login dan Register API dihapus - hanya menggunakan SSO Keycloak
	case path == "/api/logout" && method == "POST":
		handleLogoutAPI(w, r)
	case path == "/api/profile" && method == "GET":
		handleGetProfileAPI(w, r)
	// API Update Profile dan Password dihapus - dikelola oleh SSO Keycloak
	// API news dan announcements dihapus
	case path == "/api/users/sso-login" && method == "POST":
		// Endpoint untuk check atau create user dari SSO Keycloak
		handleSSOUserLoginAPI(w, r)
	case path == "/api/auth/sso-login" && method == "POST":
		// Endpoint untuk create session aplikasi setelah SSO login
		handleSSOAuthLoginAPI(w, r)
	default:
		helpers.WriteError(w, http.StatusNotFound, "Endpoint not found")
	}
}

// getMapKeys helper untuk mendapatkan semua keys dari map (untuk debugging)
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// LoginPageHandler menampilkan halaman login
// Jika user sudah memiliki session valid, redirect ke /dashboard
// Jika tidak, tampilkan form login
func LoginPageHandler(w http.ResponseWriter, r *http.Request) {
	// PENTING: Handle sso_token dan sso_id_token (dari website SSO)
	// Flow baru: sso_id_token berisi user info lengkap (TANPA perlu call API)
	// Prioritas: sso_id_token > sso_token (karena id_token sudah berisi user info)
	ssoToken := r.URL.Query().Get("sso_token")
	ssoIdToken := r.URL.Query().Get("sso_id_token")

	if ssoIdToken != "" || ssoToken != "" {
		log.Printf("🔐 SSO token detected in /login, processing...")
		if ssoIdToken != "" {
			log.Printf("   ID token present (length: %d) - berisi user info lengkap", len(ssoIdToken))
		}
		if ssoToken != "" {
			log.Printf("   Access token present (length: %d)", len(ssoToken))
		}

		// PRIORITAS: Process sso_id_token dulu (karena sudah berisi user info)
		var success bool
		if ssoIdToken != "" {
			log.Printf("🔄 Processing sso_id_token (prioritas - berisi user info)...")
			success = handleSSOTokenWithCookie(w, r, ssoIdToken)
		}

		// Jika sso_id_token gagal, coba sso_token sebagai fallback
		if !success && ssoToken != "" {
			log.Printf("⚠️ sso_id_token failed, trying sso_token as fallback...")
			success = handleSSOTokenWithCookie(w, r, ssoToken)
		}

		if success {
			// Session berhasil dibuat, render halaman sukses dengan JavaScript redirect
			next := r.URL.Query().Get("next")
			if next == "" {
				next = "/dashboard"
			}
			log.Printf("✅ SSO token processed successfully, rendering success page with redirect to: %s", next)

			// Render halaman sukses dengan JavaScript redirect (untuk memastikan cookie ter-set)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			successHTML := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>SSO Login Berhasil</title>
    <meta charset="utf-8">
</head>
<body>
    <div style="text-align: center; padding: 50px; font-family: Arial, sans-serif;">
        <h2>✅ Login SSO Berhasil!</h2>
        <p>Redirecting to dashboard...</p>
        <script>
            console.log('🔄 SSO login success, redirecting to dashboard...');
            setTimeout(function() {
                window.location.href = '%s';
            }, 1000);
        </script>
    </div>
</body>
</html>`, next)
			w.Write([]byte(successHTML))
			return
		} else {
			log.Printf("❌ Failed to process SSO token (both sso_id_token and sso_token failed)")
			// Redirect dengan error message
			http.Redirect(w, r, "/login?error=sso_token_failed&message="+url.QueryEscape("Gagal memproses SSO token. Silakan coba lagi."), http.StatusSeeOther)
			return
		}
	}

	// Cek apakah user sudah login (cek access token atau session)
	// PENTING: Jangan redirect jika ada error parameter (untuk menghindari loop)
	errorParam := r.URL.Query().Get("error")
	errorMsg := ""
	messageParam := r.URL.Query().Get("message")

	if errorParam != "" {
		switch errorParam {
		case "token_exchange_failed":
			if messageParam != "" {
				errorMsg = messageParam
			} else {
				errorMsg = "Gagal menukar authorization code. Silakan coba lagi."
			}
		case "missing_code":
			errorMsg = "Authorization code tidak ditemukan."
		case "state_mismatch":
			errorMsg = "State tidak valid. Silakan coba lagi."
		case "sso_error":
			if messageParam != "" {
				errorMsg = "Error dari SSO: " + messageParam
			} else {
				errorMsg = "Terjadi kesalahan saat login dengan SSO."
			}
		case "sso_token_failed":
			if messageParam != "" {
				errorMsg = messageParam
			} else {
				errorMsg = "Gagal memproses SSO token. Silakan coba lagi."
			}
		case "token_expired":
			errorMsg = "Token sudah expired. Silakan login lagi."
		case "no_token":
			errorMsg = "Tidak ada access token. Silakan login."
		case "login_required", "interaction_required":
			// Silent SSO failed, user needs to login manually.
			log.Printf("ℹ️ Silent SSO check returned %s, showing login form", errorParam)
		default:
			if messageParam != "" {
				errorMsg = messageParam
			} else {
				errorMsg = "Terjadi kesalahan. Silakan coba lagi."
			}
		}
	}

	// Tampilkan form login dengan error message jika ada
	renderLoginPage(w, errorMsg, "")
}

// LoginPostHandler telah dihapus - Aplikasi ini hanya menggunakan SSO Keycloak

// RequireAuth middleware — perbaikan
func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Normalisasi path (hilangkan trailing slash kecuali root)
		currentPath := r.URL.Path
		if len(currentPath) > 1 && strings.HasSuffix(currentPath, "/") {
			currentPath = strings.TrimRight(currentPath, "/")
		}

		// 1) Cek SSO access token
		if accessToken, err := helpers.GetCookie(r, "sso_access_token"); err == nil && accessToken != "" {
			if tokenExpiresStr, err := helpers.GetCookie(r, "sso_token_expires"); err == nil && tokenExpiresStr != "" {
				if tokenExpires, err := strconv.ParseInt(tokenExpiresStr, 10, 64); err == nil {
					if time.Now().Unix() <= tokenExpires {
						log.Printf("✅ Access token valid")
						next(w, r)
						return
					}
				}
			}
			log.Printf("WARNING: Access token expired or invalid, clearing cookies")
			helpers.ClearCookie(w, r, "sso_access_token")
			helpers.ClearCookie(w, r, "sso_token_expires")
		}

		// 2) Cek session dari direct login (fallback)
		sessionID, err := helpers.GetCookie(r, "client_dinas_session")
		if err != nil || sessionID == "" {
			sessionID, err = helpers.GetCookie(r, "session_id") // backward compat
		}
		if err == nil && sessionID != "" {
			userID, ok, err := validateSession(sessionID)
			if ok && err == nil && userID != "" {
				log.Printf("✅ Session valid for user: %s", userID)
				next(w, r)
				return
			}
			// invalid => clear
			if !ok {
				log.Printf("WARNING: Session invalid, clearing cookie")
				helpers.ClearCookie(w, r, "client_dinas_session")
				helpers.ClearCookie(w, r, "session_id")
			}
		}

		// --- PUBLIC ROUTES (DO NOT PROTECT) ---
		// PENTING: Cek ini HARUS dilakukan SEBELUM redirect untuk menghindari loop
		// Route ini tidak perlu auth, biarkan handler yang bertanggung jawab handle
		if strings.HasPrefix(currentPath, "/static/") ||
			strings.HasPrefix(currentPath, "/api/") ||
			strings.HasPrefix(currentPath, "/login") || // covers /login and /login/...
			strings.HasPrefix(currentPath, "/register") ||
			currentPath == "/favicon.ico" ||
			currentPath == "/logo.png" {
			next(w, r)
			return
		}

		// Tidak ada auth valid: redirect ke login
		// Cek apakah sudah ada next param di URL untuk menghindari loop
		existingNext := r.URL.Query().Get("next")
		if existingNext != "" && existingNext == currentPath {
			// Sudah redirect dengan next param yang sama, break loop
			log.Printf("WARNING: Redirect loop detected for path %s, breaking loop", currentPath)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		redirectURL := "/login"
		if currentPath != "/" {
			// escape path supaya aman (hindari open redirect / karakter aneh)
			redirectURL = "/login?next=" + url.QueryEscape(currentPath)
		}

		log.Printf("WARNING: No valid auth found for path %s, redirecting to: %s", currentPath, redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
	}
}

// DashboardHandler menampilkan halaman dashboard
// Protected route: menggunakan RequireAuth middleware untuk cek access token
func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔍 DashboardHandler: accessed by %s", r.RemoteAddr)

	// Cek session langsung tanpa RequireAuth middleware untuk debugging
	sessionID, err := helpers.GetCookie(r, "client_dinas_session")
	if err != nil {
		sessionID, err = helpers.GetCookie(r, "session_id")
	}

	log.Printf("🔍 DashboardHandler: session ID from cookie: %s", sessionID)

	if sessionID != "" {
		userID, ok, err := validateSession(sessionID)
		if ok && err == nil && userID != "" {
			log.Printf("✅ DashboardHandler: session valid, rendering dashboard for user: %s", userID)
			renderDashboardWithToken(w, r)
			return
		} else {
			log.Printf("❌ DashboardHandler: session validation failed - ok: %v, err: %v, userID: %s", ok, err, userID)
		}
	} else {
		log.Printf("❌ DashboardHandler: no session cookie found")
	}

	// Session invalid, redirect to login
	log.Printf("🔄 DashboardHandler: redirecting to login")
	http.Redirect(w, r, "/login?next=/dashboard", http.StatusSeeOther)
}

// renderDashboardWithToken render dashboard setelah token validated

// getUserByID mengambil data user dari Supabase berdasarkan ID
func getUserByID(userID string) (map[string]interface{}, error) {
	supabaseURL := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_KEY")
	if supabaseURL == "" || supabaseKey == "" {
		return nil, fmt.Errorf("SUPABASE_URL atau SUPABASE_KEY tidak di-set")
	}

	userIDEncoded := url.QueryEscape(userID)
	// Schema: id_pengguna adalah primary key, bukan id
	apiURL := fmt.Sprintf("%s/rest/v1/pengguna?id_pengguna=eq.%s&select=*", supabaseURL, userIDEncoded)

	httpReq, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("apikey", supabaseKey)
	httpReq.Header.Set("Authorization", "Bearer "+supabaseKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var users []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &users); err != nil {
		return nil, err
	}

	if len(users) == 0 {
		return nil, fmt.Errorf("user tidak ditemukan")
	}

	return users[0], nil
}

// getUserBySSOIdentifier mengambil data user dari PostgreSQL berdasarkan ID, NRK, atau NIK
func getUserBySSOIdentifier(identifier string) (map[string]interface{}, error) {
	// Ambil data user dari PostgreSQL database
	log.Printf("🔍 getUserBySSOIdentifier: getting user data for identifier: %s", identifier)

	db, err := connectPostgreSQL()
	if err != nil {
		log.Printf("❌ getUserBySSOIdentifier: failed to connect to PostgreSQL: %v", err)
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	defer db.Close()

	// Query user from PostgreSQL (Schema Baru: account.za_users)
	// Kita cari berdasarkan ID, NRK, atau NIK
	query := `
		SELECT id, email, nickname, fullname, role_id, is_active, nrk, nik 
		FROM account.za_users 
		WHERE id = $1 OR nrk = $1 OR nik = $1
	`

	var userStruct struct {
		ID          string         `json:"id"`
		Email       sql.NullString `json:"email"`
		Nickname    sql.NullString `json:"nickname"`
		Fullname    sql.NullString `json:"fullname"`
		RoleID      sql.NullString `json:"role_id"`
		IsActive    string         `json:"is_active"`
		NRK         sql.NullString `json:"nrk"`
		NIK         sql.NullString `json:"nik"`
	}

	err = db.QueryRow(query, identifier).Scan(
		&userStruct.ID,
		&userStruct.Email,
		&userStruct.Nickname,
		&userStruct.Fullname,
		&userStruct.RoleID,
		&userStruct.IsActive,
		&userStruct.NRK,
		&userStruct.NIK,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("❌ getUserBySSOIdentifier: user not found for identifier: %s", identifier)
			return nil, fmt.Errorf("user not found")
		}
		log.Printf("❌ getUserBySSOIdentifier: error querying user: %v", err)
		return nil, fmt.Errorf("error querying user: %v", err)
	}

	user := map[string]interface{}{
		"id_pengguna":   userStruct.ID,
		"email":         userStruct.Email.String,
		"nama_pengguna": userStruct.Nickname.String,
		"nama_lengkap":  userStruct.Fullname.String,
		"peran":         userStruct.RoleID.String,
		"aktif":         userStruct.IsActive == "1",
		"nrk":           userStruct.NRK.String,
		"nik":           userStruct.NIK.String,
	}

	// Fallback jika nama_lengkap kosong, gunakan nickname
	if user["nama_lengkap"] == "" {
		user["nama_lengkap"] = user["nama_pengguna"]
	}
	// Fallback jika peran kosong, set default user
	if user["peran"] == "" {
		user["peran"] = "user"
	}

	log.Printf("✅ getUserBySSOIdentifier: found user: %s (%s)", user["nama_lengkap"], user["email"])
	return user, nil
}

// getDashboardCounts mengambil jumlah pengguna, aplikasi, sessions, dan tokens
func getDashboardCounts() (map[string]int, error) {
	supabaseURL := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_KEY")
	if supabaseURL == "" || supabaseKey == "" {
		return nil, fmt.Errorf("SUPABASE_URL atau SUPABASE_KEY tidak di-set")
	}

	counts := make(map[string]int)

	// Untuk sementara, return default values
	// TODO: Implement proper counting dengan Supabase count API
	counts["pengguna"] = 0
	counts["aplikasi"] = 0
	counts["sessions"] = 0
	counts["tokens"] = 0

	return counts, nil
}

// renderDashboardWithToken render dashboard setelah token validated
func renderDashboardWithToken(w http.ResponseWriter, r *http.Request) {
	// Cek session (gunakan cookie name yang berbeda dari SSO server)
	// PENTING: Hanya gunakan cookie client_dinas_session, JANGAN gunakan sso_admin_session dari SSO server
	sessionID, err := helpers.GetCookie(r, "client_dinas_session")
	if err != nil {
		// Fallback ke session_id untuk backward compatibility (cookie lama dari direct login)
		sessionID, err = helpers.GetCookie(r, "session_id")
	}
	var userID string
	var ok bool

	if err == nil && sessionID != "" {
		// Validate session using local PostgreSQL connection
		userID, ok, err = validateSession(sessionID)
		if !ok || err != nil {
			log.Printf("WARNING: Session invalid: %v, error: %v", ok, err)
			// Jangan redirect dulu, coba render dengan user kosong
			userID = ""
		}
	}

	// ---------------------------------------------------------
	// PERIODIC SSO CHECK (Prompt=None)
	// ---------------------------------------------------------
	// Cek apakah kita perlu melakukan re-validasi ke SSO (setiap 1 menit)
	// Ini untuk menangani kasus user logout dari SSO atau ganti user
	checkTimeStr, err := helpers.GetCookie(r, "sso_check_time")
	shouldCheck := false
	
	if err != nil || checkTimeStr == "" {
		// Cookie tidak ada, set cookie baru tapi JANGAN check dulu (grace period)
		// Ini mencegah loop jika browser memblokir cookie atau delay network
		log.Printf("ℹ️ sso_check_time missing, setting new cookie and skipping check")
		helpers.SetCookie(w, r, "sso_check_time", fmt.Sprintf("%d", time.Now().Unix()), 3600)
	} else {
		// Cookie ada, cek umurnya
		if checkTime, err := strconv.ParseInt(checkTimeStr, 10, 64); err == nil {
			// Jika check terakhir lebih dari 60 detik yang lalu, lakukan check
			if time.Now().Unix() - checkTime > 60 {
				shouldCheck = true
			}
		}
	}

	if shouldCheck {
		log.Printf("🔄 Periodic SSO Check triggered. Redirecting to /auth/check")
		http.Redirect(w, r, "/auth/check", http.StatusSeeOther)
		return
	}

	// ---------------------------------------------------------
	// VALIDASI SESSION KE KEYCLOAK (Check SSO Logout)
	// ---------------------------------------------------------
	// Cek apakah user masih login di SSO server dengan memanggil UserInfo endpoint
	accessToken, _ := helpers.GetCookie(r, "sso_access_token")
	if accessToken != "" {
		userInfoURL := os.Getenv("SSO_USERINFO_URL")
		if userInfoURL == "" {
			// Fallback URL construction if env not set
			ssoURL := os.Getenv("SSO_URL")
			realm := os.Getenv("SSO_REALM")
			if ssoURL != "" && realm != "" {
				userInfoURL = fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", ssoURL, realm)
			}
		}

		if userInfoURL != "" {
			client := &http.Client{Timeout: 5 * time.Second}
			req, _ := http.NewRequest("GET", userInfoURL, nil)
			req.Header.Set("Authorization", "Bearer "+accessToken)
			resp, err := client.Do(req)
			
			if err != nil {
				log.Printf("WARNING: Failed to check SSO session: %v", err)
				// Network error, maybe allow to proceed or show warning? 
				// For now, proceed with local session.
			} else {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusUnauthorized {
					log.Printf("❌ SSO Session Expired/Invalid (401 from UserInfo). Logging out locally.")
					
					// Clear local cookies
					helpers.ClearCookie(w, r, "client_dinas_session")
					helpers.ClearCookie(w, r, "sso_access_token")
					helpers.ClearCookie(w, r, "sso_id_token")
					helpers.ClearCookie(w, r, "sso_token_expires")
					helpers.ClearCookie(w, r, "session_id")

					// Redirect to login
					http.Redirect(w, r, "/login?error=session_expired", http.StatusSeeOther)
					return
				} else if resp.StatusCode == http.StatusOK {
					log.Printf("✅ SSO Session Valid (Verified with UserInfo)")
				}
			}
		}
	} else {
		// Access token is missing, but we are in a protected route (dashboard).
		// This means we have a local session but no SSO token.
		// We should verify with SSO if the user is still logged in.
		log.Printf("⚠️ SSO Access Token missing in dashboard. Redirecting to /sso-check to re-verify.")
		http.Redirect(w, r, "/sso-check", http.StatusSeeOther)
		return
	}

	// Extract SSO Claims from ID Token Cookie FIRST to get the identifier if session is missing
	ssoClaims := make(map[string]interface{})
	idToken, err := helpers.GetCookie(r, "sso_id_token")
	if err == nil && idToken != "" {
		// Parse JWT token (without verification for display purposes)
		parts := strings.Split(idToken, ".")
		if len(parts) == 3 {
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err == nil {
				json.Unmarshal(payload, &ssoClaims)
			}
		}
	}

	var user map[string]interface{}
	
	// Strategy 1: Try to get user from Session ID (Local Login)
	if userID != "" {
		user, err = getUserBySSOIdentifier(userID)
		if err != nil {
			log.Printf("WARNING: Error getting user by ID: %v", err)
		}
	}

	// Strategy 2: If user not found via session, try to find via SSO 'sub' claim
	// Format sub: "f:component_id:identifier" -> we need the last part
	if user == nil && len(ssoClaims) > 0 {
		if sub, ok := ssoClaims["sub"].(string); ok && sub != "" {
			parts := strings.Split(sub, ":")
			if len(parts) > 0 {
				identifier := parts[len(parts)-1] // Get the last part (e.g., "111111")
				log.Printf("🔄 Attempting to find user by SSO sub identifier: %s", identifier)
				user, err = getUserBySSOIdentifier(identifier)
				if err != nil {
					log.Printf("WARNING: Error getting user by SSO identifier: %v", err)
				}
			}
		}
	}

	// If still no user, initialize empty map
	if user == nil {
		user = make(map[string]interface{})
	}

	// Ambil counts untuk dashboard
	counts, err := getDashboardCounts()
	if err != nil {
		log.Printf("WARNING: Error getting counts: %v", err)
		counts = map[string]int{
			"pengguna": 0,
			"aplikasi": 0,
			"sessions": 0,
			"tokens":   0,
		}
	}

	// Render dashboard
	renderDashboardPage(w, user, counts, ssoClaims)
}

// renderDashboardPage menampilkan halaman dashboard

// renderDashboardPage generates the HTML for the dashboard page.
func renderDashboardPage(w http.ResponseWriter, user map[string]interface{}, counts map[string]int, ssoClaims map[string]interface{}) {
	logoBase64 := base64.StdEncoding.EncodeToString(LogoData)

	userName := ""
	userEmail := ""
	avatarInitial := ""
	userRole := "User"
	roleBadgeClass := "user"
	userStatus := "Unknown"
	statusBadgeClass := ""
	nrk := "-"
	unitKerja := "-"

	// Try to get info from SSO claims first
	if ssoClaims != nil {
		if name, ok := ssoClaims["name"].(string); ok {
			userName = name
			if len(name) > 0 {
				avatarInitial = strings.ToUpper(string(name[0]))
			}
		}
		if email, ok := ssoClaims["email"].(string); ok {
			userEmail = email
		}
		if emailVerified, ok := ssoClaims["email_verified"].(bool); ok {
			if emailVerified {
				userStatus = "Verified"
				statusBadgeClass = "verified"
			} else {
				userStatus = "Not Verified"
				statusBadgeClass = "inactive"
			}
		}

		// Extract 'pegawai' object
		if pegawaiData, ok := ssoClaims["pegawai"].(map[string]interface{}); ok {
			if nrkVal, ok := pegawaiData["nrk"].(string); ok && nrkVal != "" {
				nrk = nrkVal
			}
			if roleVal, ok := pegawaiData["role"].(string); ok && roleVal != "" {
				userRole = roleVal
				if strings.ToLower(roleVal) == "admin" {
					roleBadgeClass = "admin"
				} else {
					roleBadgeClass = "user"
				}
			}
			if groupVal, ok := pegawaiData["group"].(string); ok && groupVal != "" {
				unitKerja = groupVal
			}
		} else if roleID, ok := ssoClaims["role_id"].(string); ok { // Fallback to role_id if pegawai.role is not present
			userRole = roleID
			if strings.ToLower(roleID) == "admin" {
				roleBadgeClass = "admin"
			} else {
				roleBadgeClass = "user"
			}
		}
	}

	// Fallback to local user data if SSO claims are missing some info
	if userName == "" {
		if name, ok := user["nama_lengkap"].(string); ok {
			userName = name
			if len(name) > 0 {
				avatarInitial = strings.ToUpper(string(name[0]))
			}
		}
	}
	if userEmail == "" {
		if email, ok := user["email"].(string); ok {
			userEmail = email
		}
	}
	if userRole == "User" { // Only fallback if not set by SSO
		if role, ok := user["peran"].(string); ok {
			userRole = role
			if strings.ToLower(role) == "admin" {
				roleBadgeClass = "admin"
			} else {
				roleBadgeClass = "user"
			}
		}
	}
	if userStatus == "Unknown" { // Only fallback if not set by SSO
		if active, ok := user["aktif"].(bool); ok {
			if active {
				userStatus = "Aktif"
				statusBadgeClass = "verified"
			} else {
				userStatus = "Tidak Aktif"
				statusBadgeClass = "inactive"
			}
		}
	}
	
	// Fallback for NRK from local DB
	if nrk == "-" {
		if val, ok := user["nrk"].(string); ok && val != "" {
			nrk = val
		}
	}

	// Prepare JSON payload for display
	jsonBytes, err := json.MarshalIndent(ssoClaims, "", "  ")
	jsonPayload := "Tidak ada data SSO."
	if err == nil && len(ssoClaims) > 0 {
		jsonPayload = string(jsonBytes)
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Dinas Pendidikan DKI Jakarta</title>
    <link rel="icon" type="image/png" href="/logo.png">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f1f5f9;
            min-height: 100vh;
        }
        .navbar {
            background: #1e40af;
            color: white;
            padding: 16px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .navbar-left {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .navbar-logo {
            height: 32px;
        }
        .navbar-title {
            font-size: 18px;
            font-weight: 600;
        }
        .navbar-right {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .user-menu {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            padding: 4px 8px;
            border-radius: 8px;
            transition: background 0.2s;
        }
        .user-menu:hover {
            background: rgba(255,255,255,0.1);
        }
        .user-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%%;
            background: #3b82f6;
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 14px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 24px;
        }
        .welcome-section {
            background: linear-gradient(135deg, #3b82f6 0%%, #1e40af 100%%);
            color: white;
            border-radius: 12px;
            padding: 48px;
            margin-bottom: 32px;
            text-align: center;
        }
        .welcome-title {
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 8px;
        }
        .welcome-subtitle {
            font-size: 18px;
            opacity: 0.9;
        }
        .info-card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .info-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 24px;
        }
        .info-title {
            font-size: 18px;
            font-weight: 600;
            color: #1e293b;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 24px;
        }
        .info-item label {
            display: block;
            font-size: 12px;
            font-weight: 600;
            color: #64748b;
            margin-bottom: 4px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .info-item div {
            font-size: 16px;
            color: #1e293b;
            font-weight: 500;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            background: #dcfce7;
            color: #166534;
        }
        .status-badge.inactive {
            background: #fee2e2;
            color: #dc2626;
        }
        .role-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
        }
        .role-badge.user {
            background: #e0e7ff;
            color: #4338ca;
        }
        .role-badge.admin {
            background: #fef3c7;
            color: #92400e;
        }
        .role-badge.inactive {
            background: #e5e7eb;
            color: #4b5563;
        }
        .json-dump {
            background: #1e293b;
            color: #e2e8f0;
            padding: 16px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 12px;
            overflow-x: auto;
            margin-top: 16px;
            white-space: pre-wrap;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .stat-label {
            color: #64748b;
            font-size: 14px;
            margin-bottom: 8px;
        }
        .stat-value {
            font-size: 32px;
            font-weight: 600;
            color: #1e293b;
        }
        .actions-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 16px;
        }
        .action-card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-decoration: none;
            color: inherit;
            display: block;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .action-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .action-title {
            font-size: 18px;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 8px;
        }
        .action-desc {
            color: #64748b;
            font-size: 14px;
        }
        .btn-logout {
            background: #ef4444;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: background 0.2s;
        }
        .btn-logout:hover {
            background: #dc2626;
        }
        .sso-info-card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .sso-info-title {
            font-size: 20px;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 16px;
        }
        .sso-info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
        }
        .sso-info-item {
            display: flex;
            flex-direction: column;
        }
        .sso-info-label {
            color: #64748b;
            font-size: 12px;
            font-weight: 500;
            text-transform: uppercase;
            margin-bottom: 4px;
        }
        .sso-info-value {
            color: #1e293b;
            font-size: 14px;
            font-weight: 500;
        }
        .sso-info-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 500;
        }
        .sso-info-badge.verified {
            background: #d1fae5;
            color: #065f46;
        }
        .sso-info-badge.user {
            background: #dbeafe;
            color: #1e40af;
        }
        .sso-info-badge.admin {
            background: #fef3c7;
            color: #92400e;
        }
        @media (max-width: 768px) {
            .container { padding: 16px; }
            .welcome-section { padding: 24px; }
            .stats-grid { grid-template-columns: 1fr; }
            .sso-info-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-left">
            <img src="data:image/png;base64,%s" alt="Logo" class="navbar-logo">
            <span class="navbar-title">Dinas Pendidikan DKI Jakarta</span>
        </div>
        <div class="navbar-right">
            <div class="user-menu">
                <div class="user-avatar">%s</div>
                <span id="headerUserName">%s</span>
            </div>
            <a href="/logout" class="btn-logout">Logout</a>
        </div>
    </nav>
    <div class="container">
        <div class="welcome-section">
            <h1 class="welcome-title" id="welcomeTitle">Selamat Datang, %s!</h1>
            <p class="welcome-subtitle">Dashboard Sistem Informasi Dinas Pendidikan</p>
        </div>
        <div class="info-card">
            <div class="info-header">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: #3b82f6;">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                    <circle cx="12" cy="7" r="4"></circle>
                </svg>
                <h2 class="info-title">Informasi User</h2>
            </div>
            <div class="info-grid">
                <div class="info-item">
                    <label>Nama Lengkap</label>
                    <div>%s</div>
                </div>
                <div class="info-item">
                    <label>Email</label>
                    <div>%s</div>
                </div>
                <div class="info-item">
                    <label>NRK</label>
                    <div>%s</div>
                </div>
                <div class="info-item">
                    <label>Unit Kerja</label>
                    <div>%s</div>
                </div>
                <div class="info-item">
                    <label>Peran</label>
                    <div><span class="role-badge %s">%s</span></div>
                </div>
                <div class="info-item">
                    <label>Status</label>
                    <div><span class="status-badge %s">%s</span></div>
                </div>
            </div>
        </div>

        <div class="info-card">
             <div class="info-header">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: #3b82f6;">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                    <polyline points="14 2 14 8 20 8"></polyline>
                    <line x1="16" y1="13" x2="8" y2="13"></line>
                    <line x1="16" y1="17" x2="8" y2="17"></line>
                    <polyline points="10 9 9 9 8 9"></polyline>
                </svg>
                <h2 class="info-title">Informasi Data User (Keycloak Payload)</h2>
            </div>
            <div class="json-dump">%s</div>
        </div>



        <div class="actions-grid">
            <a href="/profile" class="action-card">
                <div class="action-title">👤 Profil Saya</div>
                <div class="action-desc">Lihat informasi profil akun Anda</div>
            </a>
            <a href="/logout" class="action-card" style="background: linear-gradient(135deg, #ef4444 0%%, #dc2626 100%%); color: white;">
                <div class="action-title">🚪 Logout</div>
                <div class="action-desc">Keluar dari sistem SSO</div>
            </a>
        </div>
        
        <div style="margin-top: 24px; padding: 20px; background: #f0fdf4; border-left: 4px solid #22c55e; border-radius: 8px;">
            <p style="color: #166534; margin: 0; font-size: 14px;">
                ✅ <strong>Autentikasi SSO Berhasil!</strong> Anda telah login menggunakan Single Sign-On Keycloak.
            </p>
        </div>
    </div>

    <script>
        // Store SSO user info in sessionStorage for other pages
        const ssoUserInfo = %s;
        if (ssoUserInfo && Object.keys(ssoUserInfo).length > 0) {
            sessionStorage.setItem('sso_user_info', JSON.stringify(ssoUserInfo));
        }

        // Sync Logout Check (Periodic)
        function checkSession() {
            fetch('/auth/validate').then(res => {
                if (res.status === 401) window.location.reload();
            }).catch(e => console.error("Session check failed", e));
        }
        
        // Check on load
        checkSession();
        
        // Check every 30 seconds
        setInterval(checkSession, 30000);
        
        // Check on window focus
        window.addEventListener('focus', checkSession);
    </script>
</body>
</html>`, logoBase64, avatarInitial, userName, userName, userName, userEmail, nrk, unitKerja, roleBadgeClass, userRole, statusBadgeClass, userStatus, jsonPayload, jsonPayload)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}


// InfoDinasHandler menampilkan halaman Informasi Dinas Pendidikan
// Protected route: hanya bisa diakses oleh user yang sudah login
func InfoDinasHandler(w http.ResponseWriter, r *http.Request) {
	// Cek session (gunakan cookie name yang berbeda dari SSO server)
	// PENTING: Hanya gunakan cookie client_dinas_session, JANGAN gunakan sso_admin_session dari SSO server
	sessionID, err := helpers.GetCookie(r, "client_dinas_session")
	if err != nil {
		// Fallback ke session_id untuk backward compatibility (cookie lama dari direct login)
		sessionID, err = helpers.GetCookie(r, "session_id")
	}
	if err != nil || sessionID == "" {
		log.Printf("WARNING: No session cookie found, redirecting to login")
		http.Redirect(w, r, "/login?next=/info-dinas", http.StatusSeeOther)
		return
	}

	// Validasi session
	_, ok, err := validateSession(sessionID)
	if !ok || err != nil {
		log.Printf("WARNING: Invalid session: %v, error: %v", ok, err)
		helpers.ClearCookie(w, r, "client_dinas_session")
		helpers.ClearCookie(w, r, "session_id") // Clear juga untuk backward compatibility
		http.Redirect(w, r, "/login?next=/info-dinas", http.StatusSeeOther)
		return
	}

	// Ambil data aplikasi terhubung (jika tabel ada)
	apps, _ := getAplikasiTerdaftar()

	// Ambil data sekolah (jika tabel ada)
	schools, _ := getDataSekolah(10)

	// Render halaman
	renderInfoDinasPage(w, apps, schools)
}

// getAplikasiTerdaftar mengambil daftar aplikasi terdaftar dari Supabase
func getAplikasiTerdaftar() ([]map[string]interface{}, error) {
	supabaseURL := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_KEY")
	if supabaseURL == "" || supabaseKey == "" {
		return nil, fmt.Errorf("SUPABASE_URL atau SUPABASE_KEY tidak di-set")
	}

	// Coba ambil dari tabel aplikasi_terdaftar (jika ada)
	apiURL := fmt.Sprintf("%s/rest/v1/aplikasi_terdaftar?select=*&limit=20", supabaseURL)
	httpReq, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("apikey", supabaseKey)
	httpReq.Header.Set("Authorization", "Bearer "+supabaseKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Tabel mungkin tidak ada, return empty array
		return []map[string]interface{}{}, nil
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	var apps []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &apps); err != nil {
		return nil, err
	}

	return apps, nil
}

// getDataSekolah mengambil data sekolah dari Supabase (limit)
func getDataSekolah(limit int) ([]map[string]interface{}, error) {
	supabaseURL := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_KEY")
	if supabaseURL == "" || supabaseKey == "" {
		return nil, fmt.Errorf("SUPABASE_URL atau SUPABASE_KEY tidak di-set")
	}

	// Coba ambil dari tabel data_sekolah (jika ada)
	apiURL := fmt.Sprintf("%s/rest/v1/data_sekolah?select=*&limit=%d", supabaseURL, limit)
	httpReq, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("apikey", supabaseKey)
	httpReq.Header.Set("Authorization", "Bearer "+supabaseKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Tabel mungkin tidak ada, return demo data
		return getDemoDataSekolah(), nil
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	var schools []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &schools); err != nil {
		return getDemoDataSekolah(), nil
	}

	if len(schools) == 0 {
		return getDemoDataSekolah(), nil
	}

	return schools, nil
}

// getDemoDataSekolah mengembalikan data sekolah demo jika tabel tidak ada
func getDemoDataSekolah() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"nama":      "SDN 01 Jakarta Pusat",
			"alamat":    "Jl. Merdeka No. 1, Jakarta Pusat",
			"jenis":     "SD",
			"status":    "Negeri",
			"kecamatan": "Gambir",
		},
		{
			"nama":      "SMPN 15 Jakarta Selatan",
			"alamat":    "Jl. Kebayoran Baru, Jakarta Selatan",
			"jenis":     "SMP",
			"status":    "Negeri",
			"kecamatan": "Kebayoran Baru",
		},
		{
			"nama":      "SMAN 28 Jakarta",
			"alamat":    "Jl. Raya Pasar Minggu, Jakarta Selatan",
			"jenis":     "SMA",
			"status":    "Negeri",
			"kecamatan": "Pasar Minggu",
		},
	}
}

// renderInfoDinasPage menampilkan halaman Informasi Dinas
func renderInfoDinasPage(w http.ResponseWriter, apps []map[string]interface{}, schools []map[string]interface{}) {
	logoBase64 := base64.StdEncoding.EncodeToString(LogoData)

	// Generate HTML untuk data sekolah
	schoolsHTML := ""
	for _, school := range schools {
		nama := fmt.Sprintf("%v", school["nama"])
		alamat := fmt.Sprintf("%v", school["alamat"])
		jenis := fmt.Sprintf("%v", school["jenis"])
		status := fmt.Sprintf("%v", school["status"])
		schoolsHTML += fmt.Sprintf(`
            <div class="school-card">
                <h4>%s</h4>
                <p><strong>Jenis:</strong> %s | <strong>Status:</strong> %s</p>
                <p><strong>Alamat:</strong> %s</p>
            </div>`, nama, jenis, status, alamat)
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Informasi Dinas - Dinas Pendidikan DKI Jakarta</title>
    <link rel="icon" type="image/png" href="/logo.png">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f1f5f9;
            min-height: 100vh;
        }
        .navbar {
            background: #1e40af;
            color: white;
            padding: 16px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .navbar-left {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .navbar-logo {
            height: 32px;
        }
        .navbar-title {
            font-size: 18px;
            font-weight: 600;
        }
        .navbar-right a {
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 8px;
            transition: background 0.2s;
        }
        .navbar-right a:hover {
            background: rgba(255,255,255,0.1);
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 24px;
        }
        .hero-section {
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            color: white;
            border-radius: 12px;
            padding: 48px;
            margin-bottom: 32px;
            text-align: center;
        }
        .hero-title {
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 16px;
        }
        .hero-subtitle {
            font-size: 18px;
            opacity: 0.9;
        }
        .section {
            background: white;
            border-radius: 12px;
            padding: 32px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .section-title {
            font-size: 24px;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 2px solid #e2e8f0;
        }
        .apps-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 20px;
        }
        .app-card {
            border: 2px solid #e2e8f0;
            border-radius: 12px;
            padding: 24px;
            transition: all 0.2s;
        }
        .app-card:hover {
            border-color: #6366f1;
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.15);
        }
        .app-card h3 {
            font-size: 18px;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 12px;
        }
        .app-card p {
            color: #64748b;
            font-size: 14px;
            margin-bottom: 16px;
            line-height: 1.6;
        }
        .app-link {
            color: #6366f1;
            text-decoration: none;
            font-weight: 500;
            font-size: 14px;
        }
        .app-link:hover {
            text-decoration: underline;
        }
        .about-content {
            color: #475569;
            line-height: 1.8;
            font-size: 15px;
        }
        .about-content p {
            margin-bottom: 16px;
        }
        .contact-info {
            background: #f8fafc;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }
        .contact-info h4 {
            font-size: 16px;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 12px;
        }
        .contact-info p {
            margin-bottom: 8px;
            color: #475569;
        }
        .schools-list {
            display: grid;
            gap: 16px;
        }
        .school-card {
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 20px;
            transition: all 0.2s;
        }
        .school-card:hover {
            border-color: #6366f1;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .school-card h4 {
            font-size: 18px;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 12px;
        }
        .school-card p {
            color: #64748b;
            font-size: 14px;
            margin-bottom: 8px;
        }
        @media (max-width: 768px) {
            .container { padding: 16px; }
            .hero-section { padding: 32px 24px; }
            .hero-title { font-size: 28px; }
            .section { padding: 24px; }
            .apps-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-left">
            <img src="data:image/png;base64,%s" alt="Logo" class="navbar-logo">
            <span class="navbar-title">Dinas Pendidikan DKI Jakarta</span>
        </div>
        <div class="navbar-right">
            <a href="/dashboard">Dashboard</a>
            <a href="/profile">Profil</a>
            <a href="/logout">Logout</a>
        </div>
    </nav>
    <div class="container">
        <div class="hero-section">
            <h1 class="hero-title">Selamat Datang di SSO Dinas Pendidikan</h1>
            <p class="hero-subtitle">Portal Terpadu untuk Layanan Pendidikan DKI Jakarta</p>
        </div>

        <div class="section">
            <h2 class="section-title">Tentang Dinas</h2>
            <div class="about-content">
                <p>
                    Dinas Pendidikan Provinsi DKI Jakarta adalah instansi pemerintah yang bertanggung jawab 
                    dalam pengelolaan dan pengembangan sistem pendidikan di wilayah DKI Jakarta. Kami berkomitmen 
                    untuk memberikan layanan pendidikan yang berkualitas dan mudah diakses oleh seluruh masyarakat.
                </p>
                <p>
                    Visi kami adalah mewujudkan pendidikan yang merata, berkualitas, dan berkarakter untuk 
                    membentuk generasi yang unggul dan berdaya saing. Misi kami meliputi peningkatan akses 
                    pendidikan, peningkatan kualitas pembelajaran, dan penguatan tata kelola pendidikan.
                </p>
                <div class="contact-info">
                    <h4>Kontak & Informasi</h4>
                    <p><strong>Alamat:</strong> Jl. Jenderal Gatot Subroto, Jakarta Selatan</p>
                    <p><strong>Telepon:</strong> (021) 1234-5678</p>
                    <p><strong>Email:</strong> info@pendidikan.jakarta.go.id</p>
                    <p><strong>Website:</strong> <a href="https://pendidikan.jakarta.go.id" target="_blank">pendidikan.jakarta.go.id</a></p>
                </div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">Data Sekolah (Demo)</h2>
            <div class="schools-list">
                %s
            </div>
        </div>
    </div>
</body>
</html>`, logoBase64, schoolsHTML)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// SSOConfig menyimpan konfigurasi SSO
type SSOConfig struct {
	SSOServerURL string
	Realm        string // Realm name (e.g., dinas-pendidikan)
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
			redirectURI = "http://localhost:8070/oauth/callback"
		} else {
			redirectURI = "https://client-dinas-pendidikan.vercel.app/oauth/callback"
		}
	}

	return SSOConfig{
		SSOServerURL: ssoServerURL,
		Realm:        getEnvOrDefault("SSO_REALM", "dinas-pendidikan"),
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
	helpers.SetCookie(w, r, "sso_state", state, 600) // 10 menit

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

// TokenResponse menyimpan response dari token exchange
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	IDToken     string `json:"id_token"`
}

// UserInfo menyimpan informasi user dari SSO
type UserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
	Peran         string `json:"peran"` // Peran dari SSO (admin, user, dll)
	Role          string `json:"role"`  // Alternative field name untuk peran
}

// generateState menghasilkan random state untuk CSRF protection
func generateState() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("gagal generate state: %v", err)
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(randomBytes), nil
}

// min helper function
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// exchangeCodeForToken menukar authorization code dengan access token
func exchangeCodeForToken(code string, config SSOConfig) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/oauth/token", config.SSOServerURL)
	log.Printf("📡 Token URL: %s", tokenURL)

	// Prepare form data sesuai requirement
	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", code)
	formData.Set("redirect_uri", config.RedirectURI)
	formData.Set("client_id", config.ClientID)

	// Log request details untuk debugging
	requestBody := formData.Encode()
	log.Printf("📤 Request to SSO:")
	log.Printf("   URL: %s", tokenURL)
	log.Printf("   Method: POST")
	log.Printf("   Content-Type: application/x-www-form-urlencoded")
	log.Printf("   Body: grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s",
		code[:minInt(10, len(code))]+"...", config.RedirectURI, config.ClientID)
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

// getUserInfoFromSSO mengambil informasi user dari SSO menggunakan access token
func getUserInfoFromSSO(accessToken string, config SSOConfig) (*UserInfo, error) {
	userInfoURL := fmt.Sprintf("%s/sso-auth/realms/%s/protocol/openid-connect/userinfo", config.SSOServerURL, config.Realm)
	// Fallback URL construction if env not set correctly
	if config.Realm == "" {
		userInfoURL = fmt.Sprintf("%s/oauth/userinfo", config.SSOServerURL)
	}

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

	var rawResponse map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &rawResponse); err != nil {
		return nil, fmt.Errorf("gagal parse userinfo response: %v", err)
	}

	userInfo := &UserInfo{}

	// ---------------------------------------------------------
	// PARSING DATA STRUCTURE (NEW FORMAT)
	// ---------------------------------------------------------
	// Format Baru:
	// {
	//   "data": {
	//     "pengguna": { "nama": "...", "email": "...", "id_pengguna": "..." },
	//     "jabatan": { "role": "...", "level": "..." },
	//     "identitas": { "nik": "...", "nip": "..." },
	//     ...
	//   },
	//   "name": "...",
	//   "email": "...",
	//   "preferred_username": "..."
	// }
	
	// 1. Coba ambil dari `data` object (Structure Baru)
	if data, ok := rawResponse["data"].(map[string]interface{}); ok {
		// Pengguna
		if pengguna, ok := data["pengguna"].(map[string]interface{}); ok {
			if val, ok := pengguna["nama"].(string); ok { userInfo.Name = val }
			if val, ok := pengguna["email"].(string); ok { userInfo.Email = val }
			// Mapping ID Pengguna?
		}
		// Jabatan
		if jabatan, ok := data["jabatan"].(map[string]interface{}); ok {
			if val, ok := jabatan["role"].(string); ok { userInfo.Role = val; userInfo.Peran = val }
		}
	}

	// 2. Fallback ke standard OIDC fields (jika `data` kosong atau parsial)
	if userInfo.Name == "" {
		if val, ok := rawResponse["name"].(string); ok { userInfo.Name = val }
	}
	if userInfo.Email == "" {
		if val, ok := rawResponse["email"].(string); ok { userInfo.Email = val }
	}
	if userInfo.Sub == "" {
		if val, ok := rawResponse["sub"].(string); ok { userInfo.Sub = val }
	}
	if userInfo.Role == "" {
		// Coba ambil dari realm_access.roles atau resource_access
		// (Implementasi sederhana, sesuaikan jika perlu)
	}

	// Log hasil parsing
	log.Printf("📋 User info parsed:")
	log.Printf("   Name: %s", userInfo.Name)
	log.Printf("   Email: %s", userInfo.Email)
	log.Printf("   Role: %s", userInfo.Role)

	return userInfo, nil
}

// handleAuthCheck handles silent SSO check (redirects with prompt=none)
func handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	// Use the shared helper which handles PKCE and state correctly
	redirectToKeycloakLogin(w, r, true)
}

// handleAuthValidate handles session validation for frontend script
func handleAuthValidate(w http.ResponseWriter, r *http.Request) {
	// Cek session lokal
	sessionID, err := helpers.GetCookie(r, "client_dinas_session")
	if err != nil || sessionID == "" {
		// Session mati/tidak ada
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Validasi session ID di database
	_, ok, _ := validateSession(sessionID)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Session valid
	w.WriteHeader(http.StatusOK)
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

	// Jika user sudah ada, update nama dan peran dari SSO jika berbeda
	if len(users) > 0 {
		existingUser := users[0]
		userID := existingUser["id_pengguna"]
		if userID == nil {
			// Fallback ke id jika id_pengguna tidak ada
			userID = existingUser["id"]
		}

		// Cek apakah perlu update
		existingName, _ := existingUser["nama_lengkap"].(string)
		existingPeran, _ := existingUser["peran"].(string)
		needsUpdate := false
		updateData := map[string]interface{}{}

		// Update nama_lengkap dari SSO jika berbeda
		if userInfo.Name != "" && existingName != userInfo.Name {
			updateData["nama_lengkap"] = userInfo.Name
			needsUpdate = true
			log.Printf("🔄 Updating user name from SSO: %s -> %s", existingName, userInfo.Name)
		}

		// Update peran dari SSO jika berbeda dan peran dari SSO tidak kosong
		peranFromSSO := userInfo.Peran
		if peranFromSSO == "" {
			peranFromSSO = userInfo.Role
		}
		if peranFromSSO != "" && existingPeran != peranFromSSO {
			updateData["peran"] = peranFromSSO
			needsUpdate = true
			log.Printf("🔄 Updating user peran from SSO: %s -> %s", existingPeran, peranFromSSO)
		}

		// Update di database jika ada perubahan
		if needsUpdate {
			userIDEncoded := url.QueryEscape(fmt.Sprintf("%v", userID))
			updateURL := fmt.Sprintf("%s/rest/v1/pengguna?id_pengguna=eq.%s", supabaseURL, userIDEncoded)

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
					log.Printf("✅ User updated: %+v", updateData)
				}
			}
		}

		return userID, nil
	}

	// Jika user belum ada, buat baru
	// Gunakan peran dari SSO, fallback ke "user" jika tidak ada
	peran := userInfo.Peran
	if peran == "" {
		peran = userInfo.Role
	}
	if peran == "" {
		peran = "user" // Default role jika tidak ada dari SSO
		log.Printf("⚠️  Peran tidak ditemukan dari SSO, menggunakan default: user")
	} else {
		log.Printf("✅ Menggunakan peran dari SSO: %s", peran)
	}

	userData := map[string]interface{}{
		"email":        userInfo.Email,
		"nama_lengkap": userInfo.Name,
		"aktif":        true,
		"peran":        peran,
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
			return code[:minInt(10, len(code))] + "..."
		}
		return "(empty)"
	}())
	log.Printf("   State: %s", func() string {
		if state != "" {
			return state[:minInt(10, len(state))] + "..."
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
			helpers.ClearCookie(w, r, "sso_state")
		}
	}

	// Exchange code ke access token (tanpa PKCE)
	config := getSSOConfig()
	log.Printf("🔄 Exchanging code to token:")
	log.Printf("   SSO Server URL: %s", config.SSOServerURL)
	log.Printf("   Redirect URI: %s", config.RedirectURI)
	log.Printf("   Client ID: %s", config.ClientID)
	log.Printf("   Code: %s...", code[:minInt(10, len(code))])
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
	helpers.SetCookie(w, r, "sso_access_token", tokenResponse.AccessToken, tokenExpiresIn)

	// Simpan token expires timestamp (current time + expires_in)
	tokenExpiresAt := time.Now().Unix() + int64(tokenExpiresIn)
	helpers.SetCookie(w, r, "sso_token_expires", fmt.Sprintf("%d", tokenExpiresAt), tokenExpiresIn)

	// Simpan ID Token (penting untuk logout dan user info display)
	if tokenResponse.IDToken != "" {
		helpers.SetCookie(w, r, "sso_id_token", tokenResponse.IDToken, tokenExpiresIn)
	}

	log.Printf("✅ Token saved: expires in %d seconds", tokenExpiresIn)

	// Ambil user info dari SSO (WAJIB untuk membuat session)
	userInfo, err := getUserInfoFromSSO(tokenResponse.AccessToken, config)
	if err != nil {
		log.Printf("❌ ERROR getting user info: %v", err)
		log.Printf("⚠️  Cannot create session without user info, redirecting to login")
		http.Redirect(w, r, "/login?error=userinfo_failed&message="+url.QueryEscape("Gagal mengambil informasi user dari SSO"), http.StatusSeeOther)
		return
	}

	// Pastikan email ada
	if userInfo.Email == "" {
		log.Printf("❌ ERROR: Email tidak ditemukan di user info")
		http.Redirect(w, r, "/login?error=missing_email&message="+url.QueryEscape("Email tidak ditemukan"), http.StatusSeeOther)
		return
	}

	log.Printf("📋 User info dari SSO:")
	log.Printf("   Email: %s", userInfo.Email)
	log.Printf("   Name: %s", userInfo.Name)
	log.Printf("   Peran: %s", userInfo.Peran)

	// Buat atau update user di database client
	userID, err := findOrCreateUser(userInfo)
	if err != nil {
		log.Printf("❌ ERROR finding/creating user: %v", err)
		http.Redirect(w, r, "/login?error=user_creation_failed&message="+url.QueryEscape("Gagal membuat user"), http.StatusSeeOther)
		return
	}

	log.Printf("✅ User found/created: %v", userID)

	// Buat session di database client (WAJIB)
	sessionID, err := createSession(userID, r)
	if err != nil {
		log.Printf("❌ ERROR creating session: %v", err)
		http.Redirect(w, r, "/login?error=session_creation_failed&message="+url.QueryEscape("Gagal membuat session"), http.StatusSeeOther)
		return
	}

	log.Printf("✅ Session created: %s", sessionID)

	// Set cookie session dengan nama yang berbeda dari SSO server
	// PENTING: Gunakan cookie name yang berbeda untuk mencegah shared cookie
	// SSO server menggunakan "sso_admin_session", client website menggunakan "client_dinas_session"
	helpers.SetCookie(w, r, "client_dinas_session", sessionID, 86400) // 24 jam
	log.Printf("✅ Cookie 'client_dinas_session' set: %s", sessionID)

	// Set cookie untuk menandakan kapan terakhir kali check ke SSO dilakukan
	// Ini digunakan untuk mencegah loop redirect ke /sso-check
	helpers.SetCookie(w, r, "sso_check_time", fmt.Sprintf("%d", time.Now().Unix()), 3600) // Valid 1 jam
	log.Printf("✅ Cookie 'sso_check_time' set")

	// Log cookie settings untuk debugging
	log.Printf("🔍 Cookie settings:")
	log.Printf("   Request Host: %s", r.Host)
	log.Printf("   Request URL: %s", r.URL.String())
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		log.Printf("   X-Forwarded-Proto: %s", proto)
	}
	if r.TLS != nil {
		log.Printf("   TLS: true")
	}

	// Redirect ke dashboard
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/dashboard"
	}
	log.Printf("🔄 Redirecting to: %s", next)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// ProfileHandler dan renderProfilePageNew telah dipindahkan ke profile_handler.go

// LogoutHandler menangani proses logout user
// Flow:
// 1. Ambil session ID dari cookie client_dinas_session
// 2. Revoke session di database (DELETE dari database)
// 3. Clear SEMUA cookie terkait auth client website
// 4. Redirect ke Keycloak logout endpoint (Centralized Logout)
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Ambil session ID dari cookie client website
	sessionID, _ := helpers.GetCookie(r, "client_dinas_session")
	if sessionID != "" {
		// Revoke session di database (DELETE dari PostgreSQL)
		db, err := connectPostgreSQL()
		if err == nil {
			_, err = db.Exec("DELETE FROM sesi_login WHERE id_sesi = $1", sessionID)
			if err != nil {
				log.Printf("WARNING: Error clearing session: %v", err)
			} else {
				log.Printf("✅ Session revoked from database: %s", sessionID)
			}
			db.Close()
		}
	}

	// Ambil ID Token untuk hint logout ke Keycloak (sebelum dihapus)
	idToken, _ := helpers.GetCookie(r, "sso_id_token")

	// Clear SEMUA cookie terkait auth client website
	helpers.ClearCookie(w, r, "client_dinas_session") // Session dari client website
	helpers.ClearCookie(w, r, "sso_access_token")     // Access token dari SSO (OAuth 2.0)
	helpers.ClearCookie(w, r, "sso_id_token")         // ID token
	helpers.ClearCookie(w, r, "sso_token_expires")    // Token expiration
	helpers.ClearCookie(w, r, "sso_state")            // State untuk CSRF protection
	helpers.ClearCookie(w, r, "oauth_state")          // OAuth State
	helpers.ClearCookie(w, r, "oauth_code_verifier")  // PKCE Verifier
	helpers.ClearCookie(w, r, "session_id")           // Legacy cookie

	log.Printf("✅ All auth cookies cleared, user logged out locally")

	// 4. Redirect ke Keycloak logout endpoint (Centralized Logout)
	// Gunakan helper yang sudah diperbaiki (dengan prefix /sso-auth)
	// Ambil ID Token dari cookie jika ada (untuk id_token_hint)
	idToken, _ = helpers.GetCookie(r, "sso_id_token")
	postLogoutRedirectURI := "http://localhost:8070/login"

	redirectToKeycloakLogout(w, r, idToken, postLogoutRedirectURI)
}

// FrontChannelLogoutHandler menangani request logout DARI Keycloak (bukan dari user)
// Handler ini HANYA menghapus session lokal dan TIDAK redirect balik ke Keycloak
// Ini mencegah infinite loop error.
func FrontChannelLogoutHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("🔔 Front-Channel Logout triggered by Keycloak")

	// Ambil session ID (opsional, untuk logging)
	sessionID, _ := helpers.GetCookie(r, "client_dinas_session")
	if sessionID != "" {
		// Revoke session dari PostgreSQL
		db, err := connectPostgreSQL()
		if err == nil {
			db.Exec("DELETE FROM sesi_login WHERE id_sesi = $1", sessionID)
			db.Close()
		}
		log.Printf("✅ Session revoked: %s", sessionID)
	}

	// Clear SEMUA cookie
	helpers.ClearCookie(w, r, "client_dinas_session")
	helpers.ClearCookie(w, r, "sso_access_token")
	helpers.ClearCookie(w, r, "sso_id_token")
	helpers.ClearCookie(w, r, "sso_token_expires")
	helpers.ClearCookie(w, r, "sso_state")
	helpers.ClearCookie(w, r, "oauth_state")
	helpers.ClearCookie(w, r, "oauth_code_verifier")
	helpers.ClearCookie(w, r, "session_id")

	// Return 200 OK agar Keycloak tahu logout berhasil
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<html><body>Logged out from Client</body></html>"))
}


// SSOLoginHandler initiates the SSO flow (triggered by "Login with SSO" button)
func SSOLoginHandler(w http.ResponseWriter, r *http.Request) {
	// Redirect to Keycloak WITHOUT prompt=none (show login form if needed)
	redirectToKeycloakLogin(w, r, false)
}


// renderLogoutPage menampilkan halaman logout yang akan clear localStorage dan sessionStorage
// sebelum redirect ke halaman login
func renderLogoutPage(w http.ResponseWriter) {
	logoBase64 := base64.StdEncoding.EncodeToString(LogoData)
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logout - Dinas Pendidikan DKI Jakarta</title>
    <link rel="icon" type="image/png" href="/logo.png">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .logout-container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 100%%;
            max-width: 400px;
            padding: 40px;
            text-align: center;
        }
        .logo {
            margin-bottom: 24px;
        }
        .logo img {
            height: 48px;
            margin-bottom: 16px;
        }
        .logo h1 {
            color: #1e293b;
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
        }
        .logo p {
            color: #64748b;
            font-size: 14px;
        }
        .message {
            color: #334155;
            font-size: 16px;
            margin-bottom: 24px;
        }
        .spinner {
            border: 3px solid #f3f4f6;
            border-top: 3px solid #6366f1;
            border-radius: 50%%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 16px;
        }
        @keyframes spin {
            0%% { transform: rotate(0deg); }
            100%% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="logout-container">
        <div class="logo">
            <img src="data:image/png;base64,%s" alt="Logo Dinas Pendidikan">
            <h1>Dinas Pendidikan</h1>
            <p>Provinsi DKI Jakarta</p>
        </div>
        <div class="spinner"></div>
        <p class="message">Sedang keluar dari sistem...</p>
    </div>
    <script>
        // Clear semua data dari localStorage dan sessionStorage
        // PENTING: Hapus app_session_token untuk mencegah redirect loop
        try {
            // Clear localStorage
            localStorage.removeItem('app_session_token');
            localStorage.removeItem('user');
            console.log('✅ localStorage cleared');
            
            // Clear sessionStorage
            sessionStorage.removeItem('sso_access_token');
            sessionStorage.removeItem('sso_id_token');
            sessionStorage.removeItem('sso_user_info');
            sessionStorage.removeItem('redirect_after_login');
            console.log('✅ sessionStorage cleared');
        } catch (error) {
            console.error('Error clearing storage:', error);
        }
        
        // Redirect ke login setelah 500ms
        setTimeout(() => {
            window.location.href = '/login';
        }, 500);
    </script>
</body>
</html>`, logoBase64)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// checkSSOSession checks if user has valid SSO session and creates local session
func checkSSOSession(r *http.Request) bool {
	// Check for SSO token in query parameter
	ssoToken := r.URL.Query().Get("sso_token")
	if ssoToken != "" {
		// Validate SSO token and create session
		// This would typically involve calling SSO server to validate token
		// For now, we'll check if token exists and create session
		// TODO: Implement proper SSO token validation
		return handleSSOToken(r, ssoToken)
	}

	// Check for SSO session cookie
	ssoSession, err := helpers.GetCookie(r, "sso_session")
	if err == nil && ssoSession != "" {
		// Validate SSO session and create local session if valid
		return handleSSOSession(r, ssoSession)
	}

	return false
}

// handleSSOToken processes SSO token and creates local session
func handleSSOToken(r *http.Request, token string) bool {
	// Validate and decode JWT token
	jwtPublicKey := getJWTPublicKey()
	if jwtPublicKey == "" {
		log.Println("ERROR: JWT_PUBLIC_KEY not set for SSO validation")
		return false
	}

	// Parse and validate JWT token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method - support both RSA and HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
			// HMAC uses secret key directly
			return []byte(jwtPublicKey), nil
		}
		if _, ok := token.Method.(*jwt.SigningMethodRSA); ok {
			// RSA uses PEM formatted public key
			// For now, return as byte array - adjust if your key format is different
			return []byte(jwtPublicKey), nil
		}
		// Try to parse as any method - use key as-is
		return []byte(jwtPublicKey), nil
	})

	if err != nil {
		log.Printf("ERROR parsing SSO token: %v", err)
		// Try alternative: treat token as simple base64 encoded user info
		return handleSSOTokenSimple(r, token)
	}

	if !parsedToken.Valid {
		log.Println("ERROR: Invalid SSO token")
		return false
	}

	// Extract claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		log.Println("ERROR: Invalid token claims")
		return false
	}

	// Extract user email from claims
	email, ok := claims["email"].(string)
	if !ok {
		// Try alternative claim names
		if email, ok = claims["sub"].(string); !ok {
			if email, ok = claims["user_email"].(string); !ok {
				log.Println("ERROR: Email not found in token claims")
				return false
			}
		}
	}

	// Get or create user and create session
	sessionID, ok := createSessionFromIdentifier(r, email)
	if !ok {
		return false
	}
	// Note: Cookie will be set by caller using sessionID
	return sessionID != ""
}

// handleSSOTokenSimple handles simple token format (base64 encoded email or direct email)
func handleSSOTokenSimple(r *http.Request, token string) bool {
	// Try to decode as base64
	decoded, err := base64.URLEncoding.DecodeString(token)
	if err == nil {
		// If successful, treat as email
		email := string(decoded)
		if helpers.ValidateEmail(email) {
			sessionID, ok := createSessionFromIdentifier(r, email)
			return ok && sessionID != ""
		}
	}

	// If not base64, try as direct email
	if helpers.ValidateEmail(token) {
		sessionID, ok := createSessionFromIdentifier(r, token)
		return ok && sessionID != ""
	}

	return false
}

// handleSSOSession processes SSO session cookie and creates local session
func handleSSOSession(r *http.Request, session string) bool {
	// Validate SSO session with SSO server
	// Option 1: Session is a JWT token
	if strings.HasPrefix(session, "eyJ") { // JWT tokens typically start with "eyJ"
		return handleSSOToken(r, session)
	}

	// Option 2: Session ID that needs to be validated with SSO server
	// Call SSO server to validate session and get user info
	ssoServerURL := os.Getenv("SSO_SERVER_URL")
	if ssoServerURL == "" {
		log.Println("WARNING: SSO_SERVER_URL not set, cannot validate SSO session")
		// Fallback: try to extract email from session if it's encoded
		return handleSSOTokenSimple(r, session)
	}

	// Validate session with SSO server
	apiURL := fmt.Sprintf("%s/api/validate-session", ssoServerURL)
	httpReq, err := http.NewRequest("POST", apiURL, bytes.NewBufferString(fmt.Sprintf(`{"session":"%s"}`, session)))
	if err != nil {
		log.Printf("ERROR creating SSO validation request: %v", err)
		return false
	}

	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ERROR calling SSO server: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR: SSO session validation failed with status %d", resp.StatusCode)
		return false
	}

	var ssoResponse struct {
		Valid bool                   `json:"valid"`
		Email string                 `json:"email"`
		User  map[string]interface{} `json:"user"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ssoResponse); err != nil {
		log.Printf("ERROR parsing SSO response: %v", err)
		return false
	}

	if !ssoResponse.Valid {
		return false
	}

	// Use identifier (email or username) from SSO response
	identifier := ssoResponse.Email
	if identifier == "" && ssoResponse.User != nil {
		if e, ok := ssoResponse.User["email"].(string); ok {
			identifier = e
		}
		// Fallback to preferred_username if email is missing
		if identifier == "" {
			if u, ok := ssoResponse.User["preferred_username"].(string); ok {
				identifier = u
			}
		}
	}

	if identifier == "" {
		log.Println("ERROR: Identifier (email/username) not found in SSO response")
		return false
	}

	sessionID, ok := createSessionFromIdentifier(r, identifier)
	return ok && sessionID != ""
}

// checkSSOSessionWithCookie checks SSO session and sets cookie if valid
func checkSSOSessionWithCookie(w http.ResponseWriter, r *http.Request) bool {
	// Check for SSO token in query parameter
	ssoToken := r.URL.Query().Get("sso_token")
	if ssoToken != "" {
		return handleSSOTokenWithCookie(w, r, ssoToken)
	}

	// Check for SSO session cookie
	ssoSession, err := helpers.GetCookie(r, "sso_session")
	if err == nil && ssoSession != "" {
		return handleSSOSessionWithCookie(w, r, ssoSession)
	}

	// Check for other common SSO cookie names
	if ssoSession, err = helpers.GetCookie(r, "sso_token"); err == nil && ssoSession != "" {
		return handleSSOTokenWithCookie(w, r, ssoSession)
	}

	return false
}

// createSessionFromIdentifier gets user from database and creates local session
// getUserFromPostgreSQL looks up user from local PostgreSQL database
// createSessionTableIfNotExists creates the sesi_login table if it doesn't exist
func createSessionTableIfNotExists() error {
	db, err := connectPostgreSQL()
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	defer db.Close()

	// Drop existing table if it has foreign key constraints
	dropTableQuery := `DROP TABLE IF EXISTS sesi_login;`
	_, err = db.Exec(dropTableQuery)
	if err != nil {
		log.Printf("WARNING: Failed to drop existing sesi_login table: %v", err)
	}

	// Create new table without foreign key constraints
	createTableQuery := `
		CREATE TABLE sesi_login (
			id SERIAL PRIMARY KEY,
			id_pengguna VARCHAR(255) NOT NULL,
			id_sesi VARCHAR(255) UNIQUE NOT NULL,
			ip VARCHAR(45),
			user_agent TEXT,
			kadaluarsa TIMESTAMP NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`

	_, err = db.Exec(createTableQuery)
	if err != nil {
		return fmt.Errorf("failed to create sesi_login table: %v", err)
	}

	log.Printf("✅ Session table recreated in PostgreSQL (no foreign keys)")
	return nil
}

func getUserFromPostgreSQL(identifier string) (map[string]interface{}, error) {
	db, err := connectPostgreSQL()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	defer db.Close()

	// Query user from PostgreSQL (Schema Baru: account.za_users)
	// Search by identifier in multiple columns
	query := `
		SELECT id, email, nickname, fullname, role_id, is_active 
		FROM account.za_users 
		WHERE (
			email = $1 OR 
			nickname = $1 OR 
			nik = $1 OR 
			nrk = $1 OR 
			nikki = $1 OR 
			npsn = $1 OR 
			nisn = $1
		) AND is_active = '1'
	`

	var user struct {
		ID          string         `json:"id"`
		Email       sql.NullString `json:"email"`
		Nickname    sql.NullString `json:"nickname"`
		Fullname    sql.NullString `json:"fullname"`
		RoleID      sql.NullString `json:"role_id"`
		IsActive    string         `json:"is_active"` // char(1)
	}

	err = db.QueryRow(query, identifier).Scan(
		&user.ID,
		&user.Email,
		&user.Nickname,
		&user.Fullname,
		&user.RoleID,
		&user.IsActive,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("database query error: %v", err)
	}

	// Convert to map[string]interface{} format for compatibility
	// Map new schema columns to old keys expected by the app
	userMap := map[string]interface{}{
		"id_pengguna":   user.ID,
		"email":         user.Email.String,
		"nama_pengguna": user.Nickname.String,
		"nama_lengkap":  user.Fullname.String, // Pastikan ini terisi dari DB
		"peran":         user.RoleID.String,   // Pastikan ini terisi dari DB
		"aktif":         user.IsActive == "1",
	}

	// Fallback jika nama_lengkap kosong, gunakan nickname
	if userMap["nama_lengkap"] == "" {
		userMap["nama_lengkap"] = userMap["nama_pengguna"]
	}
	// Fallback jika peran kosong, set default user
	if userMap["peran"] == "" {
		userMap["peran"] = "user"
	}

	return userMap, nil
}

// ensureUserInSupabase creates user in Supabase if not exists (for session foreign key)
func createSessionFromIdentifier(r *http.Request, identifier string) (string, bool) {
	log.Printf("🔄 Creating session for identifier: %s", identifier)

	// Get user from PostgreSQL database
	log.Printf("🔍 Checking PostgreSQL database for user: %s", identifier)
	pgUser, err := getUserFromPostgreSQL(identifier)
	if err != nil {
		log.Printf("❌ User not found in PostgreSQL: %v", err)
		log.Printf("❌ User with identifier %s not found in database", identifier)
		return "", false
	}

	user := pgUser
	log.Printf("✅ User found in PostgreSQL database: %s (Email: %s)", identifier, user["email"])
	log.Printf("📋 User found in PostgreSQL - Name: %v, Role: %v", user["nama_lengkap"], user["peran"])

	// Check if user is active
	if active, ok := user["aktif"].(bool); !ok || !active {
		log.Printf("WARNING: User %s is not active", identifier)
		return "", false
	}

	// Create local session
	sessionID, err := helpers.GenerateSessionID()
	if err != nil {
		log.Printf("ERROR generating session ID: %v", err)
		return "", false
	}
	// Connect to PostgreSQL
	db, err := connectPostgreSQL()
	if err != nil {
		log.Printf("ERROR connecting to PostgreSQL: %v", err)
		return "", false
	}
	defer db.Close()

	// Ensure session table exists
	if err := createSessionTableIfNotExists(); err != nil {
		log.Printf("ERROR ensuring session table: %v", err)
		return "", false
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	ip := getIPAddress(r)
	userAgent := r.UserAgent()
	userID := user["id_pengguna"] // Gunakan ID dari map yang sudah distandarisasi

	// Insert session into PostgreSQL
	insertQuery := `
		INSERT INTO sesi_login (id_pengguna, id_sesi, ip, user_agent, kadaluarsa, created_at) 
		VALUES ($1, $2, $3, $4, $5, NOW())
	`

	_, err = db.Exec(insertQuery, userID, sessionID, ip, userAgent, expiresAt)
	if err != nil {
		log.Printf("ERROR creating session in PostgreSQL: %v", err)
		return "", false
	}

	log.Printf("✅ Session created successfully in PostgreSQL for user: %s (ID: %v)", user["nama_lengkap"], userID)

	// Return session ID for cookie setting
	return sessionID, true
}

// handleSSOTokenWithCookie processes SSO token and creates local session with cookie
func handleSSOTokenWithCookie(w http.ResponseWriter, r *http.Request, token string) bool {
	log.Printf("🔐 Processing SSO token (length: %d)", len(token))

	// Validate and decode JWT token
	jwtPublicKey := getJWTPublicKey()

	var parsedToken *jwt.Token
	var err error

	if jwtPublicKey == "" {
		log.Println("⚠️ WARNING: JWT_PUBLIC_KEY not set, decoding token without signature validation (development mode)")
		// Untuk development: decode token tanpa validasi signature
		parser := jwt.NewParser()
		parsedToken, _, err = parser.ParseUnverified(token, jwt.MapClaims{})
		if err != nil {
			log.Printf("❌ ERROR parsing SSO token (unverified): %v", err)
			// Try alternative: treat token as simple base64 encoded user info
			return handleSSOTokenSimpleWithCookie(w, r, token)
		}
		log.Println("✅ Token decoded without signature validation (development mode)")
	} else {
		log.Println("🔑 JWT_PUBLIC_KEY found, validating token signature...")
		// Parse and validate JWT token dengan signature validation
		parsedToken, err = jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			// Verify signing method - support both RSA and HMAC
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
				// HMAC uses secret key directly
				return []byte(jwtPublicKey), nil
			}
			if _, ok := token.Method.(*jwt.SigningMethodRSA); ok {
				// RSA uses PEM formatted public key - need to parse it
				rsaPubKey, err := parseRSAPublicKey(jwtPublicKey)
				if err != nil {
					log.Printf("⚠️ WARNING: Failed to parse RSA public key: %v. Falling back to unverified decode.", err)
					// Fallback: return nil to trigger error, then we'll decode unverified
					return nil, fmt.Errorf("invalid RSA public key: %v", err)
				}
				return rsaPubKey, nil
			}
			// Unknown signing method, try as HMAC
			return []byte(jwtPublicKey), nil
		})

		if err != nil {
			log.Printf("❌ ERROR parsing SSO token: %v", err)
			errStr := strings.ToLower(err.Error())
			// If RSA key parsing failed or signature validation failed, try to decode without signature validation
			// Check for various RSA-related error messages
			if strings.Contains(errStr, "invalid rsa public key") ||
				strings.Contains(errStr, "rsa verify expects") ||
				strings.Contains(errStr, "key is of invalid type") ||
				strings.Contains(errStr, "signature is invalid") {
				log.Println("⚠️ WARNING: RSA key parsing/signature validation failed, decoding token without signature validation (development mode)")
				parser := jwt.NewParser()
				parsedToken, _, err = parser.ParseUnverified(token, jwt.MapClaims{})
				if err != nil {
					log.Printf("❌ ERROR parsing SSO token (unverified): %v", err)
					return handleSSOTokenSimpleWithCookie(w, r, token)
				}
				log.Println("✅ Token decoded without signature validation (development mode)")
				// Skip signature validation check since we're in unverified mode
			} else {
				// Try alternative: treat token as simple base64 encoded user info
				return handleSSOTokenSimpleWithCookie(w, r, token)
			}
		} else {
			// Only check validity if we did signature validation
			if !parsedToken.Valid {
				log.Println("❌ ERROR: Invalid SSO token (signature validation failed)")
				return false
			}
			log.Println("✅ Token signature validated successfully")
		}
	}

	// Extract claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		log.Println("❌ ERROR: Invalid token claims type")
		return false
	}

	// Log all claims untuk debugging
	log.Printf("📋 Token claims received:")
	for key, value := range claims {
		log.Printf("   - %s: %v", key, value)
	}

	// Extract user email from claims (try multiple claim names)
	var email string
	var emailFound bool

	// Try email first (most common)
	if emailVal, exists := claims["email"]; exists {
		if emailStr, ok := emailVal.(string); ok && emailStr != "" {
			email = emailStr
			emailFound = true
			log.Printf("✅ Email found in 'email' claim: %s", email)
		}
	}

	// Try preferred_username as fallback
	if !emailFound {
		if usernameVal, exists := claims["preferred_username"]; exists {
			if usernameStr, ok := usernameVal.(string); ok && usernameStr != "" {
				email = usernameStr
				emailFound = true
				log.Printf("✅ Email found in 'preferred_username' claim: %s", email)
			}
		}
	}

	// Try sub as last resort (usually user ID, but might be email)
	if !emailFound {
		if subVal, exists := claims["sub"]; exists {
			if subStr, ok := subVal.(string); ok && subStr != "" {
				// Check if sub looks like an email
				if strings.Contains(subStr, "@") {
					email = subStr
					emailFound = true
					log.Printf("✅ Email found in 'sub' claim: %s", email)
				}
			}
		}
	}

	if !emailFound {
		log.Printf("❌ ERROR: Email not found in token claims. Available claims: %v", func() []string {
			keys := make([]string, 0, len(claims))
			for k := range claims {
				keys = append(keys, k)
			}
			return keys
		}())
		return false
	}

	log.Printf("✅ Email extracted from token: %s", email)

	// Get or create user and create session
	log.Printf("🔄 Creating session for email: %s", email)
	sessionID, ok := createSessionFromIdentifier(r, email)
	if !ok {
		log.Printf("❌ Failed to create session for email: %s", email)
		return false
	}
	log.Printf("✅ Session created successfully: %s", sessionID)

	// Set cookie dengan nama yang konsisten (client_dinas_session)
	helpers.SetCookie(w, r, "client_dinas_session", sessionID, 86400) // 24 jam
	// Juga set session_id untuk backward compatibility
	helpers.SetCookie(w, r, "session_id", sessionID, 86400)
	log.Printf("✅ SSO token processed, session created: %s", sessionID)
	return true
}

// handleSSOTokenSimpleWithCookie handles simple token format with cookie setting
func handleSSOTokenSimpleWithCookie(w http.ResponseWriter, r *http.Request, token string) bool {
	// Try to decode as base64
	decoded, err := base64.URLEncoding.DecodeString(token)
	if err == nil {
		// If successful, treat as email
		email := string(decoded)
		if helpers.ValidateEmail(email) {
			sessionID, ok := createSessionFromIdentifier(r, email)
			if ok {
				helpers.SetCookie(w, r, "session_id", sessionID, 86400)
				return true
			}
		}
	}

	// If not base64, try as direct email
	if helpers.ValidateEmail(token) {
		sessionID, ok := createSessionFromIdentifier(r, token)
		if ok {
			helpers.SetCookie(w, r, "session_id", sessionID, 86400)
			return true
		}
	}

	return false
}

// handleSSOSessionWithCookie processes SSO session cookie and creates local session with cookie
func handleSSOSessionWithCookie(w http.ResponseWriter, r *http.Request, session string) bool {
	// Validate SSO session with SSO server
	// Option 1: Session is a JWT token
	if strings.HasPrefix(session, "eyJ") { // JWT tokens typically start with "eyJ"
		return handleSSOTokenWithCookie(w, r, session)
	}

	// Option 2: Session ID that needs to be validated with SSO server
	// Call SSO server to validate session and get user info
	ssoServerURL := os.Getenv("SSO_SERVER_URL")
	if ssoServerURL == "" {
		log.Println("WARNING: SSO_SERVER_URL not set, trying simple token handling")
		// Fallback: try to extract email from session if it's encoded
		return handleSSOTokenSimpleWithCookie(w, r, session)
	}

	// Validate session with SSO server
	apiURL := fmt.Sprintf("%s/api/validate-session", ssoServerURL)
	httpReq, err := http.NewRequest("POST", apiURL, bytes.NewBufferString(fmt.Sprintf(`{"session":"%s"}`, session)))
	if err != nil {
		log.Printf("ERROR creating SSO validation request: %v", err)
		return false
	}

	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ERROR calling SSO server: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR: SSO session validation failed with status %d", resp.StatusCode)
		return false
	}

	var ssoResponse struct {
		Valid bool                   `json:"valid"`
		Email string                 `json:"email"`
		User  map[string]interface{} `json:"user"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ssoResponse); err != nil {
		log.Printf("ERROR parsing SSO response: %v", err)
		return false
	}

	if !ssoResponse.Valid {
		return false
	}

	// Use identifier (email or username) from SSO response
	identifier := ssoResponse.Email
	if identifier == "" && ssoResponse.User != nil {
		if e, ok := ssoResponse.User["email"].(string); ok {
			identifier = e
		}
		// Fallback to preferred_username if email is missing
		if identifier == "" {
			if u, ok := ssoResponse.User["preferred_username"].(string); ok {
				identifier = u
			}
		}
	}

	if identifier == "" {
		log.Println("ERROR: Identifier (email/username) not found in SSO response")
		return false
	}

	sessionID, ok := createSessionFromIdentifier(r, identifier)
	if !ok {
		return false
	}

	// Set cookie
	helpers.SetCookie(w, r, "session_id", sessionID, 86400)
	return true
}

// Authentication helpers
func isAuthenticated(r *http.Request) bool {
	// PENTING: Client website hanya boleh menggunakan:
	// 1. OAuth 2.0 access token (dari SSO callback)
	// 2. Session yang dibuat oleh client website sendiri (setelah user authorize)
	// JANGAN gunakan session yang dibuat oleh SSO server langsung!

	// Cek 1: OAuth 2.0 access token (prioritas pertama)
	accessToken, err := helpers.GetCookie(r, "sso_access_token")
	if err == nil && accessToken != "" {
		// Cek token expiration
		tokenExpiresStr, err := helpers.GetCookie(r, "sso_token_expires")
		if err == nil && tokenExpiresStr != "" {
			if tokenExpires, err := strconv.ParseInt(tokenExpiresStr, 10, 64); err == nil {
				if time.Now().Unix() <= tokenExpires {
					// Access token valid
					return true
				}
			}
		}
	}

	// Cek 2: Session yang dibuat oleh client website sendiri
	// PENTING: Hanya gunakan cookie client_dinas_session, JANGAN gunakan sso_admin_session dari SSO server
	sessionID, err := helpers.GetCookie(r, "client_dinas_session")
	if err != nil {
		// Fallback ke session_id untuk backward compatibility (cookie lama dari direct login)
		sessionID, err = helpers.GetCookie(r, "session_id")
		if err != nil {
			return false
		}
	}

	// Validate session using local PostgreSQL connection (same as DashboardHandler)
	userID, ok, err := validateSession(sessionID)
	if !ok || err != nil || userID == "" {
		log.Printf("WARNING: Session invalid in isAuthenticated: %v, error: %v", ok, err)
		return false
	}

	return true
}

func getCurrentUser(r *http.Request) (map[string]interface{}, error) {
	// PENTING: Gunakan cookie client_dinas_session terlebih dahulu, bukan session_id
	// Ini untuk konsistensi dengan semua page lain yang sudah menggunakan client_dinas_session
	sessionID, err := helpers.GetCookie(r, "client_dinas_session")
	if err != nil {
		// Fallback ke session_id untuk backward compatibility (cookie lama dari direct login)
		sessionID, err = helpers.GetCookie(r, "session_id")
		if err != nil {
			return nil, err
		}
	}

	// Validate Supabase connection
	supabaseURL := getSupabaseURL()
	supabaseKey := getSupabaseKey()
	if supabaseURL == "" || supabaseKey == "" {
		return nil, fmt.Errorf("supabase not configured")
	}

	// Validasi session dan ambil user ID (sama seperti dashboard)
	userID, ok, err := validateSession(sessionID)
	if !ok || err != nil || userID == "" {
		return nil, fmt.Errorf("session tidak valid")
	}

	// Ambil data user dari database menggunakan getUserByIDForHome (sama seperti dashboard)
	user, err := getUserByIDForHome(userID)
	if err != nil {
		return nil, fmt.Errorf("gagal mengambil user: %v", err)
	}

	return user, nil
}

// API Handlers
// handleLoginAPI telah dihapus sepenuhnya

// handleRegisterAPI telah dihapus - Registrasi dilakukan melalui SSO Keycloak

func handleLogoutAPI(w http.ResponseWriter, r *http.Request) {
	sessionID, err := helpers.GetCookie(r, "session_id")
	if err == nil {
		// Delete session from Supabase
		url := fmt.Sprintf("%s/rest/v1/sesi_login?id_sesi=eq.%s", getSupabaseURL(), sessionID)
		httpReq, _ := http.NewRequest("DELETE", url, nil)
		httpReq.Header.Set("apikey", getSupabaseKey())
		httpReq.Header.Set("Authorization", "Bearer "+getSupabaseKey())
		http.DefaultClient.Do(httpReq)
	}

	helpers.ClearCookie(w, r, "session_id")
	helpers.WriteSuccess(w, "Logout berhasil", nil)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID, err := helpers.GetCookie(r, "session_id")
	if err == nil {
		url := fmt.Sprintf("%s/rest/v1/sesi_login?id_sesi=eq.%s", getSupabaseURL(), sessionID)
		httpReq, _ := http.NewRequest("DELETE", url, nil)
		httpReq.Header.Set("apikey", getSupabaseKey())
		httpReq.Header.Set("Authorization", "Bearer "+getSupabaseKey())
		http.DefaultClient.Do(httpReq)
	}

	helpers.ClearCookie(w, r, "session_id")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleGetProfileAPI(w http.ResponseWriter, r *http.Request) {
	user, err := getCurrentUser(r)
	if err != nil {
		helpers.WriteError(w, http.StatusUnauthorized, "Tidak terautentikasi")
		return
	}

	// Schema: id_pengguna adalah primary key, bukan id
	userID := user["id_pengguna"]
	if userID == nil {
		userID = user["id"] // Fallback untuk backward compatibility
	}

	helpers.WriteSuccess(w, "Profile retrieved", map[string]interface{}{
		"id_pengguna":  userID,
		"email":        user["email"],
		"nama_lengkap": user["nama_lengkap"],
		"peran":        user["peran"],
	})
}

// handleUpdateProfileAPI telah dihapus - Data user dikelola oleh SSO Keycloak
// handleChangePasswordAPI telah dihapus - Password dikelola oleh SSO Keycloak

func handleGetNewsAPI(w http.ResponseWriter, r *http.Request) {
	url := fmt.Sprintf("%s/rest/v1/berita?published=eq.true&order=created_at.desc&limit=20", getSupabaseURL())
	httpReq, _ := http.NewRequest("GET", url, nil)
	httpReq.Header.Set("apikey", getSupabaseKey())
	httpReq.Header.Set("Authorization", "Bearer "+getSupabaseKey())

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal mengambil berita")
		return
	}
	defer resp.Body.Close()

	var news []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&news)

	helpers.WriteSuccess(w, "Berita retrieved", news)
}

func handleGetAnnouncementsAPI(w http.ResponseWriter, r *http.Request) {
	url := fmt.Sprintf("%s/rest/v1/pengumuman?published=eq.true&order=created_at.desc&limit=10", getSupabaseURL())
	httpReq, _ := http.NewRequest("GET", url, nil)
	httpReq.Header.Set("apikey", getSupabaseKey())
	httpReq.Header.Set("Authorization", "Bearer "+getSupabaseKey())

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal mengambil pengumuman")
		return
	}
	defer resp.Body.Close()

	var announcements []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&announcements)

	helpers.WriteSuccess(w, "Pengumuman retrieved", announcements)
}

// ============================================
// SSO KEYCLOAK HANDLERS
// ============================================
// Semua handler SSO Keycloak ada di section ini untuk memudahkan pencarian
// File: api/main_handler.go

// handleSSOUserLoginAPI - Endpoint POST /api/users/sso-login
// Check atau create user di database berdasarkan data dari SSO Keycloak
// Request body: { "email": "...", "name": "...", "keycloak_id": "..." }
// Headers: Authorization: Bearer <sso_access_token>
// Response: { "user": { "id": "...", "email": "...", "name": "...", "keycloak_id": "..." } }
func handleSSOUserLoginAPI(w http.ResponseWriter, r *http.Request) {
	// Verify Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		helpers.WriteError(w, http.StatusUnauthorized, "Authorization header required")
		return
	}

	// Parse request body
	var req struct {
		Email      string `json:"email"`
		Name       string `json:"name"`
		KeycloakID string `json:"keycloak_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("ERROR parsing request body: %v", err)
		helpers.WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if req.Email == "" {
		helpers.WriteError(w, http.StatusBadRequest, "Email is required")
		return
	}

	if req.KeycloakID == "" {
		helpers.WriteError(w, http.StatusBadRequest, "keycloak_id is required")
		return
	}

	supabaseURL := getSupabaseURL()
	supabaseKey := getSupabaseKey()
	if supabaseURL == "" || supabaseKey == "" {
		helpers.WriteError(w, http.StatusInternalServerError, "Database configuration error")
		return
	}

	// Check if user exists by email
	// Note: Jika ada kolom keycloak_id di tabel pengguna, bisa tambahkan query OR keycloak_id = ?
	emailEncoded := url.QueryEscape(req.Email)

	// Cek berdasarkan email
	apiURL := fmt.Sprintf("%s/rest/v1/pengguna?email=eq.%s&select=*", supabaseURL, emailEncoded)

	httpReq, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		log.Printf("ERROR creating request: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Failed to query database")
		return
	}

	httpReq.Header.Set("apikey", supabaseKey)
	httpReq.Header.Set("Authorization", "Bearer "+supabaseKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ERROR calling Supabase: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Failed to connect to database")
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var users []map[string]interface{}

	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(bodyBytes, &users); err != nil {
			log.Printf("ERROR parsing response: %v", err)
			helpers.WriteError(w, http.StatusInternalServerError, "Failed to parse response")
			return
		}
	}

	var user map[string]interface{}

	// Jika user tidak ditemukan, create user baru
	if len(users) == 0 {
		log.Printf("User tidak ditemukan, membuat user baru: %s", req.Email)

		// Prepare user data
		// Schema: id_pengguna (PK), email, password, nama_lengkap, peran, aktif
		// Untuk SSO user, kita set password kosong atau random (karena login via SSO)
		// Peran default: "user" (bisa diubah sesuai kebutuhan)
		userData := map[string]interface{}{
			"email":        req.Email,
			"nama_lengkap": req.Name,
			"peran":        "user", // Default role, bisa diubah sesuai kebutuhan
			"aktif":        true,
			// Note: Jika ada kolom keycloak_id di schema, tambahkan:
			// "keycloak_id": req.KeycloakID,
		}

		// Set password default (random string) untuk SSO user
		// User SSO tidak akan login dengan password, tapi tetap perlu kolom password jika NOT NULL
		// Kita tidak perlu hash password karena tidak akan pernah diverifikasi
		userData["password"] = "sso_user_no_password_" + req.KeycloakID

		// Create user di Supabase
		userJSON, _ := json.Marshal(userData)
		createURL := fmt.Sprintf("%s/rest/v1/pengguna", supabaseURL)
		createReq, err := http.NewRequest("POST", createURL, bytes.NewBuffer(userJSON))
		if err != nil {
			log.Printf("ERROR creating request: %v", err)
			helpers.WriteError(w, http.StatusInternalServerError, "Failed to create user")
			return
		}

		createReq.Header.Set("apikey", supabaseKey)
		createReq.Header.Set("Authorization", "Bearer "+supabaseKey)
		createReq.Header.Set("Content-Type", "application/json")
		createReq.Header.Set("Prefer", "return=representation")

		createResp, err := http.DefaultClient.Do(createReq)
		if err != nil {
			log.Printf("ERROR calling Supabase: %v", err)
			helpers.WriteError(w, http.StatusInternalServerError, "Failed to create user")
			return
		}
		defer createResp.Body.Close()

		createBodyBytes, _ := io.ReadAll(createResp.Body)
		if createResp.StatusCode != http.StatusOK && createResp.StatusCode != http.StatusCreated {
			log.Printf("ERROR Supabase response: Status %d, Body: %s", createResp.StatusCode, string(createBodyBytes))
			helpers.WriteError(w, http.StatusInternalServerError, "Failed to create user")
			return
		}

		var newUsers []map[string]interface{}
		if err := json.Unmarshal(createBodyBytes, &newUsers); err != nil {
			log.Printf("ERROR parsing response: %v", err)
			helpers.WriteError(w, http.StatusInternalServerError, "Failed to parse response")
			return
		}

		if len(newUsers) == 0 {
			helpers.WriteError(w, http.StatusInternalServerError, "Failed to create user")
			return
		}

		user = newUsers[0]
		log.Printf("✅ User created: %s", req.Email)
	} else {
		// User sudah ada
		user = users[0]
		log.Printf("✅ User found: %s", req.Email)
	}

	// Extract user ID (bisa id_pengguna atau id)
	userID := ""
	if idPengguna, ok := user["id_pengguna"].(string); ok {
		userID = idPengguna
	} else if id, ok := user["id"].(string); ok {
		userID = id
	} else {
		userID = fmt.Sprintf("%v", user["id_pengguna"])
	}

	// Return user data
	response := map[string]interface{}{
		"user": map[string]interface{}{
			"id":          userID,
			"email":       user["email"],
			"name":        user["nama_lengkap"],
			"keycloak_id": req.KeycloakID,
		},
	}

	helpers.WriteJSON(w, http.StatusOK, response)
}

// handleSSOAuthLoginAPI - Endpoint POST /api/auth/sso-login
// Create session aplikasi setelah user berhasil login via SSO
// Request body: { "email": "...", "keycloak_id": "..." }
// Headers: Authorization: Bearer <sso_access_token>
// Response: { "session_token": "...", "user": { ... } }
func handleSSOAuthLoginAPI(w http.ResponseWriter, r *http.Request) {
	// Verify Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		helpers.WriteError(w, http.StatusUnauthorized, "Authorization header required")
		return
	}

	// Parse request body
	var req struct {
		Email      string `json:"email"`
		KeycloakID string `json:"keycloak_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("ERROR parsing request body: %v", err)
		helpers.WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if req.Email == "" {
		helpers.WriteError(w, http.StatusBadRequest, "Email is required")
		return
	}

	supabaseURL := getSupabaseURL()
	supabaseKey := getSupabaseKey()
	if supabaseURL == "" || supabaseKey == "" {
		helpers.WriteError(w, http.StatusInternalServerError, "Database configuration error")
		return
	}

	// Get user by email
	emailEncoded := url.QueryEscape(req.Email)
	apiURL := fmt.Sprintf("%s/rest/v1/pengguna?email=eq.%s&select=*", supabaseURL, emailEncoded)

	httpReq, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		log.Printf("ERROR creating request: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Failed to query database")
		return
	}

	httpReq.Header.Set("apikey", supabaseKey)
	httpReq.Header.Set("Authorization", "Bearer "+supabaseKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ERROR calling Supabase: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Failed to connect to database")
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var users []map[string]interface{}

	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(bodyBytes, &users); err != nil {
			log.Printf("ERROR parsing response: %v", err)
			helpers.WriteError(w, http.StatusInternalServerError, "Failed to parse response")
			return
		}
	}

	if len(users) == 0 {
		helpers.WriteError(w, http.StatusNotFound, "User not found")
		return
	}

	user := users[0]

	// Extract user ID
	userID := ""
	if idPengguna, ok := user["id_pengguna"].(string); ok {
		userID = idPengguna
	} else if id, ok := user["id"].(string); ok {
		userID = id
	} else {
		userID = fmt.Sprintf("%v", user["id_pengguna"])
	}

	// Create session
	sessionID, err := createSession(userID, r)
	if err != nil {
		log.Printf("ERROR creating session: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Failed to create session")
		return
	}

	// Set cookie
	helpers.SetCookie(w, r, "client_dinas_session", sessionID, 86400) // 24 jam

	log.Printf("✅ SSO session created: %s for user: %s", sessionID, req.Email)

	// Return response
	response := map[string]interface{}{
		"session_token": sessionID,
		"user": map[string]interface{}{
			"id":    userID,
			"email": user["email"],
			"name":  user["nama_lengkap"],
		},
	}

	helpers.WriteJSON(w, http.StatusOK, response)
}

// Helper functions
func getIPAddress(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-Ip")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	return strings.Split(ip, ",")[0]
}

// Session Management Functions (moved from internal/session_helper.go for Vercel compatibility)

// createSession membuat session baru di database dan mengembalikan session ID

// validateSession memvalidasi session ID dan mengembalikan user ID jika valid
func validateSession(sessionID string) (userID string, ok bool, err error) {
	if sessionID == "" {
		log.Printf("🔍 validateSession: session ID kosong")
		return "", false, fmt.Errorf("session ID kosong")
	}

	log.Printf("🔍 validateSession: checking session ID: %s", sessionID)

	// Connect to PostgreSQL
	db, err := connectPostgreSQL()
	if err != nil {
		log.Printf("❌ validateSession: failed to connect to PostgreSQL: %v", err)
		return "", false, fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	defer db.Close()

	// Query session from PostgreSQL
	var userIDResult string
	query := `
		SELECT id_pengguna 
		FROM sesi_login 
		WHERE id_sesi = $1 AND kadaluarsa > NOW()
	`

	log.Printf("🔍 validateSession: executing query with sessionID: %s", sessionID)
	err = db.QueryRow(query, sessionID).Scan(&userIDResult)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("❌ validateSession: session not found or expired for ID: %s", sessionID)
			return "", false, nil // Session tidak ditemukan atau sudah expired
		}
		log.Printf("❌ validateSession: error querying session: %v", err)
		return "", false, fmt.Errorf("error querying session: %v", err)
	}

	log.Printf("✅ validateSession: session valid for user: %s", userIDResult)

	return userIDResult, true, nil
}

// clearSession menghapus session di database PostgreSQL
func clearSession(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID kosong")
	}

	// Connect to PostgreSQL
	db, err := connectPostgreSQL()
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	defer db.Close()

	// Delete session from PostgreSQL
	query := `DELETE FROM sesi_login WHERE id_sesi = $1`
	_, err = db.Exec(query, sessionID)
	if err != nil {
		return fmt.Errorf("error deleting session: %v", err)
	}

	return nil
}

// createSession creates a new session in PostgreSQL database
func createSession(userID interface{}, r *http.Request) (sessionID string, err error) {
	// Generate session ID
	sessionID, err = helpers.GenerateSessionID()
	if err != nil {
		log.Printf("ERROR generating session ID: %v", err)
		return "", fmt.Errorf("gagal membuat session ID")
	}

	// Connect to PostgreSQL
	db, err := connectPostgreSQL()
	if err != nil {
		return "", fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	defer db.Close()

	// Ensure session table exists
	err = createSessionTableIfNotExists()
	if err != nil {
		return "", fmt.Errorf("failed to ensure session table: %v", err)
	}

	// Prepare session data
	expiresAt := time.Now().Add(24 * time.Hour)

	// Insert session into PostgreSQL
	insertQuery := `
		INSERT INTO sesi_login (id_pengguna, id_sesi, ip, user_agent, kadaluarsa, created_at) 
		VALUES ($1, $2, $3, $4, $5, NOW())
	`

	_, err = db.Exec(insertQuery, userID, sessionID, getIPAddress(r), r.UserAgent(), expiresAt)
	if err != nil {
		log.Printf("ERROR creating session in PostgreSQL: %v", err)
		return "", fmt.Errorf("gagal membuat session")
	}

	log.Printf("✅ Session created in PostgreSQL: %s", sessionID)
	return sessionID, nil
}

// Page rendering functions
func renderLoginPage(w http.ResponseWriter, errorMsg, _ string) {
	logoBase64 := base64.StdEncoding.EncodeToString(LogoData)
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login SSO - Dinas Pendidikan DKI Jakarta</title>
    <link rel="icon" type="image/png" href="/logo.png">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .login-container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 100%%;
            max-width: 420px;
            padding: 40px;
            text-align: center;
        }
        .logo {
            margin-bottom: 32px;
        }
        .logo img {
            height: 64px;
            margin-bottom: 16px;
        }
        .logo h1 {
            color: #1e293b;
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
        }
        .logo p {
            color: #64748b;
            font-size: 14px;
        }
        .sso-info {
            background: #f0f4ff;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
        }
        .sso-info p {
            color: #4f46e5;
            font-size: 14px;
            line-height: 1.6;
        }
        .btn-sso {
            width: 100%%;
            padding: 16px 24px;
            background: linear-gradient(135deg, #4f46e5 0%%, #4338ca 100%%);
            color: white;
            border: none;
            border-radius: 12px;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            text-decoration: none;
            box-shadow: 0 4px 15px rgba(79, 70, 229, 0.4);
        }
        .btn-sso:hover {
            background: linear-gradient(135deg, #4338ca 0%%, #3730a3 100%%);
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(79, 70, 229, 0.5);
        }
        .btn-sso:active {
            transform: translateY(0);
        }
        .btn-sso svg {
            width: 24px;
            height: 24px;
            margin-right: 12px;
        }
        .error-popup {
            position: fixed;
            top: 20px;
            right: 20px;
            background: #dc2626;
            color: white;
            padding: 16px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            display: none;
            z-index: 1000;
            max-width: 400px;
        }
        .error-popup.show {
            display: block;
            animation: slideIn 0.3s ease;
        }
        @keyframes slideIn {
            from { transform: translateX(400px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        .footer-text {
            margin-top: 24px;
            color: #94a3b8;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <img src="data:image/png;base64,%s" alt="Logo Dinas Pendidikan">
            <h1>Dinas Pendidikan</h1>
            <p>Provinsi DKI Jakarta</p>
        </div>
        
        <div class="sso-info">
            <p>Silakan login menggunakan akun SSO Dinas Pendidikan Anda untuk mengakses sistem.</p>
        </div>

        <a href="/sso/login" class="btn-sso" id="ssoLoginBtn">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>
            </svg>
            Login dengan SSO
        </a>
        
        <p class="footer-text">Single Sign-On (SSO) powered by Keycloak</p>
    </div>
    <div class="error-popup" id="errorPopup"></div>
    <script>
        function showError(message) {
            const popup = document.getElementById('errorPopup');
            popup.textContent = message;
            popup.classList.add('show');
            setTimeout(() => popup.classList.remove('show'), 5000);
        }
        %s
    </script>
</body>
</html>`, logoBase64, func() string {
		if errorMsg != "" {
			return fmt.Sprintf("showError('%s');", strings.ReplaceAll(errorMsg, "'", "\\'"))
		}
		return ""
	}())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// renderRegisterPage telah dihapus - Registrasi dilakukan melalui SSO Keycloak

func getCommonHeader(user map[string]interface{}) string {
	logoBase64 := base64.StdEncoding.EncodeToString(LogoData)
	userName := "User"
	if name, ok := user["nama_lengkap"].(string); ok {
		userName = name
	}
	return fmt.Sprintf(`<header style="background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); position: sticky; top: 0; z-index: 100;">
    <nav style="max-width: 1200px; margin: 0 auto; padding: 16px 24px; display: flex; align-items: center; justify-content: space-between;">
        <div style="display: flex; align-items: center; gap: 16px;">
            <img src="data:image/png;base64,%s" alt="Logo" style="height: 40px;">
            <div>
                <h1 style="font-size: 18px; font-weight: 600; color: #1e293b; margin: 0;">Dinas Pendidikan</h1>
                <p style="font-size: 12px; color: #64748b; margin: 0;">DKI Jakarta</p>
            </div>
        </div>
        <div style="display: flex; align-items: center; gap: 24px;">
            <a href="/" style="text-decoration: none; color: #334155; font-weight: 500; font-size: 14px;">Beranda</a>
            <a href="/about" style="text-decoration: none; color: #334155; font-weight: 500; font-size: 14px;">Tentang</a>
            <a href="/services" style="text-decoration: none; color: #334155; font-weight: 500; font-size: 14px;">Layanan</a>
            <a href="/news" style="text-decoration: none; color: #334155; font-weight: 500; font-size: 14px;">Berita</a>
            <div style="display: flex; align-items: center; gap: 12px; padding-left: 24px; border-left: 1px solid #e2e8f0;">
                <span id="headerUserName" style="color: #64748b; font-size: 14px;">%s</span>
                <a href="/profile" style="text-decoration: none; color: #6366f1; font-weight: 500; font-size: 14px;">Profile</a>
                <a href="/logout" style="text-decoration: none; color: #dc2626; font-weight: 500; font-size: 14px;">Keluar</a>
            </div>
        </div>
    </nav>
    <script>
        // Update header dengan data dari sessionStorage SSO jika tersedia
        (function() {
            try {
                const ssoUserInfoStr = sessionStorage.getItem('sso_user_info');
                if (ssoUserInfoStr) {
                    const ssoUserInfo = JSON.parse(ssoUserInfoStr);
                    const userNameSpan = document.getElementById('headerUserName');
                    if (userNameSpan && ssoUserInfo.name) {
                        userNameSpan.textContent = ssoUserInfo.name;
                        console.log('✅ Updated header name from SSO:', ssoUserInfo.name);
                    }
                }
            } catch (error) {
                console.error('Error updating header from SSO:', error);
            }
        })();
    </script>
</header>`, logoBase64, userName)
}

func renderHomePage(w http.ResponseWriter, r *http.Request) {
	// Gunakan logika yang sama seperti dashboard untuk konsistensi
	// Cek session dengan cookie client_dinas_session
	sessionID, err := helpers.GetCookie(r, "client_dinas_session")
	if err != nil {
		// Fallback ke session_id untuk backward compatibility
		sessionID, err = helpers.GetCookie(r, "session_id")
	}

	var user map[string]interface{}
	if err == nil && sessionID != "" {
		// Validasi session dan ambil user ID
		userID, ok, err := validateSession(sessionID)
		if ok && err == nil && userID != "" {
			// Ambil data user dari database (sama seperti dashboard)
			user, err = getUserByIDForHome(userID)
			if err != nil {
				log.Printf("WARNING: Error getting user: %v", err)
				user = make(map[string]interface{})
			}
		} else {
			user = make(map[string]interface{})
		}
	} else {
		// Fallback ke getCurrentUser untuk backward compatibility
		user, _ = getCurrentUser(r)
	}

	header := getCommonHeader(user)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Beranda - Dinas Pendidikan DKI Jakarta</title>
    <meta name="description" content="Portal informasi dan layanan Dinas Pendidikan Provinsi DKI Jakarta">
    <link rel="icon" type="image/png" href="/logo.png">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f8fafc;
            color: #1e293b;
            line-height: 1.6;
        }
        .hero {
            background: linear-gradient(135deg, #6366f1 0%%, #8b5cf6 100%%);
            color: white;
            padding: 80px 24px;
            text-align: center;
        }
        .hero h1 {
            font-size: 48px;
            font-weight: 700;
            margin-bottom: 16px;
            letter-spacing: -0.025em;
        }
        .hero p {
            font-size: 20px;
            opacity: 0.9;
            max-width: 600px;
            margin: 0 auto;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 48px 24px;
        }
        .section {
            margin-bottom: 48px;
        }
        .section-title {
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 24px;
            color: #1e293b;
        }
        .card-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 24px;
            margin-top: 24px;
        }
        .card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .card:hover {
            transform: translateY(-4px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.15);
        }
        .card h3 {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 12px;
            color: #1e293b;
        }
        .card p {
            color: #64748b;
            font-size: 15px;
        }
        .btn {
            display: inline-block;
            padding: 12px 24px;
            background: #6366f1;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 500;
            margin-top: 16px;
            transition: background 0.2s;
        }
        .btn:hover {
            background: #4f46e5;
        }
        footer {
            background: #1e293b;
            color: white;
            padding: 48px 24px;
            text-align: center;
        }
        @media (max-width: 768px) {
            .hero h1 { font-size: 32px; }
            .hero p { font-size: 18px; }
            .card-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    %s
    <div class="hero">
        <h1>Selamat Datang</h1>
        <p>Portal Informasi dan Layanan Dinas Pendidikan Provinsi DKI Jakarta</p>
    </div>
    <div class="container">
        <section class="section">
            <h2 class="section-title">Layanan Cepat</h2>
            <div class="card-grid">
                <div class="card">
                    <h3>Informasi Sekolah</h3>
                    <p>Akses informasi lengkap tentang sekolah-sekolah di DKI Jakarta</p>
                    <a href="/services" class="btn">Lihat Layanan</a>
                </div>
                <div class="card">
                    <h3>Berita & Pengumuman</h3>
                    <p>Dapatkan informasi terbaru seputar pendidikan di DKI Jakarta</p>
                    <a href="/news" class="btn">Baca Berita</a>
                </div>
                <div class="card">
                    <h3>Tentang Kami</h3>
                    <p>Pelajari lebih lanjut tentang Dinas Pendidikan DKI Jakarta</p>
                    <a href="/about" class="btn">Tentang Kami</a>
                </div>
            </div>
        </section>
        <section class="section">
            <h2 class="section-title">Pengumuman Terbaru</h2>
            <div id="announcements" class="card-grid">
                <div class="card">
                    <p style="color: #64748b;">Memuat pengumuman...</p>
                </div>
            </div>
        </section>
    </div>
    <footer>
        <p>&copy; 2025 Dinas Pendidikan Provinsi DKI Jakarta. All rights reserved.</p>
    </footer>
    <script>
        async function loadAnnouncements() {
            try {
                const res = await fetch('/api/announcements');
                const data = await res.json();
                const container = document.getElementById('announcements');
                if (data.success && data.data && data.data.length > 0) {
                    container.innerHTML = data.data.slice(0, 3).map(item => {
                        return '<div class="card"><h3>' + (item.judul || 'Pengumuman') + '</h3><p>' + ((item.konten || '').substring(0, 100)) + '...</p></div>';
                    }).join('');
                } else {
                    container.innerHTML = '<div class="card"><p>Belum ada pengumuman</p></div>';
                }
            } catch (error) {
                console.error('Error loading announcements:', error);
            }
        }
        loadAnnouncements();
    </script>
</body>
</html>`, header)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// getUserByIDForHome mengambil data user dari Supabase berdasarkan ID (untuk home page)
// Sama seperti getUserByID di ui_dashboard.go, tapi di sini untuk menghindari circular dependency
func getUserByIDForHome(userID string) (map[string]interface{}, error) {
	supabaseURL := getSupabaseURL()
	supabaseKey := getSupabaseKey()
	if supabaseURL == "" || supabaseKey == "" {
		return nil, fmt.Errorf("SUPABASE_URL atau SUPABASE_KEY tidak di-set")
	}

	userIDEncoded := url.QueryEscape(userID)
	// Schema: id_pengguna adalah primary key, bukan id
	apiURL := fmt.Sprintf("%s/rest/v1/pengguna?id_pengguna=eq.%s&select=*", supabaseURL, userIDEncoded)

	httpReq, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("apikey", supabaseKey)
	httpReq.Header.Set("Authorization", "Bearer "+supabaseKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gagal mengambil user: status %d", resp.StatusCode)
	}

	var users []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &users); err != nil {
		return nil, err
	}

	if len(users) == 0 {
		return nil, fmt.Errorf("user tidak ditemukan")
	}

	return users[0], nil
}

func renderAboutPage(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)
	header := getCommonHeader(user)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tentang Kami - Dinas Pendidikan DKI Jakarta</title>
    <meta name="description" content="Tentang Dinas Pendidikan Provinsi DKI Jakarta">
    <link rel="icon" type="image/png" href="/logo.png">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f8fafc;
            color: #1e293b;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 48px 24px;
        }
        .card {
            background: white;
            border-radius: 12px;
            padding: 32px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            margin-bottom: 24px;
        }
        .card h2 {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 16px;
            color: #1e293b;
        }
        .card h3 {
            font-size: 20px;
            font-weight: 600;
            margin-top: 24px;
            margin-bottom: 12px;
            color: #334155;
        }
        .card p {
            color: #64748b;
            font-size: 16px;
            margin-bottom: 16px;
        }
        footer {
            background: #1e293b;
            color: white;
            padding: 48px 24px;
            text-align: center;
        }
    </style>
</head>
<body>
    %s
    <div class="container">
        <div class="card">
            <h2>Tentang Dinas Pendidikan DKI Jakarta</h2>
            <p>Dinas Pendidikan Provinsi DKI Jakarta adalah instansi pemerintah yang bertanggung jawab dalam mengelola dan mengembangkan sistem pendidikan di wilayah DKI Jakarta.</p>
            
            <h3>Sejarah</h3>
            <p>Dinas Pendidikan DKI Jakarta telah berkomitmen untuk meningkatkan kualitas pendidikan di Jakarta sejak didirikan. Kami terus berinovasi untuk memberikan layanan pendidikan terbaik bagi seluruh warga Jakarta.</p>
            
            <h3>Visi</h3>
            <p>Menjadi pusat pendidikan unggul yang menghasilkan sumber daya manusia berkualitas dan berkarakter untuk kemajuan DKI Jakarta.</p>
            
            <h3>Misi</h3>
            <ul style="color: #64748b; font-size: 16px; margin-left: 24px;">
                <li>Meningkatkan akses dan kualitas pendidikan di seluruh jenjang</li>
                <li>Mengembangkan sistem pendidikan yang inovatif dan adaptif</li>
                <li>Membangun karakter dan kompetensi peserta didik</li>
                <li>Meningkatkan profesionalisme tenaga pendidik</li>
                <li>Mengoptimalkan pemanfaatan teknologi dalam pendidikan</li>
            </ul>
            
            <h3>Kontak</h3>
            <p><strong>Alamat:</strong> Jl. Jenderal Gatot Subroto, Jakarta Selatan</p>
            <p><strong>Email:</strong> info@pendidikan.jakarta.go.id</p>
            <p><strong>Telepon:</strong> (021) 1234-5678</p>
        </div>
    </div>
    <footer>
        <p>&copy; 2025 Dinas Pendidikan Provinsi DKI Jakarta. All rights reserved.</p>
    </footer>
</body>
</html>`, header)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func renderServicesPage(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)
	header := getCommonHeader(user)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Layanan - Dinas Pendidikan DKI Jakarta</title>
    <meta name="description" content="Layanan yang tersedia di Dinas Pendidikan DKI Jakarta">
    <link rel="icon" type="image/png" href="/logo.png">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f8fafc;
            color: #1e293b;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 48px 24px;
        }
        .section-title {
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 32px;
            color: #1e293b;
        }
        .card-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 24px;
        }
        .card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .card:hover {
            transform: translateY(-4px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.15);
        }
        .card h3 {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 12px;
            color: #6366f1;
        }
        .card p {
            color: #64748b;
            font-size: 15px;
            margin-bottom: 16px;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            background: #e0e7ff;
            color: #6366f1;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 500;
            margin-bottom: 12px;
        }
        footer {
            background: #1e293b;
            color: white;
            padding: 48px 24px;
            text-align: center;
        }
    </style>
</head>
<body>
    %s
    <div class="container">
        <h1 class="section-title">Layanan yang Tersedia</h1>
        <div class="card-grid">
            <div class="card">
                <span class="badge">Pendidikan Dasar</span>
                <h3>Informasi Sekolah Dasar</h3>
                <p>Akses informasi lengkap tentang sekolah dasar di DKI Jakarta, termasuk data siswa, guru, dan fasilitas.</p>
            </div>
            <div class="card">
                <span class="badge">Pendidikan Menengah</span>
                <h3>Informasi SMP & SMA</h3>
                <p>Informasi tentang sekolah menengah pertama dan atas, kurikulum, dan program unggulan.</p>
            </div>
            <div class="card">
                <span class="badge">Pendidikan Khusus</span>
                <h3>Program Khusus</h3>
                <p>Layanan untuk pendidikan inklusif, program khusus, dan bimbingan konseling.</p>
            </div>
            <div class="card">
                <span class="badge">Pelatihan</span>
                <h3>Pelatihan Guru</h3>
                <p>Program pelatihan dan pengembangan kompetensi untuk tenaga pendidik.</p>
            </div>
            <div class="card">
                <span class="badge">Beasiswa</span>
                <h3>Program Beasiswa</h3>
                <p>Informasi tentang program beasiswa untuk siswa berprestasi dan kurang mampu.</p>
            </div>
            <div class="card">
                <span class="badge">Digital</span>
                <h3>Layanan Digital</h3>
                <p>Akses ke platform pembelajaran digital dan sistem informasi sekolah.</p>
            </div>
        </div>
    </div>
    <footer>
        <p>&copy; 2025 Dinas Pendidikan Provinsi DKI Jakarta. All rights reserved.</p>
    </footer>
    <script>
        // Update header dengan data dari sessionStorage SSO jika tersedia
        (function() {
            try {
                const ssoUserInfoStr = sessionStorage.getItem('sso_user_info');
                if (ssoUserInfoStr) {
                    const ssoUserInfo = JSON.parse(ssoUserInfoStr);
                    const userNameSpan = document.getElementById('headerUserName');
                    if (userNameSpan && ssoUserInfo.name) {
                        userNameSpan.textContent = ssoUserInfo.name;
                        console.log('✅ Updated header name from SSO:', ssoUserInfo.name);
                    }
                }
            } catch (error) {
                console.error('Error updating header from SSO:', error);
            }
        })();
    </script>
</body>
</html>`, header)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func renderNewsPage(w http.ResponseWriter, r *http.Request) {
	user, _ := getCurrentUser(r)
	header := getCommonHeader(user)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Berita - Dinas Pendidikan DKI Jakarta</title>
    <meta name="description" content="Berita dan pengumuman terbaru dari Dinas Pendidikan DKI Jakarta">
    <link rel="icon" type="image/png" href="/logo.png">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f8fafc;
            color: #1e293b;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 48px 24px;
        }
        .section-title {
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 32px;
            color: #1e293b;
        }
        .card-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 24px;
        }
        .card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .card:hover {
            transform: translateY(-4px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.15);
        }
        .card h3 {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 12px;
            color: #1e293b;
        }
        .card p {
            color: #64748b;
            font-size: 15px;
            margin-bottom: 12px;
        }
        .card-meta {
            font-size: 13px;
            color: #94a3b8;
            margin-top: 16px;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            background: #e0e7ff;
            color: #6366f1;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 500;
            margin-bottom: 12px;
        }
        footer {
            background: #1e293b;
            color: white;
            padding: 48px 24px;
            text-align: center;
        }
    </style>
</head>
<body>
    %s
    <div class="container">
        <h1 class="section-title">Berita & Pengumuman</h1>
        <div id="newsContainer" class="card-grid">
            <div class="card">
                <p>Memuat berita...</p>
            </div>
        </div>
    </div>
    <footer>
        <p>&copy; 2025 Dinas Pendidikan Provinsi DKI Jakarta. All rights reserved.</p>
    </footer>
    <script>
        // Update header dengan data dari sessionStorage SSO jika tersedia
        (function() {
            try {
                const ssoUserInfoStr = sessionStorage.getItem('sso_user_info');
                if (ssoUserInfoStr) {
                    const ssoUserInfo = JSON.parse(ssoUserInfoStr);
                    const userNameSpan = document.getElementById('headerUserName');
                    if (userNameSpan && ssoUserInfo.name) {
                        userNameSpan.textContent = ssoUserInfo.name;
                        console.log('✅ Updated header name from SSO:', ssoUserInfo.name);
                    }
                }
            } catch (error) {
                console.error('Error updating header from SSO:', error);
            }
        })();
        
        async function loadNews() {
            try {
                const res = await fetch('/api/news');
                const data = await res.json();
                const container = document.getElementById('newsContainer');
                if (data.success && data.data && data.data.length > 0) {
                    container.innerHTML = data.data.map(item => {
                        const date = item.created_at ? new Date(item.created_at).toLocaleDateString('id-ID') : '';
                        return '<div class="card"><span class="badge">' + (item.kategori || 'Berita') + '</span><h3>' + (item.judul || 'Judul Berita') + '</h3><p>' + ((item.konten || '').substring(0, 150)) + '...</p><div class="card-meta">' + date + '</div></div>';
                    }).join('');
                } else {
                    container.innerHTML = '<div class="card"><p>Belum ada berita</p></div>';
                }
            } catch (error) {
                console.error('Error loading news:', error);
                document.getElementById('newsContainer').innerHTML = '<div class="card"><p>Gagal memuat berita</p></div>';
            }
        }
        loadNews();
    </script>
</body>
</html>`, header)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// renderProfilePage telah dihapus - Digantikan oleh renderProfilePageNew di profile_handler.go

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8070"
	}

	http.HandleFunc("/", Handler)
	http.HandleFunc("/login", LoginPageHandler)
	http.HandleFunc("/dashboard", DashboardHandler)
	http.HandleFunc("/profile", ProfileHandler)
	http.HandleFunc("/logout", LogoutHandler)
	http.HandleFunc("/info-dinas", InfoDinasHandler)
	http.HandleFunc("/sso/authorize", SSOAuthorizeHandler)
	http.HandleFunc("/sso/callback", SSOCallbackHandler)
	http.HandleFunc("/sso/login", SSOLoginHandler) // New SSO Login Route
	http.HandleFunc("/sso/logout-listener", FrontChannelLogoutHandler) // Special handler for Keycloak

	log.Printf("🚀 Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
