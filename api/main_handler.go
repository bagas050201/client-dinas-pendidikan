package main

import (
	"client-dinas-pendidikan/pkg/helpers"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

//go:embed logo.png
var LogoData []byte

//go:embed static/sso-handler.js
var SSOHandlerJS []byte

var LogoBase64 string

func init() {
	LogoBase64 = base64.StdEncoding.EncodeToString(LogoData)
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

	case "/login-manual", "/sso/login":
		// Endpoint untuk login manual (jika silent check gagal)
		// Redirect ke Keycloak TANPA prompt=none (tampilkan form login)
		log.Printf("👤 Performing Manual Login (Standard SSO)...")
		redirectToKeycloakLogin(w, r, false) // false = tanpa prompt=none

	case "/login":
		LoginPageHandler(w, r)
		return
	case "/dashboard":
		DashboardHandler(w, r)
		return

	case "/logout":
		LogoutHandler(w, r)
		return
	case "/sso/authorize":
		SSOAuthorizeHandler(w, r)
		return
	case "/oauth/callback", "/callback":
		handleOAuthCallback(w, r)
		return
	case "/auth/check":
		handleAuthCheck(w, r)
		return
	case "/auth/validate":
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
	case (path == "/oauth/callback" || path == "/api/callback") && method == "GET":
		HandleOAuthCallback(w, r)
	case path == "/api/users/sso-login" && method == "POST":
		handleSSOUserLoginAPI(w, r)
	case path == "/api/auth/sso-login" && method == "POST":
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
	// Cek apakah user sudah login (cek access token atau session)
	// Cek apakah ada error parameter (khususnya login_required)
	errorParam := r.URL.Query().Get("error")

	// Jika error adalah login_required, kita harus paksa clear session dan JANGAN redirect ke dashboard
	// Ini untuk memutus infinite loop jika browser masih mengirim cookie lama
	if errorParam == "login_required" || errorParam == "interaction_required" {
		log.Printf("ℹ️ Forced logout due to %s, clearing cookies and showing login form", errorParam)
		helpers.ClearCookie(w, r, "client_dinas_session")
		helpers.ClearCookie(w, r, "sso_access_token")
		helpers.ClearCookie(w, r, "sso_id_token")
		helpers.ClearCookie(w, r, "sso_token_expires")
		helpers.ClearCookie(w, r, "session_id")
		// Lanjut ke renderLoginPage di bawah, jangan return
	} else if isAuthenticated(r) {
		// Jika tidak ada error login_required, baru cek apakah user sudah login
		log.Printf("✅ User already logged in, redirecting to dashboard")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// Cek apakah user sudah login (cek access token atau session)
	// PENTING: Jangan redirect jika ada error parameter (untuk menghindari loop)
	errorParam = r.URL.Query().Get("error")
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
	renderLoginPage(w, errorMsg)
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

// getUserBySSOIdentifier mengambil data user dari PostgreSQL berdasarkan ID, NRK, atau NIK
func getUserBySSOIdentifier(identifier string) (map[string]interface{}, error) {
	// Ambil data user dari PostgreSQL database
	log.Printf("🔍 getUserBySSOIdentifier: getting user data for identifier: %s", identifier)

	db, err := GetDB()
	if err != nil {
		log.Printf("❌ getUserBySSOIdentifier: failed to connect to PostgreSQL: %v", err)
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	// Do NOT close the DB connection here as it is a singleton pool
	// defer db.Close()

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

	// Render dashboard
	renderDashboardPage(w, user, ssoClaims)
}

// renderDashboardPage menampilkan halaman dashboard

// renderDashboardPage generates the HTML for the dashboard page.
func renderDashboardPage(w http.ResponseWriter, user map[string]interface{}, ssoClaims map[string]interface{}) {
	logoBase64 := LogoBase64

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

	data := DashboardData{
		LogoBase64:       logoBase64,
		AvatarInitial:    avatarInitial,
		UserName:         userName,
		UserEmail:        userEmail,
		NRK:              nrk,
		UnitKerja:        unitKerja,
		RoleBadgeClass:   roleBadgeClass,
		UserRole:         userRole,
		StatusBadgeClass: statusBadgeClass,
		UserStatus:       userStatus,
		JSONPayload:      jsonPayload,
		WelcomeTitle:     userName,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := RenderDashboard(w, data); err != nil {
		log.Printf("❌ Error rendering dashboard: %v", err)
	}
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

// (Structs moved to models.go)

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

// (Function removed - use ExchangeCodeForToken from keycloak_helpers.go)

// getUserInfoFromSSO mengambil informasi user dari SSO menggunakan access token
// (Function removed - use ParseIDToken from keycloak_helpers.go)

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

// findOrCreateUser mencari user di database (Read Only dari JAKEDU)
// Karena JAKEDU adalah read-only, tidak bisa membuat user baru
// Fungsi ini hanya mencari user yang sudah ada berdasarkan email
func findOrCreateUser(userInfo *UserInfo) (interface{}, error) {
	log.Printf("🔍 findOrCreateUser: searching for user with email: %s", userInfo.Email)

	db, err := GetDB()
	if err != nil {
		return "", fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	// Do NOT close the DB connection here as it is a singleton pool
	// defer db.Close()

	// Query user from JAKEDU database (account.za_users)
	query := `
		SELECT id, email, nickname, fullname 
		FROM account.za_users 
		WHERE email = $1 OR nickname = $1
		LIMIT 1
	`

	var userID, email, nickname, fullname sql.NullString
	err = db.QueryRow(query, userInfo.Email).Scan(&userID, &email, &nickname, &fullname)

	if err != nil {
		if err == sql.ErrNoRows {
			// User tidak ditemukan di database, gunakan SSO sub sebagai identifier
			log.Printf("ℹ️ User not found in JAKEDU, using SSO sub as identifier: %s", userInfo.Sub)
			return userInfo.Sub, nil
		}
		log.Printf("❌ findOrCreateUser: error querying user: %v", err)
		return userInfo.Sub, nil
	}

	log.Printf("✅ findOrCreateUser: found user in JAKEDU: %s (%s)", fullname.String, email.String)
	return userID.String, nil
}

// SSOCallbackHandler menangani callback dari SSO setelah user login
// Flow:
// 1. Terima authorization code dari query parameter
// 2. Validasi state parameter
// 3. Exchange code ke access token
// 4. Ambil user info dari SSO
// 5. Buat session user di client
// 6. Redirect ke dashboard
// (Function removed - use HandleOAuthCallback from keycloak_helpers.go)

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
		db, err := GetDB()
		if err == nil {
			_, err = db.Exec("DELETE FROM sesi_login WHERE id_sesi = $1", sessionID)
			if err != nil {
				log.Printf("WARNING: Error clearing session: %v", err)
			} else {
				log.Printf("✅ Session revoked from database: %s", sessionID)
			}
			// Do NOT close the DB connection here as it is a singleton pool
			// db.Close()
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
		db, err := GetDB()
		if err == nil {
			db.Exec("DELETE FROM sesi_login WHERE id_sesi = $1", sessionID)
			// Do NOT close the DB connection here as it is a singleton pool
			// db.Close()
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
	logoBase64 := LogoBase64
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

// createSessionTableIfNotExists creates the sesi_login table if it doesn't exist
func createSessionTableIfNotExists() error {
	db, err := GetDB()
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	// Do NOT close the DB connection here as it is a singleton pool
	// defer db.Close()

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
	db, err := GetDB()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	// Do NOT close the DB connection here as it is a singleton pool
	// defer db.Close()

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

// createSessionFromIdentifier creates a local session for the user identifier
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
	db, err := GetDB()
	if err != nil {
		log.Printf("ERROR connecting to PostgreSQL: %v", err)
		return "", false
	}
	// Do NOT close the DB connection here as it is a singleton pool
	// defer db.Close()

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

	// Validate session (using PostgreSQL)
	userID, ok, err := validateSession(sessionID)
	if !ok || err != nil || userID == "" {
		return nil, fmt.Errorf("session tidak valid")
	}

	// Ambil data user dari database menggunakan getUserBySSOIdentifier (PostgreSQL)
	user, err := getUserBySSOIdentifier(userID)
	if err != nil {
		return nil, fmt.Errorf("gagal mengambil user: %v", err)
	}

	return user, nil
}

// API Handlers
// handleLoginAPI telah dihapus sepenuhnya

// handleRegisterAPI telah dihapus - Registrasi dilakukan melalui SSO Keycloak

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

	// Check if user exists by email in PostgreSQL (JAKEDU)
	log.Printf("🔍 Checking JAKEDU database for user: %s", req.Email)
	
	db, err := GetDB()
	if err != nil {
		log.Printf("❌ Failed to connect to PostgreSQL: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Database connection error")
		return
	}
	// Do NOT close the DB connection here as it is a singleton pool
	// defer db.Close()

	query := `
		SELECT id, email, fullname, role_id 
		FROM account.za_users 
		WHERE email = $1 OR nickname = $1
		LIMIT 1
	`

	var user struct {
		ID       string
		Email    sql.NullString
		Fullname sql.NullString
		RoleID   sql.NullString
	}

	err = db.QueryRow(query, req.Email).Scan(&user.ID, &user.Email, &user.Fullname, &user.RoleID)
	
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("⚠️ User not found in JAKEDU: %s", req.Email)
			helpers.WriteError(w, http.StatusNotFound, "User tidak ditemukan di database JAKEDU")
			return
		}
		log.Printf("❌ Error querying JAKEDU: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Failed to query database")
		return
	}

	log.Printf("✅ User found in JAKEDU: %s", req.Email)

	// Return user data
	response := map[string]interface{}{
		"user": map[string]interface{}{
			"id":          user.ID,
			"email":       user.Email.String,
			"name":        user.Fullname.String,
			"role":        user.RoleID.String,
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

	// Get user by email from PostgreSQL (JAKEDU)
	log.Printf("🔍 Checking JAKEDU database for user: %s", req.Email)
	
	db, err := GetDB()
	if err != nil {
		log.Printf("❌ Failed to connect to PostgreSQL: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Database connection error")
		return
	}
	// Do NOT close the DB connection here as it is a singleton pool
	// defer db.Close()

	query := `
		SELECT id, email, fullname 
		FROM account.za_users 
		WHERE email = $1 OR nickname = $1
		LIMIT 1
	`

	var user struct {
		ID       string
		Email    sql.NullString
		Fullname sql.NullString
	}

	err = db.QueryRow(query, req.Email).Scan(&user.ID, &user.Email, &user.Fullname)
	
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("⚠️ User not found in JAKEDU: %s", req.Email)
			helpers.WriteError(w, http.StatusNotFound, "User tidak ditemukan")
			return
		}
		log.Printf("❌ Error querying JAKEDU: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Failed to query database")
		return
	}

	// Create session
	sessionID, err := createSession(user.ID, r)
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
			"id":    user.ID,
			"email": user.Email.String,
			"name":  user.Fullname.String,
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
	db, err := GetDB()
	if err != nil {
		log.Printf("❌ validateSession: failed to connect to PostgreSQL: %v", err)
		return "", false, fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	// Do NOT close the DB connection here as it is a singleton pool
	// defer db.Close()

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
	db, err := GetDB()
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	// Do NOT close the DB connection here as it is a singleton pool
	// defer db.Close()

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
	db, err := GetDB()
	if err != nil {
		return "", fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	// Do NOT close the DB connection here as it is a singleton pool
	// defer db.Close()

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
func renderLoginPage(w http.ResponseWriter, errorMsg string) {
	logoBase64 := LogoBase64
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

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8070"
	}

	http.HandleFunc("/", Handler)

	log.Printf("🚀 Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
