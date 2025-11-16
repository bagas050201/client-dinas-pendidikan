package api

import (
	"bytes"
	"client-dinas-pendidikan/api/session"
	"client-dinas-pendidikan/pkg/helpers"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
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
	"golang.org/x/crypto/bcrypt"
)

//go:embed logo.png
var LogoData []byte

// getSupabaseURL returns SUPABASE_URL from environment
func getSupabaseURL() string {
	return os.Getenv("SUPABASE_URL")
}

// getSupabaseKey returns SUPABASE_KEY from environment
func getSupabaseKey() string {
	return os.Getenv("SUPABASE_KEY")
}

// getJWTPrivateKey returns JWT_PRIVATE_KEY from environment
func getJWTPrivateKey() string {
	return os.Getenv("JWT_PRIVATE_KEY")
}

// getJWTPublicKey returns JWT_PUBLIC_KEY from environment
func getJWTPublicKey() string {
	return os.Getenv("JWT_PUBLIC_KEY")
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

	// API routes
	if strings.HasPrefix(path, "/api/") {
		handleAPI(w, r)
		return
	}

	// Static pages - menggunakan handler baru yang modular
	switch path {
	case "/", "/home":
		// Check if authenticated
		// PENTING: Jangan auto-login dari SSO tanpa explicit consent!
		// User harus explicitly klik "Login dengan SSO" dan authorize aplikasi
		// Ini sesuai dengan OAuth 2.0 Authorization Code Flow best practices
		if !isAuthenticated(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		renderHomePage(w, r)
	case "/login":
		// Gunakan handler baru untuk login
		// Support kedua metode: SSO dan direct login
		if r.Method == "POST" {
			LoginPostHandler(w, r)
		} else {
			LoginPageHandler(w, r)
		}
		return
	case "/dashboard":
		// Gunakan handler baru untuk dashboard
		DashboardHandler(w, r)
		return
	case "/info-dinas":
		// Gunakan handler baru untuk informasi dinas
		InfoDinasHandler(w, r)
		return
	case "/register":
		if isAuthenticated(r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		renderRegisterPage(w, "")
	case "/about":
		if !isAuthenticated(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		renderAboutPage(w, r)
	case "/services":
		if !isAuthenticated(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		renderServicesPage(w, r)
	case "/news":
		if !isAuthenticated(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		renderNewsPage(w, r)
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
	case "/callback":
		// Handler untuk callback dari SSO setelah login
		SSOCallbackHandler(w, r)
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
	case path == "/api/callback" && method == "GET":
		// Handler untuk callback dari SSO (support /api/callback untuk kompatibilitas)
		SSOCallbackHandler(w, r)
	case path == "/api/login" && method == "POST":
		// Gunakan handler baru untuk login API (kompatibilitas dengan AJAX)
		LoginPostHandler(w, r)
	case path == "/api/register" && method == "POST":
		handleRegisterAPI(w, r)
	case path == "/api/logout" && method == "POST":
		handleLogoutAPI(w, r)
	case path == "/api/profile" && method == "GET":
		handleGetProfileAPI(w, r)
	case path == "/api/profile" && method == "PUT":
		handleUpdateProfileAPI(w, r)
	case path == "/api/password" && method == "PUT":
		handleChangePasswordAPI(w, r)
	case path == "/api/news" && method == "GET":
		handleGetNewsAPI(w, r)
	case path == "/api/announcements" && method == "GET":
		handleGetAnnouncementsAPI(w, r)
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
	// PENTING: Jangan redirect jika ada error parameter (untuk menghindari loop)
	errorParam := r.URL.Query().Get("error")

	// Jika tidak ada error, cek apakah user sudah login
	if errorParam == "" {
		accessToken, _ := helpers.GetCookie(r, "sso_access_token")
		// PENTING: Hanya gunakan cookie client_dinas_session, JANGAN gunakan sso_admin_session dari SSO server
		sessionID, _ := helpers.GetCookie(r, "client_dinas_session")
		// Fallback ke session_id untuk backward compatibility (cookie lama dari direct login)
		if sessionID == "" {
			sessionID, _ = helpers.GetCookie(r, "session_id")
		}

		// Cek access token expiration jika ada
		if accessToken != "" {
			tokenExpiresStr, _ := helpers.GetCookie(r, "sso_token_expires")
			if tokenExpiresStr != "" {
				if tokenExpires, err := strconv.ParseInt(tokenExpiresStr, 10, 64); err == nil {
					if time.Now().Unix() <= tokenExpires {
						// Access token valid, redirect
						next := r.URL.Query().Get("next")
						if next == "" {
							next = "/dashboard"
						}
						log.Printf("✅ Access token valid, redirect ke: %s", next)
						http.Redirect(w, r, next, http.StatusSeeOther)
						return
					}
				}
			}
		}

		// Cek session jika ada
		if sessionID != "" {
			userID, ok, err := session.ValidateSession(sessionID)
			if ok && err == nil && userID != "" {
				// Session valid, redirect ke dashboard
				next := r.URL.Query().Get("next")
				if next == "" {
					next = "/dashboard"
				}
				log.Printf("✅ Session valid, redirect ke: %s", next)
				http.Redirect(w, r, next, http.StatusSeeOther)
				return
			}
		}
	}

	// Ambil error message dari query parameter (untuk error dari SSO callback)
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
		case "token_expired":
			errorMsg = "Token sudah expired. Silakan login lagi."
		case "no_token":
			errorMsg = "Tidak ada access token. Silakan login."
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

// LoginPostHandler menangani POST request untuk login
// Flow:
// 1. Parse email dan password dari request
// 2. Validasi input
// 3. Cek user di Supabase (tabel pengguna)
// 4. Verifikasi password (bcrypt atau plain text fallback)
// 5. Cek status aktif user
// 6. Buat session di database (tabel sesi_login)
// 7. Set cookie sso_admin_session
// 8. Redirect ke /dashboard (atau next param) atau return JSON jika Accept: application/json
func LoginPostHandler(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	// Cek Content-Type untuk menentukan cara parse
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		// Parse dari JSON
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("ERROR parsing JSON: %v", err)
			helpers.WriteError(w, http.StatusBadRequest, "Invalid request format")
			return
		}
	} else {
		// Parse dari form data
		if err := r.ParseForm(); err != nil {
			log.Printf("ERROR parsing form: %v", err)
			helpers.WriteError(w, http.StatusBadRequest, "Invalid request format")
			return
		}
		req.Email = r.FormValue("email")
		req.Password = r.FormValue("password")
	}

	// Validasi input
	if !helpers.ValidateEmail(req.Email) {
		log.Printf("ERROR: Email tidak valid: %s", req.Email)
		helpers.WriteError(w, http.StatusBadRequest, "Email tidak valid")
		return
	}

	if len(req.Password) < 6 {
		log.Printf("ERROR: Password terlalu pendek")
		helpers.WriteError(w, http.StatusBadRequest, "Password minimal 6 karakter")
		return
	}

	// Validasi koneksi Supabase
	supabaseURL := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_KEY")
	if supabaseURL == "" || supabaseKey == "" {
		log.Println("ERROR: SUPABASE_URL atau SUPABASE_KEY tidak di-set")
		helpers.WriteError(w, http.StatusInternalServerError, "Konfigurasi server tidak lengkap")
		return
	}

	// Ambil user dari Supabase
	emailEncoded := url.QueryEscape(req.Email)
	apiURL := fmt.Sprintf("%s/rest/v1/pengguna?email=eq.%s&select=*", supabaseURL, emailEncoded)

	httpReq, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		log.Printf("ERROR creating request: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Terjadi kesalahan")
		return
	}

	httpReq.Header.Set("apikey", supabaseKey)
	httpReq.Header.Set("Authorization", "Bearer "+supabaseKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ERROR calling Supabase: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal terhubung ke database")
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR Supabase response: Status %d, Body: %s", resp.StatusCode, string(bodyBytes))
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal mengambil data pengguna")
		return
	}

	var users []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &users); err != nil {
		log.Printf("ERROR parsing response: %v, Body: %s", err, string(bodyBytes))
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal memproses data")
		return
	}

	if len(users) == 0 {
		log.Printf("ERROR: User tidak ditemukan: %s", req.Email)
		helpers.WriteError(w, http.StatusUnauthorized, "Email atau password salah")
		return
	}

	user := users[0]

	// Verifikasi password
	var passwordMatch bool
	if passwordHash, ok := user["password"].(string); ok && passwordHash != "" {
		// Cek dengan bcrypt
		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err == nil {
			passwordMatch = true
		}
	} else {
		// Fallback: cek password plain text (untuk backward compatibility)
		if password, ok := user["password"].(string); ok {
			if password == req.Password {
				passwordMatch = true
			}
		}
	}

	if !passwordMatch {
		log.Printf("ERROR: Password salah untuk user: %s", req.Email)
		helpers.WriteError(w, http.StatusUnauthorized, "Email atau password salah")
		return
	}

	// Cek status aktif
	if active, ok := user["aktif"].(bool); !ok || !active {
		log.Printf("ERROR: User tidak aktif: %s", req.Email)
		helpers.WriteError(w, http.StatusForbidden, "Akun tidak aktif")
		return
	}

	// Buat session di database
	// Schema Supabase: id_pengguna adalah primary key, bukan id
	userID, ok := user["id_pengguna"]
	if !ok {
		// Fallback: coba id jika id_pengguna tidak ada (untuk backward compatibility)
		userID, ok = user["id"]
		if !ok {
			log.Printf("ERROR: User tidak memiliki kolom id_pengguna atau id. User keys: %v", getMapKeys(user))
			helpers.WriteError(w, http.StatusInternalServerError, "Data user tidak valid")
			return
		}
	}

	// Log untuk debugging
	log.Printf("🔍 Creating session for userID: %v (type: %T)", userID, userID)

	sessionID, err := session.CreateSession(userID, r)
	if err != nil {
		log.Printf("ERROR creating session: %v", err)
		// Log error detail untuk debugging
		log.Printf("ERROR detail - userID: %v, userID type: %T", userID, userID)
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal membuat sesi: "+err.Error())
		return
	}

	// Set cookie dengan nama yang berbeda dari SSO server
	// PENTING: Gunakan cookie name yang berbeda untuk mencegah shared cookie
	// SSO server menggunakan "sso_admin_session", client website menggunakan "client_dinas_session"
	helpers.SetCookie(w, "client_dinas_session", sessionID, 86400) // 24 jam

	// Log untuk debugging
	log.Printf("✅ Login berhasil: %s, session: %s", req.Email, sessionID)

	// Cek apakah request meminta JSON response
	acceptHeader := r.Header.Get("Accept")
	if strings.Contains(acceptHeader, "application/json") {
		// Return JSON untuk AJAX request
		next := r.URL.Query().Get("next")
		if next == "" {
			next = "/dashboard"
		}
		helpers.WriteJSON(w, http.StatusOK, map[string]interface{}{
			"success":    true,
			"message":    "Login berhasil",
			"session_id": sessionID,
			"redirect":   next,
		})
		return
	}

	// Redirect ke dashboard atau next param
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/dashboard"
	}

	// PENTING: Redirect dengan status 303 (See Other) untuk POST request
	// Jangan tulis response body sebelum redirect
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// RequireAuth adalah middleware untuk protect routes
// Cek apakah user memiliki access token ATAU session yang valid
// Support kedua metode: SSO (access token) dan direct login (session)
func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Cek 1: Access token dari SSO (prioritas pertama)
		accessToken, err := helpers.GetCookie(r, "sso_access_token")
		if err == nil && accessToken != "" {
			// Cek token expiration
			tokenExpiresStr, err := helpers.GetCookie(r, "sso_token_expires")
			if err == nil && tokenExpiresStr != "" {
				tokenExpires, err := strconv.ParseInt(tokenExpiresStr, 10, 64)
				if err == nil && time.Now().Unix() <= tokenExpires {
					// Access token valid, lanjutkan
					log.Printf("✅ Access token valid")
					next(w, r)
					return
				}
			}
			// Token expired atau invalid, clear cookies
			log.Printf("WARNING: Access token expired or invalid, clearing cookies")
			helpers.ClearCookie(w, "sso_access_token")
			helpers.ClearCookie(w, "sso_token_expires")
		}

		// Cek 2: Session dari direct login (fallback)
		// PENTING: Hanya gunakan cookie client_dinas_session, JANGAN gunakan sso_admin_session dari SSO server
		sessionID, err := helpers.GetCookie(r, "client_dinas_session")
		if err != nil {
			// Fallback ke session_id untuk backward compatibility (cookie lama dari direct login)
			sessionID, err = helpers.GetCookie(r, "session_id")
		}
		if err == nil && sessionID != "" {
			userID, ok, err := session.ValidateSession(sessionID)
			if ok && err == nil && userID != "" {
				// Session valid, lanjutkan
				log.Printf("✅ Session valid for user: %s", userID)
				next(w, r)
				return
			}
			// Session invalid, clear cookie
			if !ok {
				log.Printf("WARNING: Session invalid, clearing cookie")
				helpers.ClearCookie(w, "client_dinas_session")
				helpers.ClearCookie(w, "session_id") // Clear juga untuk backward compatibility
			}
		}

		// Tidak ada token atau session yang valid, redirect ke login
		// JANGAN tambahkan error=no_token untuk menghindari redirect loop
		// Jika sudah ada error di URL, jangan tambahkan lagi
		nextParam := r.URL.Query().Get("next")
		if nextParam == "" {
			nextParam = r.URL.Path
		}
		redirectURL := "/login"
		if nextParam != "" && nextParam != "/login" {
			redirectURL = "/login?next=" + helpers.SanitizeInput(nextParam)
		}
		log.Printf("WARNING: No valid auth found, redirecting to: %s", redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
	}
}

// DashboardHandler menampilkan halaman dashboard
// Protected route: menggunakan RequireAuth middleware untuk cek access token
func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Cek access token dengan middleware
	RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		// Token valid, lanjutkan render dashboard
		renderDashboardWithToken(w, r)
	})(w, r)
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
		// Validasi session jika ada
		userID, ok, _ = session.ValidateSession(sessionID)
	}

	// Ambil data user jika session ada
	var user map[string]interface{}
	if ok && userID != "" {
		user, err = getUserByIDForDashboard(userID)
		if err != nil {
			log.Printf("WARNING: Error getting user: %v", err)
			// Lanjutkan dengan user kosong
			user = make(map[string]interface{})
		}
	} else {
		// Jika tidak ada session, gunakan user kosong
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
	renderDashboardPage(w, user, counts)
}

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

// getUserByIDForDashboard mengambil data user dari Supabase berdasarkan ID
func getUserByIDForDashboard(userID string) (map[string]interface{}, error) {
	return getUserByID(userID)
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

// renderDashboardPage menampilkan halaman dashboard
func renderDashboardPage(w http.ResponseWriter, user map[string]interface{}, counts map[string]int) {
	logoBase64 := base64.StdEncoding.EncodeToString(LogoData)
	userName := "User"
	if name, ok := user["nama_lengkap"].(string); ok && name != "" {
		userName = name
	} else if email, ok := user["email"].(string); ok {
		userName = email
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
            padding: 8px 12px;
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
            background: white;
            border-radius: 12px;
            padding: 32px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .welcome-title {
            font-size: 28px;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 8px;
        }
        .welcome-subtitle {
            color: #64748b;
            font-size: 16px;
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
        @media (max-width: 768px) {
            .container { padding: 16px; }
            .welcome-section { padding: 24px; }
            .stats-grid { grid-template-columns: 1fr; }
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
                <span>%s</span>
            </div>
            <a href="/logout" class="btn-logout">Logout</a>
        </div>
    </nav>
    <div class="container">
        <div class="welcome-section">
            <h1 class="welcome-title">Selamat Datang, %s!</h1>
            <p class="welcome-subtitle">Dashboard Sistem Informasi Dinas Pendidikan</p>
        </div>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Pengguna</div>
                <div class="stat-value">%d</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Aplikasi Terhubung</div>
                <div class="stat-value">%d</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Sessions Aktif</div>
                <div class="stat-value">%d</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Tokens</div>
                <div class="stat-value">%d</div>
            </div>
        </div>
        <div class="actions-grid">
            <a href="/info-dinas" class="action-card">
                <div class="action-title">📋 Informasi Dinas</div>
                <div class="action-desc">Lihat informasi lengkap tentang Dinas Pendidikan DKI Jakarta</div>
            </a>
            <a href="/profile" class="action-card">
                <div class="action-title">👤 Profil Saya</div>
                <div class="action-desc">Kelola informasi profil dan pengaturan akun</div>
            </a>
            <a href="/news" class="action-card">
                <div class="action-title">📰 Berita & Pengumuman</div>
                <div class="action-desc">Baca berita dan pengumuman terbaru</div>
            </a>
            <a href="/services" class="action-card">
                <div class="action-title">🛠️ Layanan</div>
                <div class="action-desc">Akses berbagai layanan yang tersedia</div>
            </a>
        </div>
    </div>
</body>
</html>`, logoBase64, string([]rune(userName)[0]), userName, userName, counts["pengguna"], counts["aplikasi"], counts["sessions"], counts["tokens"])

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
	_, ok, err := session.ValidateSession(sessionID)
	if !ok || err != nil {
		log.Printf("WARNING: Invalid session: %v, error: %v", ok, err)
		helpers.ClearCookie(w, "client_dinas_session")
		helpers.ClearCookie(w, "session_id") // Clear juga untuk backward compatibility
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

	// Generate HTML untuk aplikasi terhubung
	appsHTML := ""
	if len(apps) > 0 {
		for _, app := range apps {
			nama := fmt.Sprintf("%v", app["nama"])
			deskripsi := fmt.Sprintf("%v", app["deskripsi"])
			link := fmt.Sprintf("%v", app["link_akses"])
			if link == "" {
				link = "#"
			}
			appsHTML += fmt.Sprintf(`
            <div class="app-card">
                <h3>%s</h3>
                <p>%s</p>
                <a href="%s" class="app-link" target="_blank">Akses Aplikasi →</a>
            </div>`, nama, deskripsi, link)
		}
	} else {
		// Demo apps jika tidak ada data
		appsHTML = `
            <div class="app-card">
                <h3>Sistem Informasi Akademik</h3>
                <p>Platform untuk mengelola data akademik siswa dan guru</p>
                <a href="#" class="app-link">Akses Aplikasi →</a>
            </div>
            <div class="app-card">
                <h3>Portal PPDB Online</h3>
                <p>Sistem pendaftaran peserta didik baru secara online</p>
                <a href="#" class="app-link">Akses Aplikasi →</a>
            </div>
            <div class="app-card">
                <h3>E-Learning Platform</h3>
                <p>Platform pembelajaran daring untuk siswa dan guru</p>
                <a href="#" class="app-link">Akses Aplikasi →</a>
            </div>`
	}

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
            <h2 class="section-title">Aplikasi Terhubung</h2>
            <div class="apps-grid">
                %s
            </div>
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
</html>`, logoBase64, appsHTML, schoolsHTML)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

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
	tokenURL := fmt.Sprintf("%s/api/token", config.SSOServerURL)
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
			helpers.ClearCookie(w, "sso_state")
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
				sessionID, err := session.CreateSession(userID, r)
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

// ProfileHandler menampilkan dan mengelola halaman profil user
// Protected route: hanya bisa diakses oleh user yang sudah login
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Cek session (gunakan cookie name yang berbeda dari SSO server)
	// PENTING: Hanya gunakan cookie client_dinas_session, JANGAN gunakan sso_admin_session dari SSO server
	sessionID, err := helpers.GetCookie(r, "client_dinas_session")
	if err != nil {
		// Fallback ke session_id untuk backward compatibility (cookie lama dari direct login)
		sessionID, err = helpers.GetCookie(r, "session_id")
	}
	if err != nil || sessionID == "" {
		log.Printf("WARNING: No session cookie found, redirecting to login")
		http.Redirect(w, r, "/login?next=/profile", http.StatusSeeOther)
		return
	}

	// Validasi session
	userID, ok, err := session.ValidateSession(sessionID)
	if !ok || err != nil {
		log.Printf("WARNING: Invalid session: %v, error: %v", ok, err)
		helpers.ClearCookie(w, "client_dinas_session")
		helpers.ClearCookie(w, "session_id") // Clear juga untuk backward compatibility
		http.Redirect(w, r, "/login?next=/profile", http.StatusSeeOther)
		return
	}

	// Handle POST untuk update profile
	if r.Method == "POST" {
		handleUpdateProfile(w, r, userID)
		return
	}

	// GET: tampilkan form profil
	user, err := getUserByID(userID)
	if err != nil {
		log.Printf("ERROR getting user: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal mengambil data user")
		return
	}

	renderProfilePageNew(w, user)
}

// handleUpdateProfile menangani update profil user
func handleUpdateProfile(w http.ResponseWriter, r *http.Request, userID string) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		helpers.WriteError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	namaLengkap := r.FormValue("nama_lengkap")
	email := r.FormValue("email")

	// Validasi
	if !helpers.ValidateEmail(email) {
		helpers.WriteError(w, http.StatusBadRequest, "Email tidak valid")
		return
	}

	if len(namaLengkap) < 3 {
		helpers.WriteError(w, http.StatusBadRequest, "Nama lengkap minimal 3 karakter")
		return
	}

	// Update di Supabase
	supabaseURL := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_KEY")
	if supabaseURL == "" || supabaseKey == "" {
		helpers.WriteError(w, http.StatusInternalServerError, "Konfigurasi server tidak lengkap")
		return
	}

	updateData := map[string]interface{}{
		"nama_lengkap": namaLengkap,
		"email":        email,
	}

	updateJSON, _ := json.Marshal(updateData)
	userIDEncoded := url.QueryEscape(userID)
	// Schema: id_pengguna adalah primary key, bukan id
	apiURL := fmt.Sprintf("%s/rest/v1/pengguna?id_pengguna=eq.%s", supabaseURL, userIDEncoded)

	httpReq, err := http.NewRequest("PATCH", apiURL, bytes.NewBuffer(updateJSON))
	if err != nil {
		log.Printf("ERROR creating request: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Terjadi kesalahan")
		return
	}

	httpReq.Header.Set("apikey", supabaseKey)
	httpReq.Header.Set("Authorization", "Bearer "+supabaseKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ERROR calling Supabase: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal mengupdate profil")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("ERROR Supabase response: Status %d, Body: %s", resp.StatusCode, string(bodyBytes))
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal mengupdate profil")
		return
	}

	// Redirect kembali ke profile dengan success message
	http.Redirect(w, r, "/profile?success=1", http.StatusSeeOther)
}

// renderProfilePageNew menampilkan halaman profil (versi baru untuk handler modular)
func renderProfilePageNew(w http.ResponseWriter, user map[string]interface{}) {
	logoBase64 := base64.StdEncoding.EncodeToString(LogoData)
	namaLengkap := ""
	email := ""
	peran := ""

	if n, ok := user["nama_lengkap"].(string); ok {
		namaLengkap = n
	}
	if e, ok := user["email"].(string); ok {
		email = e
	}
	if p, ok := user["peran"].(string); ok {
		peran = p
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profil - Dinas Pendidikan DKI Jakarta</title>
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
            max-width: 800px;
            margin: 0 auto;
            padding: 24px;
        }
        .profile-card {
            background: white;
            border-radius: 12px;
            padding: 32px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .profile-header {
            margin-bottom: 32px;
        }
        .profile-title {
            font-size: 28px;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 8px;
        }
        .profile-subtitle {
            color: #64748b;
            font-size: 16px;
        }
        .form-group {
            margin-bottom: 24px;
        }
        .form-group label {
            display: block;
            color: #334155;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 8px;
        }
        .form-group input,
        .form-group select {
            width: 100%%;
            padding: 12px 16px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 15px;
            transition: all 0.2s;
            background: #f8fafc;
        }
        .form-group input:focus,
        .form-group select:focus {
            outline: none;
            border-color: #6366f1;
            background: white;
        }
        .form-group input:disabled {
            background: #e2e8f0;
            cursor: not-allowed;
        }
        .btn-primary {
            background: #6366f1;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-primary:hover {
            background: #4f46e5;
        }
        .success-message {
            background: #d1fae5;
            color: #065f46;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 24px;
            display: none;
        }
        .success-message.show {
            display: block;
        }
        @media (max-width: 768px) {
            .container { padding: 16px; }
            .profile-card { padding: 24px; }
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
            <a href="/info-dinas">Informasi</a>
            <a href="/logout">Logout</a>
        </div>
    </nav>
    <div class="container">
        <div class="profile-card">
            <div class="profile-header">
                <h1 class="profile-title">Profil Saya</h1>
                <p class="profile-subtitle">Kelola informasi profil dan pengaturan akun Anda</p>
            </div>
            <div class="success-message" id="successMsg">
                Profil berhasil diperbarui!
            </div>
            <form method="POST" action="/profile">
                <div class="form-group">
                    <label for="nama_lengkap">Nama Lengkap</label>
                    <input type="text" id="nama_lengkap" name="nama_lengkap" value="%s" required>
                </div>
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" id="email" name="email" value="%s" required>
                </div>
                <div class="form-group">
                    <label for="peran">Peran</label>
                    <input type="text" id="peran" name="peran" value="%s" disabled>
                </div>
                <button type="submit" class="btn-primary">Simpan Perubahan</button>
            </form>
            <div style="margin-top: 32px; padding-top: 32px; border-top: 1px solid #e2e8f0;">
                <h3 style="font-size: 18px; font-weight: 600; color: #1e293b; margin-bottom: 16px;">Ubah Password</h3>
                <p style="color: #64748b; margin-bottom: 16px;">Untuk mengubah password, silakan gunakan fitur "Ubah Password" di halaman profil lengkap.</p>
                <a href="/profile" style="color: #6366f1; text-decoration: none; font-weight: 500;">Buka Halaman Profil Lengkap →</a>
            </div>
        </div>
    </div>
    <script>
        // Tampilkan success message jika ada parameter success
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('success') === '1') {
            document.getElementById('successMsg').classList.add('show');
            setTimeout(() => {
                document.getElementById('successMsg').classList.remove('show');
            }, 3000);
        }
    </script>
</body>
</html>`, logoBase64, namaLengkap, email, peran)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// LogoutHandler menangani proses logout user
// Flow:
// 1. Ambil session ID dari cookie client_dinas_session
// 2. Revoke session di database (DELETE dari database)
// 3. Clear SEMUA cookie terkait auth client website
// 4. Redirect ke halaman home (/)
// PENTING: Logout di client website TIDAK logout dari SSO server (OAuth 2.0 standard)
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Ambil session ID dari cookie client website
	// PENTING: Gunakan cookie name yang berbeda dari SSO server
	sessionID, err := helpers.GetCookie(r, "client_dinas_session")
	if err == nil && sessionID != "" {
		// Revoke session di database (DELETE)
		if err := session.ClearSession(sessionID); err != nil {
			log.Printf("WARNING: Error clearing session: %v", err)
			// Lanjutkan meskipun error, tetap clear cookie
		} else {
			log.Printf("✅ Session revoked from database: %s", sessionID)
		}
	}

	// Clear SEMUA cookie terkait auth client website
	// PENTING: Hanya hapus cookie client website, TIDAK hapus cookie SSO server
	helpers.ClearCookie(w, "client_dinas_session") // Session dari client website
	helpers.ClearCookie(w, "sso_access_token")     // Access token dari SSO (OAuth 2.0)
	helpers.ClearCookie(w, "sso_token_expires")    // Token expiration
	helpers.ClearCookie(w, "sso_state")            // State untuk CSRF protection
	helpers.ClearCookie(w, "sso_code_verifier")    // PKCE verifier (jika ada)

	// Clear cookie lama untuk backward compatibility
	helpers.ClearCookie(w, "session_id")
	// PENTING: Jangan clear sso_admin_session karena itu cookie dari SSO server
	// Logout di client website tidak seharusnya logout dari SSO server (OAuth 2.0 standard)

	log.Printf("✅ All auth cookies cleared, user logged out")

	// Redirect ke home
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
	sessionID, ok := createSessionFromEmail(r, email)
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
			sessionID, ok := createSessionFromEmail(r, email)
			return ok && sessionID != ""
		}
	}

	// If not base64, try as direct email
	if helpers.ValidateEmail(token) {
		sessionID, ok := createSessionFromEmail(r, token)
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

	// Use email from SSO response
	email := ssoResponse.Email
	if email == "" && ssoResponse.User != nil {
		if e, ok := ssoResponse.User["email"].(string); ok {
			email = e
		}
	}

	if email == "" {
		log.Println("ERROR: Email not found in SSO response")
		return false
	}

	sessionID, ok := createSessionFromEmail(r, email)
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

// createSessionFromEmail gets user from database and creates local session
func createSessionFromEmail(r *http.Request, email string) (string, bool) {
	supabaseURL := getSupabaseURL()
	supabaseKey := getSupabaseKey()
	if supabaseURL == "" || supabaseKey == "" {
		log.Println("ERROR: Supabase not configured")
		return "", false
	}

	// Get user from database
	emailEncoded := url.QueryEscape(email)
	apiURL := fmt.Sprintf("%s/rest/v1/pengguna?email=eq.%s&select=*", supabaseURL, emailEncoded)

	httpReq, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		log.Printf("ERROR creating request: %v", err)
		return "", false
	}

	httpReq.Header.Set("apikey", supabaseKey)
	httpReq.Header.Set("Authorization", "Bearer "+supabaseKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ERROR calling Supabase: %v", err)
		return "", false
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR Supabase response: Status %d, Body: %s", resp.StatusCode, string(bodyBytes))
		return "", false
	}

	var users []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &users); err != nil {
		log.Printf("ERROR parsing response: %v", err)
		return "", false
	}

	if len(users) == 0 {
		log.Printf("WARNING: User with email %s not found in database", email)
		return "", false
	}

	user := users[0]

	// Check if user is active
	if active, ok := user["aktif"].(bool); !ok || !active {
		log.Printf("WARNING: User %s is not active", email)
		return "", false
	}

	// Create local session
	sessionID, err := helpers.GenerateSessionID()
	if err != nil {
		log.Printf("ERROR generating session ID: %v", err)
		return "", false
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	// Schema Supabase: id_pengguna, id_sesi, ip, user_agent, kadaluarsa
	// Schema: id_pengguna adalah primary key, bukan id
	userIDValue := user["id_pengguna"]
	if userIDValue == nil {
		userIDValue = user["id"]
	}
	sessionData := map[string]interface{}{
		"id_pengguna": userIDValue,                    // user_id → id_pengguna
		"id_sesi":     sessionID,                      // session_id → id_sesi
		"ip":          getIPAddress(r),                // ip_address → ip
		"user_agent":  r.UserAgent(),                  // user_agent (sudah benar)
		"kadaluarsa":  expiresAt.Format(time.RFC3339), // expires_at → kadaluarsa
	}

	sessionJSON, _ := json.Marshal(sessionData)
	apiURL = fmt.Sprintf("%s/rest/v1/sesi_login", supabaseURL)
	httpReq, err = http.NewRequest("POST", apiURL, bytes.NewBuffer(sessionJSON))
	if err != nil {
		log.Printf("ERROR creating session request: %v", err)
		return "", false
	}

	httpReq.Header.Set("apikey", supabaseKey)
	httpReq.Header.Set("Authorization", "Bearer "+supabaseKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Prefer", "return=representation")

	resp, err = http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ERROR creating session: %v", err)
		return "", false
	}
	resp.Body.Close()

	// Return session ID for cookie setting
	return sessionID, true
}

// handleSSOTokenWithCookie processes SSO token and creates local session with cookie
func handleSSOTokenWithCookie(w http.ResponseWriter, r *http.Request, token string) bool {
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
			// If you have PEM format, you may need to parse it with crypto/x509
			return []byte(jwtPublicKey), nil
		}
		// Try to parse as any method - use key as-is
		return []byte(jwtPublicKey), nil
	})

	if err != nil {
		log.Printf("ERROR parsing SSO token: %v", err)
		// Try alternative: treat token as simple base64 encoded user info
		return handleSSOTokenSimpleWithCookie(w, r, token)
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
	sessionID, ok := createSessionFromEmail(r, email)
	if !ok {
		return false
	}

	// Set cookie
	helpers.SetCookie(w, "session_id", sessionID, 86400)
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
			sessionID, ok := createSessionFromEmail(r, email)
			if ok {
				helpers.SetCookie(w, "session_id", sessionID, 86400)
				return true
			}
		}
	}

	// If not base64, try as direct email
	if helpers.ValidateEmail(token) {
		sessionID, ok := createSessionFromEmail(r, token)
		if ok {
			helpers.SetCookie(w, "session_id", sessionID, 86400)
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

	// Use email from SSO response
	email := ssoResponse.Email
	if email == "" && ssoResponse.User != nil {
		if e, ok := ssoResponse.User["email"].(string); ok {
			email = e
		}
	}

	if email == "" {
		log.Println("ERROR: Email not found in SSO response")
		return false
	}

	sessionID, ok := createSessionFromEmail(r, email)
	if !ok {
		return false
	}

	// Set cookie
	helpers.SetCookie(w, "session_id", sessionID, 86400)
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

	// Validate Supabase connection
	supabaseURL := getSupabaseURL()
	supabaseKey := getSupabaseKey()
	if supabaseURL == "" || supabaseKey == "" {
		return false
	}

	// Check session in Supabase with proper URL encoding
	// Schema: id_sesi (text), kadaluarsa (timestamptz), id_pengguna (uuid)
	// PENTING: Kita perlu memastikan session ini dibuat oleh client website, bukan SSO server
	// Untuk sementara, kita akan cek user_agent untuk membedakan
	// (Ini bukan solusi sempurna, tapi cukup untuk development)
	sessionIDEncoded := url.QueryEscape(sessionID)
	expiresEncoded := url.QueryEscape(time.Now().Format(time.RFC3339))

	// Query session dengan filter user_agent untuk memastikan session dari client website
	// SSO server biasanya punya user_agent yang berbeda, atau kita bisa tambahkan kolom client_id
	// Untuk sementara, kita hanya cek apakah session valid dan belum expired
	apiURL := fmt.Sprintf("%s/rest/v1/sesi_login?id_sesi=eq.%s&kadaluarsa=gt.%s&select=*,pengguna(*)",
		supabaseURL, sessionIDEncoded, expiresEncoded)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("apikey", supabaseKey)
	req.Header.Set("Authorization", "Bearer "+supabaseKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return false
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var sessions []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &sessions); err != nil {
		return false
	}

	if len(sessions) == 0 {
		return false
	}

	// PENTING: Session ini hanya dibuat oleh client website sendiri setelah OAuth 2.0 flow
	// Tidak perlu cek prefix karena session sudah terpisah (hanya dibuat oleh client website)
	// Jika session ada di database, berarti valid (karena hanya dibuat oleh client website)
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
func handleLoginAPI(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helpers.WriteError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	// Validate input
	if !helpers.ValidateEmail(req.Email) {
		helpers.WriteError(w, http.StatusBadRequest, "Email tidak valid")
		return
	}

	if len(req.Password) < 6 {
		helpers.WriteError(w, http.StatusBadRequest, "Password minimal 6 karakter")
		return
	}

	// Validate Supabase connection
	supabaseURL := getSupabaseURL()
	supabaseKey := getSupabaseKey()
	if supabaseURL == "" || supabaseKey == "" {
		log.Println("ERROR: SUPABASE_URL or SUPABASE_KEY not set")
		helpers.WriteError(w, http.StatusInternalServerError, "Konfigurasi server tidak lengkap")
		return
	}

	// Get user from Supabase with proper URL encoding
	emailEncoded := url.QueryEscape(req.Email)
	apiURL := fmt.Sprintf("%s/rest/v1/pengguna?email=eq.%s&select=*", getSupabaseURL(), emailEncoded)

	httpReq, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		log.Printf("ERROR creating request: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Terjadi kesalahan")
		return
	}

	httpReq.Header.Set("apikey", getSupabaseKey())
	httpReq.Header.Set("Authorization", "Bearer "+getSupabaseKey())
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ERROR calling Supabase: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal terhubung ke database")
		return
	}
	defer resp.Body.Close()

	// Read response body for debugging
	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR Supabase response: Status %d, Body: %s", resp.StatusCode, string(bodyBytes))
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal mengambil data pengguna")
		return
	}

	var users []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &users); err != nil {
		log.Printf("ERROR parsing response: %v, Body: %s", err, string(bodyBytes))
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal memproses data")
		return
	}

	if len(users) == 0 {
		helpers.WriteError(w, http.StatusUnauthorized, "Email atau password salah")
		return
	}

	user := users[0]

	// Verify password
	var passwordMatch bool
	if passwordHash, ok := user["password"].(string); ok && passwordHash != "" {
		// Verify password with bcrypt
		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err == nil {
			passwordMatch = true
		}
	} else {
		// Fallback: Try password_hash field (for backward compatibility)
		if password, ok := user["password"].(string); ok {
			if password == req.Password {
				passwordMatch = true
			}
		}
	}

	if !passwordMatch {
		helpers.WriteError(w, http.StatusUnauthorized, "Email atau password salah")
		return
	}

	// Check if user is active
	if active, ok := user["aktif"].(bool); !ok || !active {
		helpers.WriteError(w, http.StatusForbidden, "Akun tidak aktif")
		return
	}

	// Create session
	sessionID, _ := helpers.GenerateSessionID()
	expiresAt := time.Now().Add(24 * time.Hour)

	sessionData := map[string]interface{}{
		"user_id":    user["id"],
		"session_id": sessionID,
		"ip_address": getIPAddress(r),
		"user_agent": r.UserAgent(),
		"expires_at": expiresAt.Format(time.RFC3339),
	}

	sessionJSON, _ := json.Marshal(sessionData)
	apiURL = fmt.Sprintf("%s/rest/v1/sesi_login", getSupabaseURL())
	httpReq, err = http.NewRequest("POST", apiURL, bytes.NewBuffer(sessionJSON))
	if err != nil {
		log.Printf("ERROR creating request: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Terjadi kesalahan")
		return
	}
	httpReq.Header.Set("apikey", getSupabaseKey())
	httpReq.Header.Set("Authorization", "Bearer "+getSupabaseKey())
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Prefer", "return=representation")

	resp, err = http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ERROR calling Supabase: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal membuat sesi")
		return
	}
	resp.Body.Close()

	// Set cookie
	helpers.SetCookie(w, "session_id", sessionID, 86400)

	// Return success with redirect instruction
	helpers.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"message":  "Login berhasil",
		"redirect": "/",
	})
	return
}

func handleRegisterAPI(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		Password    string `json:"password"`
		NamaLengkap string `json:"nama_lengkap"`
		Peran       string `json:"peran"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helpers.WriteError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	// Validate input
	if !helpers.ValidateEmail(req.Email) {
		helpers.WriteError(w, http.StatusBadRequest, "Email tidak valid")
		return
	}

	if len(req.Password) < 6 {
		helpers.WriteError(w, http.StatusBadRequest, "Password minimal 6 karakter")
		return
	}

	if len(req.NamaLengkap) < 3 {
		helpers.WriteError(w, http.StatusBadRequest, "Nama lengkap minimal 3 karakter")
		return
	}

	validRoles := map[string]bool{"guru": true, "wali": true, "murid": true, "admin": true, "user": true}
	if !validRoles[req.Peran] {
		helpers.WriteError(w, http.StatusBadRequest, "Peran tidak valid")
		return
	}

	// Validate Supabase connection
	supabaseURL := getSupabaseURL()
	supabaseKey := getSupabaseKey()
	if supabaseURL == "" || supabaseKey == "" {
		log.Println("ERROR: SUPABASE_URL or SUPABASE_KEY not set")
		helpers.WriteError(w, http.StatusInternalServerError, "Konfigurasi server tidak lengkap")
		return
	}

	// Check if email exists with proper URL encoding
	emailEncoded := url.QueryEscape(req.Email)
	// Schema: id_pengguna adalah primary key, bukan id
	apiURL := fmt.Sprintf("%s/rest/v1/pengguna?email=eq.%s&select=id_pengguna", supabaseURL, emailEncoded)
	httpReq, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		log.Printf("ERROR creating request: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Terjadi kesalahan")
		return
	}
	httpReq.Header.Set("apikey", getSupabaseKey())
	httpReq.Header.Set("Authorization", "Bearer "+getSupabaseKey())
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ERROR calling Supabase: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal terhubung ke database")
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR Supabase response: Status %d, Body: %s", resp.StatusCode, string(bodyBytes))
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal memeriksa email")
		return
	}

	var existingUsers []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &existingUsers); err != nil {
		log.Printf("ERROR parsing response: %v, Body: %s", err, string(bodyBytes))
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal memproses data")
		return
	}

	if len(existingUsers) > 0 {
		helpers.WriteError(w, http.StatusConflict, "Email sudah terdaftar")
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal mengenkripsi password")
		return
	}

	// Create user
	userData := map[string]interface{}{
		"email":        req.Email,
		"password":     string(hashedPassword),
		"nama_lengkap": helpers.SanitizeInput(req.NamaLengkap),
		"peran":        req.Peran,
		"aktif":        true,
	}

	userJSON, _ := json.Marshal(userData)
	apiURL = fmt.Sprintf("%s/rest/v1/pengguna", getSupabaseURL())
	httpReq, err = http.NewRequest("POST", apiURL, bytes.NewBuffer(userJSON))
	if err != nil {
		log.Printf("ERROR creating request: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Terjadi kesalahan")
		return
	}
	httpReq.Header.Set("apikey", getSupabaseKey())
	httpReq.Header.Set("Authorization", "Bearer "+getSupabaseKey())
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Prefer", "return=representation")

	resp, err = http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ERROR calling Supabase: %v", err)
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal membuat akun")
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Printf("ERROR Supabase response: Status %d, Body: %s", resp.StatusCode, string(bodyBytes))
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal membuat akun")
		return
	}

	var newUsers []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &newUsers); err != nil {
		log.Printf("ERROR parsing response: %v, Body: %s", err, string(bodyBytes))
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal memproses data")
		return
	}

	if len(newUsers) == 0 {
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal membuat akun")
		return
	}

	newUser := newUsers[0]

	// Auto-login: Create session menggunakan session.CreateSession
	// Schema: id_pengguna adalah primary key, bukan id
	userIDVal := newUser["id_pengguna"]
	if userIDVal == nil {
		// Fallback ke id jika id_pengguna tidak ada (untuk backward compatibility)
		userIDVal = newUser["id"]
		if userIDVal == nil {
			log.Printf("ERROR: User tidak memiliki kolom id_pengguna atau id. User keys: %v", getMapKeys(newUser))
			helpers.WriteError(w, http.StatusInternalServerError, "Data user tidak valid")
			return
		}
	}

	// Convert userID ke string untuk konsistensi
	userID := fmt.Sprintf("%v", userIDVal)

	// Buat session menggunakan session.CreateSession
	sessionID, err := session.CreateSession(userID, r)
	if err != nil {
		log.Printf("WARNING: Error creating session: %v", err)
		// Lanjutkan meskipun error, registrasi tetap berhasil
	} else {
		// Set cookie dengan nama yang berbeda dari SSO server
		// PENTING: Gunakan cookie name yang berbeda untuk mencegah shared cookie
		helpers.SetCookie(w, "client_dinas_session", sessionID, 86400) // 24 jam
		log.Printf("✅ Session created for new user: %s", sessionID)
	}

	// Return success with redirect instruction
	helpers.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"message":  "Registrasi berhasil",
		"redirect": "/",
	})
	return
}

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

	helpers.ClearCookie(w, "session_id")
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

	helpers.ClearCookie(w, "session_id")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleGetProfileAPI(w http.ResponseWriter, r *http.Request) {
	user, err := getCurrentUser(r)
	if err != nil {
		helpers.WriteError(w, http.StatusUnauthorized, "Tidak terautentikasi")
		return
	}

	helpers.WriteSuccess(w, "Profile retrieved", map[string]interface{}{
		"id":           user["id"],
		"email":        user["email"],
		"nama_lengkap": user["nama_lengkap"],
		"peran":        user["peran"],
	})
}

func handleUpdateProfileAPI(w http.ResponseWriter, r *http.Request) {
	user, err := getCurrentUser(r)
	if err != nil {
		helpers.WriteError(w, http.StatusUnauthorized, "Tidak terautentikasi")
		return
	}

	var req struct {
		NamaLengkap string `json:"nama_lengkap"`
		Email       string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helpers.WriteError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	if len(req.NamaLengkap) < 3 {
		helpers.WriteError(w, http.StatusBadRequest, "Nama lengkap minimal 3 karakter")
		return
	}

	if !helpers.ValidateEmail(req.Email) {
		helpers.WriteError(w, http.StatusBadRequest, "Email tidak valid")
		return
	}

	// Check if email is taken by another user
	// Schema: id_pengguna adalah primary key, bukan id
	emailEncoded := url.QueryEscape(req.Email)
	userIDValue := user["id_pengguna"]
	if userIDValue == nil {
		userIDValue = user["id"]
	}
	url := fmt.Sprintf("%s/rest/v1/pengguna?email=eq.%s&id_pengguna=neq.%v&select=id_pengguna", getSupabaseURL(), emailEncoded, userIDValue)
	httpReq, _ := http.NewRequest("GET", url, nil)
	httpReq.Header.Set("apikey", getSupabaseKey())
	httpReq.Header.Set("Authorization", "Bearer "+getSupabaseKey())

	resp, err := http.DefaultClient.Do(httpReq)
	if err == nil {
		defer resp.Body.Close()
		var existingUsers []map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&existingUsers)
		if len(existingUsers) > 0 {
			helpers.WriteError(w, http.StatusConflict, "Email sudah digunakan")
			return
		}
	}

	// Update user
	updateData := map[string]interface{}{
		"nama_lengkap": helpers.SanitizeInput(req.NamaLengkap),
		"email":        req.Email,
		"updated_at":   time.Now().Format(time.RFC3339),
	}

	updateJSON, _ := json.Marshal(updateData)
	// Schema: id_pengguna adalah primary key, bukan id
	// Reuse userIDValue dari scope sebelumnya atau get baru
	var updateUserID interface{}
	updateUserID = user["id_pengguna"]
	if updateUserID == nil {
		updateUserID = user["id"]
	}
	updateURL := fmt.Sprintf("%s/rest/v1/pengguna?id_pengguna=eq.%v", getSupabaseURL(), updateUserID)
	httpReq, _ = http.NewRequest("PATCH", updateURL, bytes.NewBuffer(updateJSON))
	httpReq.Header.Set("apikey", getSupabaseKey())
	httpReq.Header.Set("Authorization", "Bearer "+getSupabaseKey())
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Prefer", "return=representation")

	_, err = http.DefaultClient.Do(httpReq)
	if err != nil {
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal mengupdate profile")
		return
	}

	helpers.WriteSuccess(w, "Profile berhasil diupdate", nil)
}

func handleChangePasswordAPI(w http.ResponseWriter, r *http.Request) {
	user, err := getCurrentUser(r)
	if err != nil {
		helpers.WriteError(w, http.StatusUnauthorized, "Tidak terautentikasi")
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helpers.WriteError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	if len(req.NewPassword) < 6 {
		helpers.WriteError(w, http.StatusBadRequest, "Password baru minimal 6 karakter")
		return
	}

	// Get current password hash
	// Schema: id_pengguna adalah primary key, bukan id
	userIDValue := user["id_pengguna"]
	if userIDValue == nil {
		userIDValue = user["id"]
	}
	url := fmt.Sprintf("%s/rest/v1/pengguna?id_pengguna=eq.%v&select=password", getSupabaseURL(), userIDValue)
	httpReq, _ := http.NewRequest("GET", url, nil)
	httpReq.Header.Set("apikey", getSupabaseKey())
	httpReq.Header.Set("Authorization", "Bearer "+getSupabaseKey())

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		helpers.WriteError(w, http.StatusInternalServerError, "Terjadi kesalahan")
		return
	}
	defer resp.Body.Close()

	var users []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&users)
	if len(users) == 0 {
		helpers.WriteError(w, http.StatusNotFound, "User tidak ditemukan")
		return
	}

	passwordHash := fmt.Sprintf("%v", users[0]["password"])

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.OldPassword)); err != nil {
		helpers.WriteError(w, http.StatusUnauthorized, "Password lama salah")
		return
	}

	// Hash new password
	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal mengenkripsi password")
		return
	}

	// Update password
	updateData := map[string]interface{}{
		"password":   string(newHashedPassword),
		"updated_at": time.Now().Format(time.RFC3339),
	}

	updateJSON, _ := json.Marshal(updateData)
	// Schema: id_pengguna adalah primary key, bukan id
	// Reuse userIDValue dari scope sebelumnya atau get baru
	var updateUserID interface{}
	updateUserID = user["id_pengguna"]
	if updateUserID == nil {
		updateUserID = user["id"]
	}
	updateURL := fmt.Sprintf("%s/rest/v1/pengguna?id_pengguna=eq.%v", getSupabaseURL(), updateUserID)
	httpReq, _ = http.NewRequest("PATCH", updateURL, bytes.NewBuffer(updateJSON))
	httpReq.Header.Set("apikey", getSupabaseKey())
	httpReq.Header.Set("Authorization", "Bearer "+getSupabaseKey())
	httpReq.Header.Set("Content-Type", "application/json")

	_, err = http.DefaultClient.Do(httpReq)
	if err != nil {
		helpers.WriteError(w, http.StatusInternalServerError, "Gagal mengubah password")
		return
	}

	helpers.WriteSuccess(w, "Password berhasil diubah", nil)
}

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
func createSession(userID interface{}, r *http.Request) (sessionID string, err error) {
	supabaseURL := getSupabaseURL()
	supabaseKey := getSupabaseKey()
	if supabaseURL == "" || supabaseKey == "" {
		return "", fmt.Errorf("SUPABASE_URL atau SUPABASE_KEY tidak di-set")
	}

	// Generate session ID
	sessionID, err = helpers.GenerateSessionID()
	if err != nil {
		log.Printf("ERROR generating session ID: %v", err)
		return "", fmt.Errorf("gagal membuat session ID")
	}

	// Siapkan data session sesuai schema Supabase
	expiresAt := time.Now().Add(24 * time.Hour)
	sessionData := map[string]interface{}{
		"id_pengguna": userID,
		"id_sesi":     sessionID,
		"ip":          getIPAddress(r),
		"user_agent":  r.UserAgent(),
		"kadaluarsa":  expiresAt.Format(time.RFC3339),
	}

	// Convert ke JSON
	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		log.Printf("ERROR marshaling session data: %v", err)
		return "", fmt.Errorf("gagal memproses data session")
	}

	// POST ke Supabase
	apiURL := fmt.Sprintf("%s/rest/v1/sesi_login", supabaseURL)
	httpReq, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(sessionJSON))
	if err != nil {
		log.Printf("ERROR creating request: %v", err)
		return "", fmt.Errorf("gagal membuat request")
	}

	httpReq.Header.Set("apikey", supabaseKey)
	httpReq.Header.Set("Authorization", "Bearer "+supabaseKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Prefer", "return=representation")

	// Eksekusi request
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ERROR calling Supabase: %v", err)
		return "", fmt.Errorf("gagal terhubung ke database")
	}
	defer resp.Body.Close()

	// Baca response untuk debugging
	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Printf("ERROR Supabase response: Status %d, Body: %s", resp.StatusCode, string(bodyBytes))
		return "", fmt.Errorf("gagal membuat session di database: status %d", resp.StatusCode)
	}

	log.Printf("✅ Session created: %s for user: %v", sessionID, userID)
	return sessionID, nil
}

// validateSession memvalidasi session ID dan mengembalikan user ID jika valid
func validateSession(sessionID string) (userID string, ok bool, err error) {
	supabaseURL := getSupabaseURL()
	supabaseKey := getSupabaseKey()
	if supabaseURL == "" || supabaseKey == "" {
		return "", false, fmt.Errorf("SUPABASE_URL atau SUPABASE_KEY tidak di-set")
	}

	if sessionID == "" {
		return "", false, fmt.Errorf("session ID kosong")
	}

	// Query session dengan proper URL encoding
	sessionIDEncoded := url.QueryEscape(sessionID)
	now := time.Now().Format(time.RFC3339)
	nowEncoded := url.QueryEscape(now)

	// Query: id_sesi = ? AND kadaluarsa > now
	apiURL := fmt.Sprintf("%s/rest/v1/sesi_login?id_sesi=eq.%s&kadaluarsa=gt.%s&select=id_pengguna",
		supabaseURL, sessionIDEncoded, nowEncoded)

	httpReq, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		log.Printf("ERROR creating request: %v", err)
		return "", false, fmt.Errorf("gagal membuat request")
	}

	httpReq.Header.Set("apikey", supabaseKey)
	httpReq.Header.Set("Authorization", "Bearer "+supabaseKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ERROR calling Supabase: %v", err)
		return "", false, fmt.Errorf("gagal terhubung ke database")
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("ERROR Supabase response: Status %d, Body: %s", resp.StatusCode, string(bodyBytes))
		return "", false, fmt.Errorf("gagal memvalidasi session")
	}

	var sessions []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &sessions); err != nil {
		log.Printf("ERROR parsing response: %v", err)
		return "", false, fmt.Errorf("gagal memproses data")
	}

	if len(sessions) == 0 {
		return "", false, nil // Session tidak ditemukan atau expired
	}

	// Extract id_pengguna (user_id)
	session := sessions[0]
	userIDVal := session["id_pengguna"]
	if userIDVal == nil {
		return "", false, fmt.Errorf("id_pengguna tidak ditemukan")
	}

	// Convert id_pengguna ke string
	userID = fmt.Sprintf("%v", userIDVal)
	return userID, true, nil
}

// clearSession menghapus session di database (DELETE)
func clearSession(sessionID string) error {
	supabaseURL := getSupabaseURL()
	supabaseKey := getSupabaseKey()
	if supabaseURL == "" || supabaseKey == "" {
		return fmt.Errorf("SUPABASE_URL atau SUPABASE_KEY tidak di-set")
	}

	if sessionID == "" {
		return fmt.Errorf("session ID kosong")
	}

	// DELETE session dari Supabase
	sessionIDEncoded := url.QueryEscape(sessionID)
	apiURL := fmt.Sprintf("%s/rest/v1/sesi_login?id_sesi=eq.%s", supabaseURL, sessionIDEncoded)
	httpReq, err := http.NewRequest("DELETE", apiURL, nil)
	if err != nil {
		log.Printf("ERROR creating request: %v", err)
		return fmt.Errorf("gagal membuat request")
	}

	httpReq.Header.Set("apikey", supabaseKey)
	httpReq.Header.Set("Authorization", "Bearer "+supabaseKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Printf("ERROR calling Supabase: %v", err)
		return fmt.Errorf("gagal terhubung ke database")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("ERROR Supabase response: Status %d, Body: %s", resp.StatusCode, string(bodyBytes))
		return fmt.Errorf("gagal menghapus session")
	}

	log.Printf("✅ Session cleared: %s", sessionID)
	return nil
}

// Page rendering functions
func renderLoginPage(w http.ResponseWriter, errorMsg, email string) {
	logoBase64 := base64.StdEncoding.EncodeToString(LogoData)
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Dinas Pendidikan DKI Jakarta</title>
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
        }
        .logo {
            text-align: center;
            margin-bottom: 32px;
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
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            color: #334155;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 8px;
        }
        .input-wrapper {
            position: relative;
        }
        .form-group input {
            width: 100%%;
            padding: 12px 16px;
            padding-right: 45px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 15px;
            transition: all 0.2s;
            background: #f8fafc;
        }
        .form-group input:focus {
            outline: none;
            border-color: #6366f1;
            background: white;
        }
        .password-toggle {
            position: absolute;
            right: 12px;
            top: 50%%;
            transform: translateY(-50%%);
            background: none;
            border: none;
            cursor: pointer;
            color: #64748b;
            font-size: 18px;
            padding: 4px;
        }
        .password-toggle:hover {
            color: #334155;
        }
        .password-toggle svg {
            width: 18px;
            height: 18px;
            pointer-events: none;
        }
        .btn-primary {
            width: 100%%;
            padding: 14px;
            background: #6366f1;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            margin-top: 8px;
        }
        .btn-primary:hover {
            background: #4f46e5;
        }
        .btn-primary:disabled {
            background: #94a3b8;
            cursor: not-allowed;
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
        .link-text {
            text-align: center;
            margin-top: 24px;
            color: #64748b;
            font-size: 14px;
        }
        .link-text a {
            color: #6366f1;
            text-decoration: none;
            font-weight: 500;
        }
        .link-text a:hover {
            text-decoration: underline;
        }
        .divider {
            display: flex;
            align-items: center;
            margin: 24px 0;
            color: #94a3b8;
            font-size: 14px;
        }
        .divider::before,
        .divider::after {
            content: '';
            flex: 1;
            height: 1px;
            background: #e2e8f0;
        }
        .divider span {
            padding: 0 16px;
        }
        .btn-sso {
            width: 100%%;
            padding: 14px;
            background: white;
            color: #1e293b;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            text-decoration: none;
        }
        .btn-sso:hover {
            border-color: #6366f1;
            background: #f8fafc;
        }
        .btn-sso svg {
            width: 20px;
            height: 20px;
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
        <form id="loginForm" method="POST" action="/login">
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required value="%s" autocomplete="email">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <div class="input-wrapper">
                    <input type="password" id="password" name="password" required autocomplete="current-password">
                    <button type="button" class="password-toggle" onclick="togglePassword('password')">
                        <svg class="eye-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                        </svg>
                        <svg class="eye-off-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" style="display: none;">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                        </svg>
                    </button>
                </div>
            </div>
            <button type="submit" class="btn-primary" id="submitBtn">Masuk</button>
        </form>
        <div class="divider">
            <span>atau</span>
        </div>
        <div class="link-text">
            Belum punya akun? <a href="/register">Daftar di sini</a>
        </div>
    </div>
    <div class="error-popup" id="errorPopup"></div>
    <script>
        function togglePassword(inputId) {
            const input = document.getElementById(inputId);
            const button = input.nextElementSibling;
            const eyeIcon = button.querySelector('.eye-icon');
            const eyeOffIcon = button.querySelector('.eye-off-icon');
            if (input.type === 'password') {
                input.type = 'text';
                eyeIcon.style.display = 'none';
                eyeOffIcon.style.display = 'block';
            } else {
                input.type = 'password';
                eyeIcon.style.display = 'block';
                eyeOffIcon.style.display = 'none';
            }
        }
        function showError(message) {
            const popup = document.getElementById('errorPopup');
            popup.textContent = message;
            popup.classList.add('show');
            setTimeout(() => popup.classList.remove('show'), 5000);
        }
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('submitBtn');
            const originalText = btn.textContent;
            btn.disabled = true;
            btn.textContent = 'Memproses...';
            const formData = {
                email: document.getElementById('email').value.trim(),
                password: document.getElementById('password').value
            };
            if (!formData.email || !formData.password) {
                showError('Email dan password harus diisi');
                btn.disabled = false;
                btn.textContent = originalText;
                return;
            }
            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify(formData)
                });
                
                // Cek status code
                if (!res.ok) {
                    const errorData = await res.json().catch(() => ({ error: 'Login gagal' }));
                    showError(errorData.error || 'Login gagal');
                    btn.disabled = false;
                    btn.textContent = originalText;
                    return;
                }
                
                const data = await res.json();
                if (data.success) {
                    // Redirect ke dashboard atau redirect URL dari server
                    const redirectUrl = data.redirect || '/dashboard';
                    window.location.href = redirectUrl;
                } else {
                    showError(data.error || 'Login gagal');
                    btn.disabled = false;
                    btn.textContent = originalText;
                }
            } catch (error) {
                console.error('Login error:', error);
                showError('Terjadi kesalahan. Silakan coba lagi.');
                btn.disabled = false;
                btn.textContent = originalText;
            }
        });
        %s
    </script>
</body>
</html>`, logoBase64, email, func() string {
		if errorMsg != "" {
			return fmt.Sprintf("showError('%s');", strings.ReplaceAll(errorMsg, "'", "\\'"))
		}
		return ""
	}())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func renderRegisterPage(w http.ResponseWriter, errorMsg string) {
	logoBase64 := base64.StdEncoding.EncodeToString(LogoData)
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Daftar - Dinas Pendidikan DKI Jakarta</title>
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
        .register-container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 100%%;
            max-width: 480px;
            padding: 40px;
            max-height: 90vh;
            overflow-y: auto;
        }
        .logo {
            text-align: center;
            margin-bottom: 32px;
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
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            color: #334155;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 8px;
        }
        .input-wrapper {
            position: relative;
        }
        .form-group input,
        .form-group select {
            width: 100%%;
            padding: 12px 16px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 15px;
            transition: all 0.2s;
            background: #f8fafc;
        }
        .form-group input[type="password"] {
            padding-right: 45px;
        }
        .form-group input:focus,
        .form-group select:focus {
            outline: none;
            border-color: #6366f1;
            background: white;
        }
        .password-toggle {
            position: absolute;
            right: 12px;
            top: 50%%;
            transform: translateY(-50%%);
            background: none;
            border: none;
            cursor: pointer;
            color: #64748b;
            font-size: 18px;
            padding: 4px;
        }
        .password-toggle:hover {
            color: #334155;
        }
        .password-toggle svg {
            width: 18px;
            height: 18px;
            pointer-events: none;
        }
        .btn-primary {
            width: 100%%;
            padding: 14px;
            background: #6366f1;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            margin-top: 8px;
        }
        .btn-primary:hover {
            background: #4f46e5;
        }
        .btn-primary:disabled {
            background: #94a3b8;
            cursor: not-allowed;
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
        .link-text {
            text-align: center;
            margin-top: 24px;
            color: #64748b;
            font-size: 14px;
        }
        .link-text a {
            color: #6366f1;
            text-decoration: none;
            font-weight: 500;
        }
        .link-text a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="register-container">
        <div class="logo">
            <img src="data:image/png;base64,%s" alt="Logo Dinas Pendidikan">
            <h1>Daftar Akun</h1>
            <p>Dinas Pendidikan DKI Jakarta</p>
        </div>
        <form id="registerForm">
            <div class="form-group">
                <label for="nama_lengkap">Nama Lengkap</label>
                <input type="text" id="nama_lengkap" name="nama_lengkap" required autocomplete="name">
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required autocomplete="email">
            </div>
            <div class="form-group">
                <label for="peran">Peran</label>
                <select id="peran" name="peran" required>
                    <option value="">Pilih Peran</option>
                    <option value="guru">Guru</option>
                    <option value="wali">Wali Murid</option>
                    <option value="murid">Murid</option>
                    <option value="user">User Umum</option>
                </select>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <div class="input-wrapper">
                    <input type="password" id="password" name="password" required autocomplete="new-password">
                    <button type="button" class="password-toggle" onclick="togglePassword('password')">
                        <svg class="eye-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                        </svg>
                        <svg class="eye-off-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" style="display: none;">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                        </svg>
                    </button>
                </div>
            </div>
            <button type="submit" class="btn-primary" id="submitBtn">Daftar</button>
        </form>
        <div class="link-text">
            Sudah punya akun? <a href="/login">Masuk di sini</a>
        </div>
    </div>
    <div class="error-popup" id="errorPopup"></div>
    <script>
        function togglePassword(inputId) {
            const input = document.getElementById(inputId);
            const button = input.nextElementSibling;
            const eyeIcon = button.querySelector('.eye-icon');
            const eyeOffIcon = button.querySelector('.eye-off-icon');
            if (input.type === 'password') {
                input.type = 'text';
                eyeIcon.style.display = 'none';
                eyeOffIcon.style.display = 'block';
            } else {
                input.type = 'password';
                eyeIcon.style.display = 'block';
                eyeOffIcon.style.display = 'none';
            }
        }
        function showError(message) {
            const popup = document.getElementById('errorPopup');
            popup.textContent = message;
            popup.classList.add('show');
            setTimeout(() => popup.classList.remove('show'), 5000);
        }
        document.getElementById('registerForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('submitBtn');
            const originalText = btn.textContent;
            btn.disabled = true;
            btn.textContent = 'Memproses...';
            const formData = {
                nama_lengkap: document.getElementById('nama_lengkap').value.trim(),
                email: document.getElementById('email').value.trim(),
                peran: document.getElementById('peran').value,
                password: document.getElementById('password').value
            };
            if (!formData.nama_lengkap || !formData.email || !formData.peran || !formData.password) {
                showError('Semua field harus diisi');
                btn.disabled = false;
                btn.textContent = originalText;
                return;
            }
            if (formData.password.length < 6) {
                showError('Password minimal 6 karakter');
                btn.disabled = false;
                btn.textContent = originalText;
                return;
            }
            try {
                const res = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(formData)
                });
                
                // Cek status code
                if (!res.ok) {
                    const errorData = await res.json().catch(() => ({ error: 'Registrasi gagal' }));
                    showError(errorData.error || 'Registrasi gagal');
                    btn.disabled = false;
                    btn.textContent = originalText;
                    return;
                }
                
                const data = await res.json();
                if (data.success) {
                    // Redirect to home page after successful registration
                    window.location.href = data.redirect || '/';
                } else {
                    showError(data.error || 'Registrasi gagal');
                    btn.disabled = false;
                    btn.textContent = originalText;
                }
            } catch (error) {
                console.error('Register error:', error);
                showError('Terjadi kesalahan. Silakan coba lagi.');
                btn.disabled = false;
                btn.textContent = originalText;
            }
        });
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
                <span style="color: #64748b; font-size: 14px;">%s</span>
                <a href="/profile" style="text-decoration: none; color: #6366f1; font-weight: 500; font-size: 14px;">Profile</a>
                <a href="/logout" style="text-decoration: none; color: #dc2626; font-weight: 500; font-size: 14px;">Keluar</a>
            </div>
        </div>
    </nav>
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

func renderProfilePage(w http.ResponseWriter, r *http.Request) {
	user, err := getCurrentUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	header := getCommonHeader(user)
	userName := fmt.Sprintf("%v", user["nama_lengkap"])
	userEmail := fmt.Sprintf("%v", user["email"])
	userRole := fmt.Sprintf("%v", user["peran"])

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile - Dinas Pendidikan DKI Jakarta</title>
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
            display: grid;
            grid-template-columns: 280px 1fr;
            gap: 24px;
        }
        .sidebar {
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            height: fit-content;
        }
        .sidebar h2 {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 24px;
            color: #1e293b;
        }
        .sidebar-menu {
            list-style: none;
        }
        .sidebar-menu li {
            margin-bottom: 8px;
        }
        .sidebar-menu a {
            display: block;
            padding: 12px;
            color: #64748b;
            text-decoration: none;
            border-radius: 8px;
            transition: all 0.2s;
        }
        .sidebar-menu a:hover,
        .sidebar-menu a.active {
            background: #e0e7ff;
            color: #6366f1;
        }
        .main-content {
            background: white;
            border-radius: 12px;
            padding: 32px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .main-content h1 {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 32px;
            color: #1e293b;
        }
        .form-section {
            margin-bottom: 32px;
        }
        .form-section h2 {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 20px;
            color: #334155;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            color: #334155;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 8px;
        }
        .form-group input {
            width: 100%%;
            padding: 12px 16px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 15px;
            transition: all 0.2s;
            background: #f8fafc;
        }
        .form-group input:focus {
            outline: none;
            border-color: #6366f1;
            background: white;
        }
        .form-group input:disabled {
            background: #f1f5f9;
            color: #64748b;
        }
        .btn-primary {
            padding: 12px 24px;
            background: #6366f1;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-primary:hover {
            background: #4f46e5;
        }
        .btn-primary:disabled {
            background: #94a3b8;
            cursor: not-allowed;
        }
        .success-message {
            background: #d1fae5;
            color: #065f46;
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
        }
        .success-message.show {
            display: block;
        }
        .error-message {
            background: #fee2e2;
            color: #991b1b;
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
        }
        .error-message.show {
            display: block;
        }
        @media (max-width: 768px) {
            .container {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    %s
    <div class="container">
        <aside class="sidebar">
            <h2>Menu</h2>
            <ul class="sidebar-menu">
                <li><a href="#profile" class="active" onclick="showSection('profile')">Edit Profile</a></li>
                <li><a href="#password" onclick="showSection('password')">Ubah Password</a></li>
            </ul>
        </aside>
        <main class="main-content">
            <h1>Profile Saya</h1>
            <div id="successMsg" class="success-message"></div>
            <div id="errorMsg" class="error-message"></div>
            
            <div id="profileSection" class="form-section">
                <h2>Informasi Profile</h2>
                <form id="profileForm">
                    <div class="form-group">
                        <label for="nama_lengkap">Nama Lengkap</label>
                        <input type="text" id="nama_lengkap" name="nama_lengkap" value="%s" required>
                    </div>
                    <div class="form-group">
                        <label for="email">Email</label>
                        <input type="email" id="email" name="email" value="%s" required>
                    </div>
                    <div class="form-group">
                        <label for="peran">Peran</label>
                        <input type="text" id="peran" value="%s" disabled>
                    </div>
                    <button type="submit" class="btn-primary" id="profileBtn">Simpan Perubahan</button>
                </form>
            </div>
            
            <div id="passwordSection" class="form-section" style="display: none;">
                <h2>Ubah Password</h2>
                <form id="passwordForm">
                    <div class="form-group">
                        <label for="old_password">Password Lama</label>
                        <input type="password" id="old_password" name="old_password" required>
                    </div>
                    <div class="form-group">
                        <label for="new_password">Password Baru</label>
                        <input type="password" id="new_password" name="new_password" required>
                    </div>
                    <div class="form-group">
                        <label for="confirm_password">Konfirmasi Password Baru</label>
                        <input type="password" id="confirm_password" name="confirm_password" required>
                    </div>
                    <button type="submit" class="btn-primary" id="passwordBtn">Ubah Password</button>
                </form>
            </div>
        </main>
    </div>
    <script>
        function showSection(section) {
            document.getElementById('profileSection').style.display = section === 'profile' ? 'block' : 'none';
            document.getElementById('passwordSection').style.display = section === 'password' ? 'block' : 'none';
            document.querySelectorAll('.sidebar-menu a').forEach(a => a.classList.remove('active'));
            event.target.classList.add('active');
        }
        function showMessage(type, message) {
            const successMsg = document.getElementById('successMsg');
            const errorMsg = document.getElementById('errorMsg');
            successMsg.classList.remove('show');
            errorMsg.classList.remove('show');
            if (type === 'success') {
                successMsg.textContent = message;
                successMsg.classList.add('show');
            } else {
                errorMsg.textContent = message;
                errorMsg.classList.add('show');
            }
            setTimeout(() => {
                successMsg.classList.remove('show');
                errorMsg.classList.remove('show');
            }, 5000);
        }
        document.getElementById('profileForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('profileBtn');
            const originalText = btn.textContent;
            btn.disabled = true;
            btn.textContent = 'Menyimpan...';
            const formData = {
                nama_lengkap: document.getElementById('nama_lengkap').value.trim(),
                email: document.getElementById('email').value.trim()
            };
            try {
                const res = await fetch('/api/profile', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(formData)
                });
                const data = await res.json();
                if (data.success) {
                    showMessage('success', 'Profile berhasil diupdate');
                } else {
                    showMessage('error', data.error || 'Gagal mengupdate profile');
                }
            } catch (error) {
                showMessage('error', 'Terjadi kesalahan. Silakan coba lagi.');
            }
            btn.disabled = false;
            btn.textContent = originalText;
        });
        document.getElementById('passwordForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('passwordBtn');
            const originalText = btn.textContent;
            const newPassword = document.getElementById('new_password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            if (newPassword !== confirmPassword) {
                showMessage('error', 'Password baru dan konfirmasi tidak cocok');
                btn.disabled = false;
                btn.textContent = originalText;
                return;
            }
            if (newPassword.length < 6) {
                showMessage('error', 'Password baru minimal 6 karakter');
                btn.disabled = false;
                btn.textContent = originalText;
                return;
            }
            btn.disabled = true;
            btn.textContent = 'Mengubah...';
            const formData = {
                old_password: document.getElementById('old_password').value,
                new_password: newPassword
            };
            try {
                const res = await fetch('/api/password', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(formData)
                });
                const data = await res.json();
                if (data.success) {
                    showMessage('success', 'Password berhasil diubah');
                    document.getElementById('passwordForm').reset();
                } else {
                    showMessage('error', data.error || 'Gagal mengubah password');
                }
            } catch (error) {
                showMessage('error', 'Terjadi kesalahan. Silakan coba lagi.');
            }
            btn.disabled = false;
            btn.textContent = originalText;
        });
    </script>
</body>
</html>`, header, userName, userEmail, userRole)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
