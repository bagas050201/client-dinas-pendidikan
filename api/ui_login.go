package api

import (
	"client-dinas-pendidikan/internal"
	"client-dinas-pendidikan/pkg/helpers"
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

	"golang.org/x/crypto/bcrypt"
)

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
			userID, ok, err := internal.ValidateSession(sessionID)
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
	if passwordHash, ok := user["password_hash"].(string); ok && passwordHash != "" {
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

	sessionID, err := internal.CreateSession(userID, r)
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
