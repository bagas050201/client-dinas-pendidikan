package api

import (
	"client-dinas-pendidikan/api/session"
	"client-dinas-pendidikan/pkg/helpers"
	"log"
	"net/http"
	"strconv"
	"time"
)

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
