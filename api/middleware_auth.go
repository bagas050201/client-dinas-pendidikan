package api

import (
	"client-dinas-pendidikan/api/session"
	"client-dinas-pendidikan/pkg/helpers"
	"log"
	"net/http"
	"strconv"
	"time"
)

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

// GetAccessToken mengambil access token dari cookie (untuk digunakan di API calls)
func GetAccessToken(r *http.Request) (string, error) {
	return helpers.GetCookie(r, "sso_access_token")
}
