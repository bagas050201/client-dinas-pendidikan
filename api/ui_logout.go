package api

import (
	"client-dinas-pendidikan/internal"
	"client-dinas-pendidikan/pkg/helpers"
	"log"
	"net/http"
)

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
		if err := internal.ClearSession(sessionID); err != nil {
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
