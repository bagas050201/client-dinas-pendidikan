package helpers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Response represents a standard API response
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// WriteJSON writes a JSON response
func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// WriteError writes an error response
func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, Response{
		Success: false,
		Error:   message,
	})
}

// WriteSuccess writes a success response
func WriteSuccess(w http.ResponseWriter, message string, data interface{}) {
	WriteJSON(w, http.StatusOK, Response{
		Success: true,
		Message: message,
		Data:    data,
	})
}

// GenerateSessionID generates a random session ID
func GenerateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// SetCookie sets a secure HTTP cookie
// Secure: false untuk development (localhost), true untuk production (HTTPS)
// Auto-detect production berdasarkan request scheme (HTTPS) atau X-Forwarded-Proto header
func SetCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	// Deteksi apakah request dari HTTPS (production)
	// Vercel menggunakan X-Forwarded-Proto header
	isSecure := false
	if r != nil {
		// Cek X-Forwarded-Proto header (Vercel/Cloudflare/proxy)
		if proto := r.Header.Get("X-Forwarded-Proto"); proto == "https" {
			isSecure = true
		} else if r.TLS != nil {
			// Cek langsung dari TLS connection
			isSecure = true
		} else if r.URL != nil && r.URL.Scheme == "https" {
			// Cek dari URL scheme
			isSecure = true
		}
	}

	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   isSecure,             // true untuk HTTPS (production), false untuk HTTP (development)
		SameSite: http.SameSiteLaxMode, // Lax untuk compatibility yang lebih baik
	}
	http.SetCookie(w, cookie)
}

// GetCookie retrieves a cookie value
func GetCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

// ClearCookie removes a cookie
func ClearCookie(w http.ResponseWriter, r *http.Request, name string) {
	// Deteksi apakah request dari HTTPS (production)
	isSecure := false
	if r != nil {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto == "https" {
			isSecure = true
		} else if r.TLS != nil {
			isSecure = true
		} else if r.URL != nil && r.URL.Scheme == "https" {
			isSecure = true
		}
	}

	// Clear cookie dengan MaxAge: -1 untuk menghapus cookie
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Hapus cookie segera
		HttpOnly: true,
		Secure:   isSecure,             // true untuk HTTPS (production), false untuk HTTP (development)
		SameSite: http.SameSiteLaxMode, // Lax untuk compatibility yang lebih baik
	}
	http.SetCookie(w, cookie)

	// Juga set cookie dengan domain kosong untuk memastikan dihapus
	cookie2 := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie2)
}

// FormatTime formats a time to Indonesian format
func FormatTime(t time.Time) string {
	months := []string{
		"Januari", "Februari", "Maret", "April", "Mei", "Juni",
		"Juli", "Agustus", "September", "Oktober", "November", "Desember",
	}
	return fmt.Sprintf("%d %s %d", t.Day(), months[t.Month()-1], t.Year())
}

// ValidateEmail performs basic email validation
func ValidateEmail(email string) bool {
	if len(email) < 3 || len(email) > 254 {
		return false
	}
	atIndex := -1
	dotIndex := -1
	for i, char := range email {
		if char == '@' {
			if atIndex != -1 {
				return false
			}
			atIndex = i
		}
		if char == '.' && atIndex != -1 {
			dotIndex = i
		}
	}
	return atIndex > 0 && dotIndex > atIndex && dotIndex < len(email)-1
}

// SanitizeInput sanitizes user input
func SanitizeInput(input string) string {
	// Basic sanitization - remove null bytes and trim
	result := ""
	for _, char := range input {
		if char != 0 {
			result += string(char)
		}
	}
	return result
}
