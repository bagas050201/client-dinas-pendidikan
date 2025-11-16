package session

import (
	"bytes"
	"client-dinas-pendidikan/pkg/helpers"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

// getSupabaseURL returns SUPABASE_URL from environment
func getSupabaseURL() string {
	return os.Getenv("SUPABASE_URL")
}

// getSupabaseKey returns SUPABASE_KEY from environment
func getSupabaseKey() string {
	return os.Getenv("SUPABASE_KEY")
}

// CreateSession membuat session baru di database dan mengembalikan session ID
// Fungsi ini akan:
// 1. Generate session ID unik
// 2. Insert ke tabel sesi_login di Supabase
// 3. Return session ID untuk disimpan sebagai cookie
// Memerlukan env var: SUPABASE_URL, SUPABASE_KEY
func CreateSession(userID interface{}, r *http.Request) (sessionID string, err error) {
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
	// Schema: id (uuid), id_sesi (text), id_pengguna (uuid), created_at (timestamptz), kadaluarsa (timestamptz), ip (text), user_agent (text)
	// PENTING: Session ini dibuat oleh client website sendiri setelah user authorize via OAuth 2.0
	// Tidak perlu prefix karena session sudah terpisah (hanya dibuat oleh client website)
	expiresAt := time.Now().Add(24 * time.Hour)
	sessionData := map[string]interface{}{
		"id_pengguna": userID,                         // user_id → id_pengguna
		"id_sesi":     sessionID,                      // session_id → id_sesi (tanpa prefix)
		"ip":          getIPAddress(r),                // ip_address → ip
		"user_agent":  r.UserAgent(),                  // user_agent (sudah benar)
		"kadaluarsa":  expiresAt.Format(time.RFC3339), // expires_at → kadaluarsa
		// Tidak ada kolom "aktif" di schema, jadi tidak perlu
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
		log.Printf("ERROR detail - userID: %v (type: %T), sessionID: %s", userID, userID, sessionID)
		log.Printf("ERROR detail - sessionData: %+v", sessionData)
		return "", fmt.Errorf("gagal membuat session di database: status %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	log.Printf("✅ Session created: %s for user: %v", sessionID, userID)
	return sessionID, nil
}

// ValidateSession memvalidasi session ID dan mengembalikan user ID jika valid
// Fungsi ini akan:
// 1. Query tabel sesi_login di Supabase
// 2. Cek apakah session masih aktif dan belum expired
// 3. Return user_id jika valid, atau error jika tidak
// Memerlukan env var: SUPABASE_URL, SUPABASE_KEY
// PENTING: Session ini hanya dibuat oleh client website sendiri setelah OAuth 2.0 flow
// Tidak perlu cek prefix karena session sudah terpisah (hanya dibuat oleh client website)
func ValidateSession(sessionID string) (userID string, ok bool, err error) {
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
	// Schema: id_sesi (text), kadaluarsa (timestamptz), id_pengguna (uuid)
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
	// PENTING: Session ini hanya dibuat oleh client website sendiri setelah OAuth 2.0 flow
	// Tidak perlu cek prefix karena session sudah terpisah
	session := sessions[0]
	userIDVal := session["id_pengguna"]
	if userIDVal == nil {
		return "", false, fmt.Errorf("id_pengguna tidak ditemukan")
	}

	// Convert id_pengguna ke string
	userID = fmt.Sprintf("%v", userIDVal)
	return userID, true, nil
}

// ClearSession menghapus session di database (DELETE)
// Fungsi ini akan:
// 1. Delete row di tabel sesi_login berdasarkan id_sesi
// Memerlukan env var: SUPABASE_URL, SUPABASE_KEY
func ClearSession(sessionID string) error {
	supabaseURL := getSupabaseURL()
	supabaseKey := getSupabaseKey()
	if supabaseURL == "" || supabaseKey == "" {
		return fmt.Errorf("SUPABASE_URL atau SUPABASE_KEY tidak di-set")
	}

	if sessionID == "" {
		return fmt.Errorf("session ID kosong")
	}

	// DELETE session dari Supabase (tidak ada kolom aktif, jadi langsung delete)
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

// getIPAddress mendapatkan IP address dari request
func getIPAddress(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-Ip")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	// Ambil IP pertama jika ada multiple IPs
	for idx := 0; idx < len(ip); idx++ {
		if ip[idx] == ',' {
			return ip[:idx]
		}
	}
	return ip
}

