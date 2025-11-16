package api

import (
	"bytes"
	"client-dinas-pendidikan/api/session"
	"client-dinas-pendidikan/pkg/helpers"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
)

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

