package api

import (
	"client-dinas-pendidikan/internal"
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
		userID, ok, _ = internal.ValidateSession(sessionID)
	}

	// Ambil data user jika session ada
	var user map[string]interface{}
	if ok && userID != "" {
		user, err = getUserByID(userID)
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

// getDashboardCounts mengambil jumlah pengguna, aplikasi, sessions, dan tokens
func getDashboardCounts() (map[string]int, error) {
	supabaseURL := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_KEY")
	if supabaseURL == "" || supabaseKey == "" {
		return nil, fmt.Errorf("SUPABASE_URL atau SUPABASE_KEY tidak di-set")
	}

	counts := make(map[string]int)

	// Count pengguna
	// Schema: id_pengguna adalah primary key
	apiURL := fmt.Sprintf("%s/rest/v1/pengguna?select=id_pengguna&limit=1", supabaseURL)
	httpReq, _ := http.NewRequest("HEAD", apiURL, nil)
	httpReq.Header.Set("apikey", supabaseKey)
	httpReq.Header.Set("Authorization", "Bearer "+supabaseKey)
	httpReq.Header.Set("Prefer", "count=exact")
	resp, err := http.DefaultClient.Do(httpReq)
	if err == nil {
		if countHeader := resp.Header.Get("Content-Range"); countHeader != "" {
			// Parse Content-Range header jika ada
			// Format: "0-0/100" -> ambil angka terakhir
		}
		resp.Body.Close()
	}

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
