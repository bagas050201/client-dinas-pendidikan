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
	"os"
)

// InfoDinasHandler menampilkan halaman Informasi Dinas Pendidikan
// Protected route: hanya bisa diakses oleh user yang sudah login
// Menampilkan:
// - Hero/title "Selamat Datang di SSO Dinas Pendidikan"
// - Section "Aplikasi Terhubung": fetch dari aplikasi_terdaftar (jika ada) atau demo data
// - Section "Tentang Dinas": static teks + kontak CP
// - Section "Data Sekolah (demo)": fetch dari data_sekolah (limit 10) atau demo data
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
	_, ok, err := internal.ValidateSession(sessionID)
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
			"nama":     "SDN 01 Jakarta Pusat",
			"alamat":   "Jl. Merdeka No. 1, Jakarta Pusat",
			"jenis":    "SD",
			"status":   "Negeri",
			"kecamatan": "Gambir",
		},
		{
			"nama":     "SMPN 15 Jakarta Selatan",
			"alamat":   "Jl. Kebayoran Baru, Jakarta Selatan",
			"jenis":    "SMP",
			"status":   "Negeri",
			"kecamatan": "Kebayoran Baru",
		},
		{
			"nama":     "SMAN 28 Jakarta",
			"alamat":   "Jl. Raya Pasar Minggu, Jakarta Selatan",
			"jenis":    "SMA",
			"status":   "Negeri",
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

