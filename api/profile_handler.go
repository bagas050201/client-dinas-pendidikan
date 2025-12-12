package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"client-dinas-pendidikan/pkg/helpers"
)

// ProfileHandler menampilkan halaman profil user (Read-Only)
// Data user diambil dari session yang sudah tervalidasi
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Cek session
	sessionID, err := helpers.GetCookie(r, "client_dinas_session")
	if err != nil {
		sessionID, err = helpers.GetCookie(r, "session_id")
	}
	if err != nil || sessionID == "" {
		log.Printf("WARNING: No session cookie found, redirecting to login")
		http.Redirect(w, r, "/login?next=/profile", http.StatusSeeOther)
		return
	}

	// Validasi session dan ambil userID
	userID, ok, err := validateSession(sessionID)
	if !ok || err != nil {
		log.Printf("WARNING: Invalid session: %v, error: %v", ok, err)
		helpers.ClearCookie(w, r, "client_dinas_session")
		helpers.ClearCookie(w, r, "session_id")
		http.Redirect(w, r, "/login?next=/profile", http.StatusSeeOther)
		return
	}

	// Coba ambil data user dari ID token SSO
	ssoIDToken, _ := helpers.GetCookie(r, "sso_id_token")
	var userInfo map[string]interface{}

	if ssoIDToken != "" {
		// Parse ID token untuk ambil user info
		userInfo, err = getUserInfoFromIDToken(ssoIDToken)
		if err != nil {
			log.Printf("WARNING: Failed to parse ID token: %v", err)
		}
	}

	// Jika tidak bisa dari Keycloak, coba dari database
	if userInfo == nil {
		userInfo, err = getUserBySSOIdentifier(userID)
		if err != nil {
			log.Printf("WARNING: Failed to get user from DB: %v, using basic info", err)
			// Fallback: buat user info minimal dari userID
			userInfo = map[string]interface{}{
				"id":           userID,
				"nama_lengkap": userID,
				"email":        "",
				"peran":        "user",
			}
		}
	}

	// Render halaman profil
	renderProfilePageNew(w, userInfo)
}

// renderProfilePageNew menampilkan halaman profil (Read-Only)
func renderProfilePageNew(w http.ResponseWriter, user map[string]interface{}) {
	logoBase64 := base64.StdEncoding.EncodeToString(LogoData)

	// Ambil data user dengan fallback
	namaLengkap := getProfileStringValue(user, "nama_lengkap", "name", "fullname", "preferred_username")
	email := getProfileStringValue(user, "email")
	peran := getProfileStringValue(user, "peran", "role", "role_id")

	if namaLengkap == "" {
		namaLengkap = "User"
	}
	if peran == "" {
		peran = "user"
	}

	// Ambil initial untuk avatar
	initial := "U"
	if len(namaLengkap) > 0 {
		initial = string([]rune(namaLengkap)[0])
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
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
        }
        .navbar {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            color: white;
            padding: 16px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .navbar-left {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .navbar-logo {
            height: 40px;
            border-radius: 8px;
        }
        .navbar-title {
            font-size: 18px;
            font-weight: 600;
        }
        .navbar-right {
            display: flex;
            gap: 8px;
        }
        .navbar-right a {
            color: white;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 8px;
            transition: all 0.3s;
            font-weight: 500;
        }
        .navbar-right a:hover {
            background: rgba(255,255,255,0.2);
        }
        .navbar-right a.logout-btn {
            background: rgba(239, 68, 68, 0.8);
        }
        .navbar-right a.logout-btn:hover {
            background: rgba(239, 68, 68, 1);
        }
        .container {
            max-width: 700px;
            margin: 40px auto;
            padding: 0 24px;
        }
        .profile-card {
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.2);
        }
        .profile-header {
            text-align: center;
            margin-bottom: 40px;
        }
        .profile-avatar {
            width: 100px;
            height: 100px;
            border-radius: 50%%;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            font-size: 40px;
            color: white;
            font-weight: 600;
        }
        .profile-title {
            font-size: 28px;
            font-weight: 700;
            color: #1e293b;
            margin-bottom: 8px;
        }
        .profile-subtitle {
            color: #64748b;
            font-size: 16px;
        }
        .info-box {
            background: #eff6ff;
            border-left: 4px solid #3b82f6;
            padding: 16px 20px;
            margin-bottom: 30px;
            border-radius: 0 8px 8px 0;
        }
        .info-box p {
            color: #1e40af;
            margin: 0;
            font-size: 14px;
            line-height: 1.5;
        }
        .form-group {
            margin-bottom: 24px;
        }
        .form-group label {
            display: block;
            color: #374151;
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 8px;
        }
        .form-group input {
            width: 100%%;
            padding: 14px 18px;
            border: 2px solid #e5e7eb;
            border-radius: 10px;
            font-size: 16px;
            background: #f9fafb;
            color: #374151;
            cursor: not-allowed;
        }
        .form-group input:disabled {
            background: #f3f4f6;
            color: #6b7280;
        }
        .badge {
            display: inline-block;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-role {
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            color: white;
        }
        .back-btn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            color: #6366f1;
            text-decoration: none;
            font-weight: 600;
            margin-top: 20px;
            padding: 12px 24px;
            border-radius: 10px;
            transition: all 0.3s;
        }
        .back-btn:hover {
            background: #f0f0ff;
        }
        @media (max-width: 768px) {
            .container { padding: 16px; margin: 20px auto; }
            .profile-card { padding: 24px; }
            .navbar { flex-direction: column; gap: 12px; }
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
            <a href="/logout" class="logout-btn">Logout</a>
        </div>
    </nav>
    
    <div class="container">
        <div class="profile-card">
            <div class="profile-header">
                <div class="profile-avatar">%s</div>
                <h1 class="profile-title">Profil Saya</h1>
                <p class="profile-subtitle">Data akun Anda yang terdaftar di sistem SSO</p>
            </div>
            
            <div class="info-box">
                <p>
                    <strong>ℹ️ Info:</strong> Data profil Anda dikelola secara terpusat melalui sistem SSO Keycloak. 
                    Untuk mengubah data, silakan hubungi administrator atau akses portal SSO.
                </p>
            </div>
            
            <div class="form-group">
                <label>Nama Lengkap</label>
                <input type="text" value="%s" disabled>
            </div>
            
            <div class="form-group">
                <label>Email</label>
                <input type="email" value="%s" disabled>
            </div>
            
            <div class="form-group">
                <label>Peran</label>
                <span class="badge badge-role">%s</span>
            </div>
            
            <a href="/dashboard" class="back-btn">
                ← Kembali ke Dashboard
            </a>
        </div>
    </div>
    
    <script>
        // Update dari sessionStorage jika ada
        (function() {
            try {
                const ssoData = sessionStorage.getItem('sso_user_info');
                if (ssoData) {
                    const user = JSON.parse(ssoData);
                    console.log('✅ SSO User Info:', user);
                }
            } catch (e) {
                console.error('Error:', e);
            }
        })();
    </script>
</body>
</html>`, logoBase64, initial, namaLengkap, email, peran)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// getProfileStringValue mengambil nilai string dari map dengan fallback keys
func getProfileStringValue(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if val, ok := m[key]; ok {
			if str, ok := val.(string); ok && str != "" {
				return str
			}
		}
	}
	return ""
}
