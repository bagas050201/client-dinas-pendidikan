package main

import (
	"html/template"
	"io"
)

// DashboardData holds the data to be rendered in the dashboard template
type DashboardData struct {
	LogoBase64       string
	AvatarInitial    string
	UserName         string
	UserEmail        string
	NRK              string
	UnitKerja        string
	RoleBadgeClass   string
	UserRole         string
	StatusBadgeClass string
	UserStatus       string
	JSONPayload      string
	WelcomeTitle     string
}

const dashboardHTML = `<!DOCTYPE html>
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
            padding: 4px 8px;
            border-radius: 8px;
            transition: background 0.2s;
        }
        .user-menu:hover {
            background: rgba(255,255,255,0.1);
        }
        .user-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: #3b82f6;
            color: white;
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
            background: linear-gradient(135deg, #3b82f6 0%, #1e40af 100%);
            color: white;
            border-radius: 12px;
            padding: 48px;
            margin-bottom: 32px;
            text-align: center;
        }
        .welcome-title {
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 8px;
        }
        .welcome-subtitle {
            font-size: 18px;
            opacity: 0.9;
        }
        .info-card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .info-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 24px;
        }
        .info-title {
            font-size: 18px;
            font-weight: 600;
            color: #1e293b;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 24px;
        }
        .info-item label {
            display: block;
            font-size: 12px;
            font-weight: 600;
            color: #64748b;
            margin-bottom: 4px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .info-item div {
            font-size: 16px;
            color: #1e293b;
            font-weight: 500;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            background: #dcfce7;
            color: #166534;
        }
        .status-badge.inactive {
            background: #fee2e2;
            color: #dc2626;
        }
        .role-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
        }
        .role-badge.user {
            background: #e0e7ff;
            color: #4338ca;
        }
        .role-badge.admin {
            background: #fef3c7;
            color: #92400e;
        }
        .role-badge.inactive {
            background: #e5e7eb;
            color: #4b5563;
        }
        .json-dump {
            background: #1e293b;
            color: #e2e8f0;
            padding: 16px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 12px;
            overflow-x: auto;
            margin-top: 16px;
            white-space: pre-wrap;
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
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-left">
            <img src="data:image/png;base64,{{.LogoBase64}}" alt="Logo" class="navbar-logo">
            <span class="navbar-title">Dinas Pendidikan DKI Jakarta</span>
        </div>
        <div class="navbar-right">
            <div class="user-menu">
                <div class="user-avatar">{{.AvatarInitial}}</div>
                <span id="headerUserName">{{.UserName}}</span>
            </div>
            <a href="/logout" class="btn-logout">Logout</a>
        </div>
    </nav>
    <div class="container">
        <div class="welcome-section">
            <h1 class="welcome-title" id="welcomeTitle">Selamat Datang, {{.UserName}}!</h1>
            <p class="welcome-subtitle">Dashboard Sistem Informasi Dinas Pendidikan</p>
        </div>
        <div class="info-card">
            <div class="info-header">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: #3b82f6;">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                    <circle cx="12" cy="7" r="4"></circle>
                </svg>
                <h2 class="info-title">Informasi User</h2>
            </div>
            <div class="info-grid">
                <div class="info-item">
                    <label>Nama Lengkap</label>
                    <div>{{.UserName}}</div>
                </div>
                <div class="info-item">
                    <label>Email</label>
                    <div>{{.UserEmail}}</div>
                </div>
                <div class="info-item">
                    <label>NRK</label>
                    <div>{{.NRK}}</div>
                </div>
                <div class="info-item">
                    <label>Unit Kerja</label>
                    <div>{{.UnitKerja}}</div>
                </div>
                <div class="info-item">
                    <label>Peran</label>
                    <div><span class="role-badge {{.RoleBadgeClass}}">{{.UserRole}}</span></div>
                </div>
                <div class="info-item">
                    <label>Status</label>
                    <div><span class="status-badge {{.StatusBadgeClass}}">{{.UserStatus}}</span></div>
                </div>
            </div>
        </div>

        <div class="info-card">
             <div class="info-header">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: #3b82f6;">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                    <polyline points="14 2 14 8 20 8"></polyline>
                    <line x1="16" y1="13" x2="8" y2="13"></line>
                    <line x1="16" y1="17" x2="8" y2="17"></line>
                    <polyline points="10 9 9 9 8 9"></polyline>
                </svg>
                <h2 class="info-title">Informasi Data User (Keycloak Payload)</h2>
            </div>
            <div class="json-dump">{{.JSONPayload}}</div>
        </div>

        <div class="actions-grid">

            <a href="/logout" class="action-card" style="background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); color: white;">
                <div class="action-title">🚪 Logout</div>
                <div class="action-desc">Keluar dari sistem SSO</div>
            </a>
        </div>
        
        <div style="margin-top: 24px; padding: 20px; background: #f0fdf4; border-left: 4px solid #22c55e; border-radius: 8px;">
            <p style="color: #166534; margin: 0; font-size: 14px;">
                ✅ <strong>Autentikasi SSO Berhasil!</strong> Anda telah login menggunakan Single Sign-On Keycloak.
            </p>
        </div>
    </div>

    <script>
        // Store SSO user info in sessionStorage for other pages
        const ssoUserInfo = {{.JSONPayload}};
        if (ssoUserInfo && Object.keys(ssoUserInfo).length > 0) {
            sessionStorage.setItem('sso_user_info', JSON.stringify(ssoUserInfo));
        }

        // Sync Logout Check (Periodic)
        function checkSession() {
            fetch('/auth/validate').then(res => {
                if (res.status === 401) window.location.reload();
            }).catch(e => console.error("Session check failed", e));
        }
        
        // Check on load
        checkSession();
        
        // Check every 30 seconds
        setInterval(checkSession, 30000);
        
        // Check on window focus
        window.addEventListener('focus', checkSession);
    </script>
</body>
</html>`

var dashboardTmpl = template.Must(template.New("dashboard").Parse(dashboardHTML))

// RenderDashboard renders the dashboard template
func RenderDashboard(w io.Writer, data DashboardData) error {
	return dashboardTmpl.Execute(w, data)
}
