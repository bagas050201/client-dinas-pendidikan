# Panduan Implementasi SSO untuk Website Client

> **Dokumentasi ini ditujukan untuk developer website client yang ingin mengintegrasikan dengan SSO Dinas Pendidikan**

## 📋 Daftar Isi

1. [Ringkasan Perubahan](#ringkasan-perubahan)
2. [Prasyarat](#prasyarat)
3. [Langkah-langkah Implementasi](#langkah-langkah-implementasi)
4. [Struktur Data JWT Baru](#struktur-data-jwt-baru)
5. [Contoh Kode](#contoh-kode)
6. [Testing & Debugging](#testing--debugging)
7. [Troubleshooting](#troubleshooting)

---

## 🎯 Ringkasan Perubahan

### Perubahan Utama dari Versi Sebelumnya:

1. **✅ URL Prefix Baru**: Semua endpoint SSO sekarang menggunakan `/sso-auth/` (sebelumnya `/auth/`)
2. **✅ Struktur JWT BKN-Style**: Data pengguna sekarang dalam format nested sesuai standar BKN
3. **✅ Multi-Identifier Login**: Support login dengan NIK, NIP, NRK, NUPTK, NPSN, NISN, NIKKI
4. **✅ Enhanced User Data**: Informasi lengkap termasuk hierarki organisasi, jabatan, pangkat, dll

---

## 📦 Prasyarat

Sebelum memulai, pastikan Anda memiliki:

- [ ] **Client ID** dan **Client Secret** dari tim SSO
- [ ] **Redirect URI** yang sudah didaftarkan di Keycloak
- [ ] **Base URL SSO**: `http://localhost:8080/sso-auth` (development) atau URL production
- [ ] Akses ke dokumentasi API SSO

---

## 🚀 Langkah-langkah Implementasi

### Step 1: Konfigurasi Environment Variables

Buat file `.env` di project Anda:

```bash
# SSO Configuration
SSO_BASE_URL=http://localhost:8080/sso-auth
SSO_REALM=dinas-pendidikan
SSO_CLIENT_ID=your-client-id
SSO_CLIENT_SECRET=your-client-secret
SSO_REDIRECT_URI=http://localhost:8070/login
SSO_LOGOUT_REDIRECT_URI=http://localhost:8070
```

### Step 2: Install Dependencies

#### Untuk Node.js/Express:
```bash
npm install axios jsonwebtoken dotenv
```

#### Untuk PHP:
```bash
composer require guzzlehttp/guzzle firebase/php-jwt vlucas/phpdotenv
```

#### Untuk Python/Flask:
```bash
pip install requests PyJWT python-dotenv
```

### Step 3: Implementasi OAuth Flow

Berikut adalah alur lengkap OAuth 2.0:

```
1. User klik "Login with SSO"
   ↓
2. Redirect ke SSO Login Page
   ↓
3. User masukkan credentials
   ↓
4. SSO redirect kembali dengan authorization code
   ↓
5. Exchange code untuk access token
   ↓
6. Fetch user info menggunakan access token
```

### Step 4: Implementasi True SSO (Auto-Login) ⭐ PENTING

Agar user tidak perlu login ulang jika sudah login di website lain (SSO), gunakan parameter `prompt=none`.

**Logic Flow:**
1. User buka website Anda.
2. Cek apakah ada session lokal?
   - ✅ Ada: Tampilkan dashboard.
   - ❌ Tidak: Redirect ke SSO dengan `prompt=none`.
3. Keycloak cek session:
   - ✅ Ada Session: Redirect balik dengan `code` -> **Auto Login Sukses!**
   - ❌ Tidak Ada: Redirect balik dengan `error=login_required`.
4. Jika error `login_required`:
   - Tampilkan tombol "Login dengan SSO" (atau redirect ke login page biasa).

**Contoh URL untuk Silent Check:**
```javascript
const authUrl = `${SSO_BASE_URL}/realms/${SSO_REALM}/protocol/openid-connect/auth`;
const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    prompt: 'none' // 👈 PARAMETER KUNCI
});
window.location.href = `${authUrl}?${params}`;
```

---

## 📊 Struktur Data JWT Baru

### Format JWT Token (BKN-Style Nested Structure)

```json
{
  "data": {
    "pengguna": {
      "id_pengguna": "5fb68603-da5f-4415-869e-07eab96dacf8",
      "nama": "NAMA",
      "email": "upt.pusdatin@jakarta.go.id",
      "email_terverifikasi": true
    },
    "identitas": {
      "nik": "3173010101900001",
      "nip": "198001012005011001",
      "nrk": "111111",
      "nuptk": "1234567890123456",
      "npsn": null,
      "nisn": null,
      "nikki": null
    },
    "jabatan": {
      "level": "Super Admin",
      "role": "UPT Pusdatin"
    },
    "organisasi": {
      "dinas_id": null,
      "dinas_nama": "Dinas Pendidikan Provinsi DKI Jakarta",
      "group": "PUSAT DATA DAN TEKNOLOGI INFORMASI PENDIDIKAN",
      "kode_dinas": "31.73.01.001",
      "nama_satuan_kerja": "Pusat Data",
      "tipe_satuan_kerja": "UPT"
    },
    "kepegawaian": {
      "pangkat": "Pembina (IV/a)",
      "golongan": "IV/a",
      "tmt_cpns": "2005-01-01",
      "tmt_pns": "2007-01-01",
      "status_pegawai": "AKTIF",
      "jenis_pegawai": "PNS"
    },
    "validasi": {
      "is_active": true,
      "updated_at": "2025-12-11T01:19:30Z"
    }
  },
  "iat": 1765417170,
  "exp": 1765417770
}
```

### Perbedaan dengan Format Lama:

| Aspek | Format Lama (❌) | Format Baru (✅) |
|-------|-----------------|-----------------|
| Struktur | Flat (semua field di root level) | Nested (dikelompokkan berdasarkan domain) |
| Nama Field | Campuran (camelCase, snake_case) | Konsisten (snake_case) |
| URL Prefix | `/auth/` | `/sso-auth/` |
| User ID | `userId` atau `uuid` | `data.pengguna.id_pengguna` |
| Email | `email` | `data.pengguna.email` |
| Role | `role` | `data.jabatan.role` |
| Level | `level` | `data.jabatan.level` |

---

## 💻 Contoh Kode

### 1. Node.js/Express Implementation

#### `routes/auth.js`
```javascript
const express = require('express');
const axios = require('axios');
const router = express.Router();

// Konfigurasi SSO
const SSO_CONFIG = {
  baseUrl: process.env.SSO_BASE_URL,
  realm: process.env.SSO_REALM,
  clientId: process.env.SSO_CLIENT_ID,
  clientSecret: process.env.SSO_CLIENT_SECRET,
  redirectUri: process.env.SSO_REDIRECT_URI,
};

// GET: Silent SSO Check (Auto-Login)
router.get('/sso-check', (req, res) => {
  const authUrl = `${SSO_CONFIG.baseUrl}/realms/${SSO_CONFIG.realm}/protocol/openid-connect/auth`;
  const params = new URLSearchParams({
    client_id: SSO_CONFIG.clientId,
    redirect_uri: SSO_CONFIG.redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    prompt: 'none' // Silent check
  });
  res.redirect(`${authUrl}?${params}`);
});

// GET: Manual Login (Tombol Click)
router.get('/login', (req, res) => {
  const authUrl = `${SSO_CONFIG.baseUrl}/realms/${SSO_CONFIG.realm}/protocol/openid-connect/auth`;
  const params = new URLSearchParams({
    client_id: SSO_CONFIG.clientId,
    redirect_uri: SSO_CONFIG.redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    // Tanpa prompt=none
  });
  res.redirect(`${authUrl}?${params}`);
});

// GET: Callback dari SSO
router.get('/callback', async (req, res) => {
  const { code, error } = req.query;
  
  // Handle Silent Login Failure
  if (error === 'login_required') {
    return res.redirect('/login-page'); // Redirect ke halaman landing/login local
  }

  if (!code) {
    return res.status(400).json({ error: 'Authorization code missing' });
  }
  
  try {
    // 1. Exchange code untuk token
    const tokenUrl = `${SSO_CONFIG.baseUrl}/realms/${SSO_CONFIG.realm}/protocol/openid-connect/token`;
    const tokenResponse = await axios.post(tokenUrl, new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: SSO_CONFIG.redirectUri,
      client_id: SSO_CONFIG.clientId,
      client_secret: SSO_CONFIG.clientSecret,
    }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    
    const { access_token, refresh_token } = tokenResponse.data;
    
    // 2. Fetch user info
    const userInfoUrl = `${SSO_CONFIG.baseUrl}/realms/${SSO_CONFIG.realm}/protocol/openid-connect/userinfo`;
    const userInfoResponse = await axios.get(userInfoUrl, {
      headers: { 'Authorization': `Bearer ${access_token}` }
    });
    
    const userData = userInfoResponse.data;
    
    // 3. Simpan session (gunakan struktur nested baru)
    req.session.user = {
      id: userData.data.pengguna.id_pengguna,
      nama: userData.data.pengguna.nama,
      email: userData.data.pengguna.email,
      role: userData.data.jabatan.role,
      level: userData.data.jabatan.level,
      dinas: userData.data.organisasi.dinas_nama,
      group: userData.data.organisasi.group,
      // Simpan identitas
      nik: userData.data.identitas.nik,
      nip: userData.data.identitas.nip,
      nrk: userData.data.identitas.nrk,
      // Simpan kepegawaian
      pangkat: userData.data.kepegawaian.pangkat,
      golongan: userData.data.kepegawaian.golongan,
      status: userData.data.kepegawaian.status_pegawai,
    };
    
    req.session.tokens = {
      access_token,
      refresh_token,
    };
    
    // 4. Redirect ke dashboard
    res.redirect('/dashboard');
    
  } catch (error) {
    console.error('SSO Login Error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Login failed', 
      details: error.response?.data 
    });
  }
});

// GET: Logout
router.get('/logout', async (req, res) => {
  const { access_token } = req.session.tokens || {};
  
  // 1. Logout dari Keycloak
  if (access_token) {
    try {
      const logoutUrl = `${SSO_CONFIG.baseUrl}/realms/${SSO_CONFIG.realm}/protocol/openid-connect/logout`;
      await axios.post(logoutUrl, new URLSearchParams({
        client_id: SSO_CONFIG.clientId,
        client_secret: SSO_CONFIG.clientSecret,
        refresh_token: req.session.tokens.refresh_token,
      }), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
    } catch (error) {
      console.error('Keycloak logout error:', error.message);
    }
  }
  
  // 2. Destroy session
  req.session.destroy();
  
  // 3. Redirect ke halaman login
  res.redirect('/');
});

module.exports = router;
```

#### `middleware/auth.js`
```javascript
// Middleware untuk proteksi route
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/auth/login');
  }
  next();
}

// Middleware untuk role-based access
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    const userRole = req.session.user?.role;
    if (!allowedRoles.includes(userRole)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  };
}

module.exports = { requireAuth, requireRole };
```

#### `app.js`
```javascript
const express = require('express');
const session = require('express-session');
const authRoutes = require('./routes/auth');
const { requireAuth } = require('./middleware/auth');

const app = express();

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Routes
app.use('/auth', authRoutes);

// Protected route example
app.get('/dashboard', requireAuth, (req, res) => {
  res.json({
    message: 'Welcome to dashboard',
    user: req.session.user
  });
});

app.listen(8070, () => {
  console.log('App running on http://localhost:8070');
});
```

---

### 2. PHP Implementation

#### `config/sso.php`
```php
<?php
return [
    'base_url' => getenv('SSO_BASE_URL'),
    'realm' => getenv('SSO_REALM'),
    'client_id' => getenv('SSO_CLIENT_ID'),
    'client_secret' => getenv('SSO_CLIENT_SECRET'),
    'redirect_uri' => getenv('SSO_REDIRECT_URI'),
];
```

#### `SSOClient.php`
```php
<?php
require 'vendor/autoload.php';

use GuzzleHttp\Client;

class SSOClient {
    private $config;
    private $httpClient;
    
    public function __construct($config) {
        $this->config = $config;
        $this->httpClient = new Client();
    }
    
    public function getLoginUrl($silent = false) {
        $params = [
            'client_id' => $this->config['client_id'],
            'redirect_uri' => $this->config['redirect_uri'],
            'response_type' => 'code',
            'scope' => 'openid email profile',
        ];

        if ($silent) {
            $params['prompt'] = 'none';
        }
        
        return sprintf(
            '%s/realms/%s/protocol/openid-connect/auth?%s',
            $this->config['base_url'],
            $this->config['realm'],
            http_build_query($params)
        );
    }
    
    public function exchangeCode($code) {
        $tokenUrl = sprintf(
            '%s/realms/%s/protocol/openid-connect/token',
            $this->config['base_url'],
            $this->config['realm']
        );
        
        $response = $this->httpClient->post($tokenUrl, [
            'form_params' => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->config['redirect_uri'],
                'client_id' => $this->config['client_id'],
                'client_secret' => $this->config['client_secret'],
            ]
        ]);
        
        return json_decode($response->getBody(), true);
    }
    
    public function getUserInfo($accessToken) {
        $userInfoUrl = sprintf(
            '%s/realms/%s/protocol/openid-connect/userinfo',
            $this->config['base_url'],
            $this->config['realm']
        );
        
        $response = $this->httpClient->get($userInfoUrl, [
            'headers' => [
                'Authorization' => 'Bearer ' . $accessToken
            ]
        ]);
        
        return json_decode($response->getBody(), true);
    }
    
    public function logout($refreshToken) {
        $logoutUrl = sprintf(
            '%s/realms/%s/protocol/openid-connect/logout',
            $this->config['base_url'],
            $this->config['realm']
        );
        
        $this->httpClient->post($logoutUrl, [
            'form_params' => [
                'client_id' => $this->config['client_id'],
                'client_secret' => $this->config['client_secret'],
                'refresh_token' => $refreshToken,
            ]
        ]);
    }
}
```

#### `login.php`
```php
<?php
session_start();
require 'config/sso.php';
require 'SSOClient.php';

$ssoConfig = include 'config/sso.php';
$ssoClient = new SSOClient($ssoConfig);

if (isset($_GET['code'])) {
    // Callback dari SSO
    try {
        // 1. Exchange code untuk token
        $tokens = $ssoClient->exchangeCode($_GET['code']);
        
        // 2. Fetch user info
        $userInfo = $ssoClient->getUserInfo($tokens['access_token']);
        
        // 3. Simpan session (gunakan struktur nested baru)
        $_SESSION['user'] = [
            'id' => $userInfo['data']['pengguna']['id_pengguna'],
            'nama' => $userInfo['data']['pengguna']['nama'],
            'email' => $userInfo['data']['pengguna']['email'],
            'role' => $userInfo['data']['jabatan']['role'],
            'level' => $userInfo['data']['jabatan']['level'],
            'dinas' => $userInfo['data']['organisasi']['dinas_nama'],
            'group' => $userInfo['data']['organisasi']['group'],
            'nik' => $userInfo['data']['identitas']['nik'],
            'nip' => $userInfo['data']['identitas']['nip'],
            'pangkat' => $userInfo['data']['kepegawaian']['pangkat'],
        ];
        
        $_SESSION['tokens'] = [
            'access_token' => $tokens['access_token'],
            'refresh_token' => $tokens['refresh_token'],
        ];
        
        // 4. Redirect ke dashboard
        header('Location: /dashboard.php');
        exit;
        
    } catch (Exception $e) {
        die('Login failed: ' . $e->getMessage());
    }
} else {
    // Redirect ke SSO login
    header('Location: ' . $ssoClient->getLoginUrl());
    exit;
}
```

---

### 3. Python/Flask Implementation

#### `sso_client.py`
```python
import os
import requests
from urllib.parse import urlencode

class SSOClient:
    def __init__(self):
        self.base_url = os.getenv('SSO_BASE_URL')
        self.realm = os.getenv('SSO_REALM')
        self.client_id = os.getenv('SSO_CLIENT_ID')
        self.client_secret = os.getenv('SSO_CLIENT_SECRET')
        self.redirect_uri = os.getenv('SSO_REDIRECT_URI')
    
    def get_login_url(self):
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': 'openid email profile',
        }
        auth_url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/auth"
        return f"{auth_url}?{urlencode(params)}"
    
    def exchange_code(self, code):
        token_url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token"
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }
        response = requests.post(token_url, data=data)
        response.raise_for_status()
        return response.json()
    
    def get_user_info(self, access_token):
        userinfo_url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/userinfo"
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(userinfo_url, headers=headers)
        response.raise_for_status()
        return response.json()
    
    def logout(self, refresh_token):
        logout_url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/logout"
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': refresh_token,
        }
        requests.post(logout_url, data=data)
```

#### `app.py`
```python
from flask import Flask, redirect, request, session, jsonify
from sso_client import SSOClient
from functools import wraps

app = Flask(__name__)
app.secret_key = os.getenv('SESSION_SECRET', 'your-secret-key')

sso = SSOClient()

# Middleware untuk proteksi route
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect('/auth/login')
        return f(*args, **kwargs)
    return decorated_function

@app.route('/auth/login')
def login():
    return redirect(sso.get_login_url())

@app.route('/auth/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return jsonify({'error': 'Authorization code missing'}), 400
    
    try:
        # 1. Exchange code untuk token
        tokens = sso.exchange_code(code)
        
        # 2. Fetch user info
        user_info = sso.get_user_info(tokens['access_token'])
        
        # 3. Simpan session (gunakan struktur nested baru)
        session['user'] = {
            'id': user_info['data']['pengguna']['id_pengguna'],
            'nama' => user_info['data']['pengguna']['nama'],
            'email': user_info['data']['pengguna']['email'],
            'role': user_info['data']['jabatan']['role'],
            'level': user_info['data']['jabatan']['level'],
            'dinas': user_info['data']['organisasi']['dinas_nama'],
            'group': user_info['data']['organisasi']['group'],
            'nik': user_info['data']['identitas']['nik'],
            'nip': user_info['data']['identitas']['nip'],
            'pangkat': user_info['data']['kepegawaian']['pangkat'],
        }
        
        session['tokens'] = {
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token'],
        }
        
        # 4. Redirect ke dashboard
        return redirect('/dashboard')
        
    except Exception as e:
        return jsonify({'error': 'Login failed', 'details': str(e)}), 500

@app.route('/auth/logout')
def logout():
    if 'tokens' in session:
        try:
            sso.logout(session['tokens']['refresh_token'])
        except:
            pass
    
    session.clear()
    return redirect('/')

@app.route('/dashboard')
@require_auth
def dashboard():
    return jsonify({
        'message': 'Welcome to dashboard',
        'user': session['user']
    })

if __name__ == '__main__':
    app.run(port=8070, debug=True)
```

---

### 4. Frontend JavaScript (Vanilla JS)

#### `login.html`
```html
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Dinas Pendidikan</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="login-container">
        <div class="login-card">
            <img src="logo.png" alt="Logo Dinas Pendidikan" class="logo">
            <h1>Dinas Pendidikan</h1>
            <p>Silakan login menggunakan SSO</p>
            
            <button id="sso-login-btn" class="btn-primary">
                <svg><!-- Icon --></svg>
                Login dengan SSO
            </button>
            
            <div class="info">
                <p>Gunakan salah satu identifier berikut:</p>
                <ul>
                    <li>NIK</li>
                    <li>NIP</li>
                    <li>NRK</li>
                    <li>NUPTK</li>
                    <li>NPSN (untuk sekolah)</li>
                    <li>NISN (untuk siswa)</li>
                    <li>NIKKI</li>
                    <li>Username</li>
                    <li>Email</li>
                </ul>
            </div>
        </div>
    </div>
    
    <script>
        document.getElementById('sso-login-btn').addEventListener('click', function() {
            // Redirect ke backend /auth/login yang akan redirect ke Keycloak
            window.location.href = '/auth/login';
        });
    </script>
</body>
</html>
```

#### `dashboard.html`
```html
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Dinas Pendidikan</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <nav class="navbar">
        <div class="nav-brand">Dinas Pendidikan</div>
        <div class="nav-menu">
            <span id="user-name">Loading...</span>
            <button id="logout-btn" class="btn-secondary">Logout</button>
        </div>
    </nav>
    
    <div class="container">
        <div class="user-card">
            <h2>Profil Pengguna</h2>
            <div id="user-info">
                <!-- Will be populated by JavaScript -->
            </div>
        </div>
    </div>
    
    <script src="dashboard.js"></script>
</body>
</html>
```

#### `dashboard.js`
```javascript
// Fetch user data from session/API
async function loadUserInfo() {
    try {
        const response = await fetch('/api/user', {
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error('Failed to fetch user info');
        }
        
        const data = await response.json();
        const user = data.user;
        
        // Update UI dengan struktur data baru
        document.getElementById('user-name').textContent = user.nama;
        
        const userInfoHtml = `
            <div class="info-group">
                <h3>Informasi Pribadi</h3>
                <p><strong>Nama:</strong> ${user.nama}</p>
                <p><strong>Email:</strong> ${user.email}</p>
                <p><strong>NIK:</strong> ${user.nik || '-'}</p>
                <p><strong>NIP:</strong> ${user.nip || '-'}</p>
                <p><strong>NRK:</strong> ${user.nrk || '-'}</p>
            </div>
            
            <div class="info-group">
                <h3>Jabatan</h3>
                <p><strong>Role:</strong> ${user.role}</p>
                <p><strong>Level:</strong> ${user.level}</p>
            </div>
            
            <div class="info-group">
                <h3>Organisasi</h3>
                <p><strong>Dinas:</strong> ${user.dinas}</p>
                <p><strong>Group:</strong> ${user.group}</p>
            </div>
            
            <div class="info-group">
                <h3>Kepegawaian</h3>
                <p><strong>Pangkat:</strong> ${user.pangkat || '-'}</p>
                <p><strong>Golongan:</strong> ${user.golongan || '-'}</p>
                <p><strong>Status:</strong> ${user.status || '-'}</p>
            </div>
        `;
        
        document.getElementById('user-info').innerHTML = userInfoHtml;
        
    } catch (error) {
        console.error('Error loading user info:', error);
        // Redirect to login if session expired
        window.location.href = '/auth/login';
    }
}

// Logout handler
document.getElementById('logout-btn').addEventListener('click', function() {
    if (confirm('Apakah Anda yakin ingin logout?')) {
        window.location.href = '/auth/logout';
    }
});

// Load user info on page load
loadUserInfo();
```

---

## 🧪 Testing & Debugging

### 1. Test Login Flow
```bash
# 1. Buka browser ke halaman login
open http://localhost:8070

# 2. Klik "Login with SSO"

# 3. Masukkan credentials:
# Username: 111111 (atau NIK/NIP/NRK lainnya)
# Password: password

# 4. Setelah login sukses, cek session
```

### 2. Inspect JWT Token

Tambahkan endpoint untuk debug token (hapus di production!):

```javascript
app.get('/debug/token', requireAuth, (req, res) => {
  res.json({
    session: req.session,
    user: req.session.user,
    tokens: {
      access_token: req.session.tokens?.access_token,
      // Decode JWT untuk melihat payload
      decoded: jwt.decode(req.session.tokens?.access_token)
    }
  });
});
```

### 3. Test dengan Curl

```bash
# 1. Get Authorization Code
curl -v "http://localhost:8080/sso-auth/realms/dinas-pendidikan/protocol/openid-connect/auth?client_id=your-client-id&redirect_uri=http://localhost:8070/login&response_type=code&scope=openid"

# 2. Exchange Code untuk Token
curl -X POST "http://localhost:8080/sso-auth/realms/dinas-pendidikan/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTH_CODE" \
  -d "redirect_uri=http://localhost:8070/login" \
  -d "client_id=your-client-id" \
  -d "client_secret=your-client-secret"

# 3. Get User Info
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  "http://localhost:8080/sso-auth/realms/dinas-pendidikan/protocol/openid-connect/userinfo"
```

---

## ❗ Troubleshooting

### Problem 1: "Invalid redirect URI"
**Penyebab:** Redirect URI tidak terdaftar di Keycloak  
**Solusi:**
1. Login ke Keycloak Admin Console
2. Pilih Client Anda
3. Tambahkan redirect URI yang sesuai
4. Pastikan exact match (termasuk trailing slash)

### Problem 2: "Unauthorized Client"
**Penyebab:** Client secret salah atau client type salah  
**Solusi:**
1. Cek `client_secret` di environment variables
2. Pastikan client type = "confidential" di Keycloak
3. Enable "Standard Flow" di client settings

### Problem 3: "Cookie not found"
**Penyebab:** SameSite policy di browser  
**Solusi (Development):**
```javascript
// Set cookie options
cookie: {
  secure: false, // Set true di production dengan HTTPS
  sameSite: 'lax',
  httpOnly: true
}
```

### Problem 4: Data structure tidak sesuai
**Penyebab:** Menggunakan struktur lama (flat)  
**Solusi:** Update kode untuk menggunakan struktur nested:

```javascript
// ❌ Cara Lama
const userId = userData.userId;
const email = userData.email;

// ✅ Cara Baru
const userId = userData.data.pengguna.id_pengguna;
const email = userData.data.pengguna.email;
```

### Problem 5: Token expired
**Penyebab:** Access token expire setelah beberapa menit  
**Solusi:** Implement token refresh:

```javascript
async function refreshAccessToken(refreshToken) {
  const tokenUrl = `${SSO_BASE_URL}/realms/${REALM}/protocol/openid-connect/token`;
  const response = await axios.post(tokenUrl, new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
  }));
  
  return response.data;
}

// Gunakan middleware untuk auto-refresh
app.use(async (req, res, next) => {
  if (req.session.tokens) {
    const decoded = jwt.decode(req.session.tokens.access_token);
    const now = Math.floor(Date.now() / 1000);
    
    // Refresh jika token akan expire dalam 5 menit
    if (decoded.exp - now < 300) {
      try {
        const newTokens = await refreshAccessToken(req.session.tokens.refresh_token);
        req.session.tokens = newTokens;
      } catch (error) {
        console.error('Token refresh failed:', error);
        return res.redirect('/auth/login');
      }
    }
  }
  next();
});
```

---

## 📞 Support

Jika Anda mengalami masalah atau butuh bantuan:

1. **Dokumentasi Lengkap**: Lihat `CLIENT-INTEGRATION-GUIDE.md`
2. **API Reference**: Lihat `API-REFERENCE.md`
3. **Keycloak Setup**: Lihat `KEYCLOAK_CLIENT_SETUP.md`
4. **Docker Architecture**: Lihat `DOCKER-ARCHITECTURE.md`

**Kontak Tim SSO:**
- Email: upt.pusdatin@jakarta.go.id
- GitLab Issues: [Repository URL]

---

## 📝 Checklist Implementasi

Sebelum go-live, pastikan semua item berikut sudah selesai:

- [ ] Environment variables sudah dikonfigurasi
- [ ] Client ID dan Secret sudah didapat dari tim SSO
- [ ] Redirect URI sudah didaftarkan di Keycloak
- [ ] OAuth flow sudah diimplementasi dengan benar
- [ ] Data structure menggunakan format nested baru
- [ ] Session management sudah diterapkan
- [ ] Logout flow sudah berfungsi
- [ ] Error handling sudah lengkap
- [ ] Token refresh sudah diimplementasi
- [ ] Testing sudah dilakukan di development
- [ ] Security headers sudah diterapkan (HTTPS, CSP, dll)
- [ ] Logging sudah disetup untuk debugging
- [ ] Documentation untuk tim internal sudah dibuat

---

**Good luck dengan implementasi SSO! 🚀**
