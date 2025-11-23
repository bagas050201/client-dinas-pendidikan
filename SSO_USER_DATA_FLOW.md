# Flow Mendapatkan Data User dari SSO dan Menampilkannya

## 📋 Overview

Dokumen ini menjelaskan bagaimana website client mendapatkan data user dari SSO Keycloak dan menampilkannya di halaman website.

## 🔄 Flow Lengkap

### **STEP 1: Website SSO Mengirim Token**

Ketika user klik aplikasi di Portal SSO, website SSO akan redirect ke website client dengan token di URL:

```
localhost:8070/login?sso_token=<JWT_TOKEN>&sso_id_token=<ID_TOKEN>&sso_client_id=localhost-8070-website-dinas-pendidikan
```

**File:** `api/main_handler.go` (line ~83-94)
- Handler root path (`/`) detect `sso_token` di URL
- Redirect ke `/login` dengan parameter token

---

### **STEP 2: Frontend Decode JWT Token**

Script `sso-handler.js` otomatis detect token saat page load dan decode JWT untuk extract user info.

**File:** `api/static/sso-handler.js` (line ~25-73)

```javascript
// 1. Detect token dari URL
const ssoToken = urlParams.get('sso_token');

// 2. Decode JWT token
const userInfo = await verifyToken(ssoToken);
```

**File:** `api/static/sso-handler.js` (line ~103-139)

```javascript
function decodeJWTToken(token) {
    // Decode JWT payload (base64url)
    const decoded = JSON.parse(atob(padded));
    
    // Extract user info dari JWT claims
    const userInfo = {
        sub: decoded.sub,              // User ID dari Keycloak
        email: decoded.email,           // Email user
        name: decoded.name,             // Nama lengkap
        preferred_username: decoded.preferred_username,
        email_verified: decoded.email_verified,
        peran: decoded.peran || 'user' // Role/peran
    };
    
    return userInfo;
}
```

**Data yang di-extract dari JWT:**
- `sub`: User ID dari Keycloak (contoh: `86bef184-5c28-47c9-b6dc-1bd515b1e7cf`)
- `email`: Email user (contoh: `admin@dinas-pendidikan.go.id`)
- `name`: Nama lengkap (contoh: `Admin Dinas Pendidikan`)
- `preferred_username`: Username (contoh: `admin`)
- `peran`: Role/peran user (jika ada di JWT)

---

### **STEP 3: Check atau Create User di Database**

Setelah decode token, frontend mengirim data user ke backend untuk check/create user di Supabase.

**File:** `api/static/sso-handler.js` (line ~193-221)

```javascript
// POST /api/users/sso-login
const response = await fetch('/api/users/sso-login', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
    },
    body: JSON.stringify({
        email: userData.email,        // dari JWT
        name: userData.name,          // dari JWT
        keycloak_id: userData.id      // sub dari JWT
    })
});
```

**File:** `api/main_handler.go` (line ~3643-3842)

```go
func handleSSOUserLoginAPI(w http.ResponseWriter, r *http.Request) {
    // 1. Parse request body
    var req struct {
        Email      string `json:"email"`
        Name       string `json:"name"`
        KeycloakID string `json:"keycloak_id"`
    }
    
    // 2. Check user di Supabase berdasarkan email
    // Query: SELECT * FROM pengguna WHERE email = ?
    
    // 3. Jika user tidak ada, create user baru
    if len(users) == 0 {
        userData := map[string]interface{}{
            "email":       req.Email,
            "nama_lengkap": req.Name,
            "peran":       "user",
            "aktif":       true,
        }
        // INSERT ke Supabase
    }
    
    // 4. Return user data
    response := map[string]interface{}{
        "user": map[string]interface{}{
            "id":          userID,        // id_pengguna dari Supabase
            "email":       user["email"],
            "name":        user["nama_lengkap"],
            "keycloak_id": req.KeycloakID,
        },
    }
}
```

**Hasil:**
- User data disimpan di Supabase (tabel `pengguna`)
- Return `id_pengguna` (UUID dari Supabase) dan data user

---

### **STEP 4: Create Session**

Setelah user di-check/create, frontend membuat session aplikasi.

**File:** `api/static/sso-handler.js` (line ~226-259)

```javascript
// POST /api/auth/sso-login
const response = await fetch('/api/auth/sso-login', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
    },
    body: JSON.stringify({
        email: user.email,
        keycloak_id: user.keycloak_id
    })
});
```

**File:** `api/main_handler.go` (line ~3844-3958)

```go
func handleSSOAuthLoginAPI(w http.ResponseWriter, r *http.Request) {
    // 1. Get user by email dari Supabase
    // 2. Create session di Supabase (tabel sesi_login)
    sessionID, err := session.CreateSession(userID, r)
    
    // 3. Set cookie
    helpers.SetCookie(w, r, "client_dinas_session", sessionID, 86400)
    
    // 4. Return session token
    response := map[string]interface{}{
        "session_token": sessionID,
        "user": map[string]interface{}{
            "id":    userID,
            "email": user["email"],
            "name":  user["nama_lengkap"],
        },
    }
}
```

**Hasil:**
- Session dibuat di Supabase (tabel `sesi_login`)
- Cookie `client_dinas_session` diset di browser
- User bisa akses halaman protected

---

### **STEP 5: Ambil Data User untuk Ditampilkan**

Setelah user login, setiap halaman yang membutuhkan data user akan:

1. **Ambil session ID dari cookie**
2. **Validate session di Supabase**
3. **Ambil user ID dari session**
4. **Query user data dari Supabase**
5. **Tampilkan data user di halaman**

**File:** `api/main_handler.go` (line ~577-622)

```go
func renderDashboardWithToken(w http.ResponseWriter, r *http.Request) {
    // 1. Ambil session ID dari cookie
    sessionID, err := helpers.GetCookie(r, "client_dinas_session")
    
    // 2. Validate session di Supabase
    userID, ok, err := session.ValidateSession(sessionID)
    
    // 3. Ambil user data dari Supabase
    user, err := getUserByIDForDashboard(userID)
    
    // 4. Render halaman dengan data user
    renderDashboardPage(w, user, counts)
}
```

**File:** `api/main_handler.go` (line ~625-666)

```go
func getUserByID(userID string) (map[string]interface{}, error) {
    // Query Supabase: SELECT * FROM pengguna WHERE id_pengguna = ?
    apiURL := fmt.Sprintf("%s/rest/v1/pengguna?id_pengguna=eq.%s&select=*", 
        supabaseURL, userIDEncoded)
    
    // Return user data dari Supabase
    return users[0], nil
}
```

**File:** `api/main_handler.go` (line ~693-701)

```go
func renderDashboardPage(w http.ResponseWriter, user map[string]interface{}, counts map[string]int) {
    // Extract nama user dari data Supabase
    userName := "User"
    if name, ok := user["nama_lengkap"].(string); ok && name != "" {
        userName = name  // Tampilkan nama dari Supabase
    } else if email, ok := user["email"].(string); ok {
        userName = email
    }
    
    // Render HTML dengan data user
    html := fmt.Sprintf(`...Selamat Datang, %s...`, userName)
}
```

---

## 📊 Diagram Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Website SSO → Redirect dengan Token                         │
│    localhost:8070/login?sso_token=JWT_TOKEN&...                 │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. Frontend: sso-handler.js                                     │
│    - Detect token dari URL                                      │
│    - Decode JWT token → Extract user info                      │
│      • email: admin@dinas-pendidikan.go.id                      │
│      • name: Admin Dinas Pendidikan                             │
│      • sub: 86bef184-5c28-47c9-b6dc-1bd515b1e7cf               │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. Backend: POST /api/users/sso-login                           │
│    - Check user di Supabase (by email)                          │
│    - Jika tidak ada, create user baru                           │
│    - Return: { id, email, name, keycloak_id }                   │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. Backend: POST /api/auth/sso-login                            │
│    - Get user dari Supabase                                      │
│    - Create session di Supabase (tabel sesi_login)              │
│    - Set cookie: client_dinas_session                            │
│    - Return: { session_token, user }                            │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. Redirect ke /dashboard                                       │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 6. Backend: GET /dashboard                                      │
│    - Ambil session ID dari cookie                                │
│    - Validate session di Supabase                                │
│    - Get user ID dari session                                    │
│    - Query user data dari Supabase                               │
│      SELECT * FROM pengguna WHERE id_pengguna = ?               │
│    - Render halaman dengan data user                             │
│      • nama_lengkap: Admin Dinas Pendidikan                      │
│      • email: admin@dinas-pendidikan.go.id                       │
│      • peran: admin                                              │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ 7. Frontend: Tampilkan data user di halaman                     │
│    "Selamat Datang, Admin Dinas Pendidikan"                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔑 Key Points

### **1. Data User dari JWT (Keycloak)**
- **Sumber:** JWT token dari SSO server
- **Data:** `email`, `name`, `sub` (user ID Keycloak)
- **Digunakan untuk:** Check/create user di Supabase

### **2. Data User dari Supabase**
- **Sumber:** Tabel `pengguna` di Supabase
- **Data:** `id_pengguna`, `email`, `nama_lengkap`, `peran`
- **Digunakan untuk:** Menampilkan di halaman website

### **3. Session Management**
- **Sumber:** Tabel `sesi_login` di Supabase
- **Cookie:** `client_dinas_session` (session ID)
- **Digunakan untuk:** Validasi user sudah login

---

## 📝 Summary

1. **Token dari SSO** → Decode JWT → Extract user info (email, name, sub)
2. **Check/create user** → Simpan di Supabase (tabel `pengguna`)
3. **Create session** → Simpan di Supabase (tabel `sesi_login`)
4. **Set cookie** → `client_dinas_session` = session ID
5. **Ambil data user** → Query dari Supabase berdasarkan session
6. **Tampilkan** → Render nama, email, dll di halaman

**Jadi, data user yang ditampilkan di website client berasal dari Supabase, bukan langsung dari Keycloak. Keycloak hanya digunakan untuk authentication (verifikasi user sudah login), sedangkan data user disimpan dan diambil dari Supabase.**

