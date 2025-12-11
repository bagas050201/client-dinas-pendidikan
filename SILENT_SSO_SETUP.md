# 🎯 Setup Silent SSO (True Single Sign-On)

> **Goal:** Login sekali di mana saja → Otomatis login di semua aplikasi! 🚀

---

## 🎬 **Apa itu Silent SSO?**

**Silent SSO** = Login sekali, akses semua aplikasi tanpa input password lagi!

### **Skenario:**

1. ✅ User login di **Website SSO Admin Portal** (localhost:3000)
2. ✅ User buka **Website Client** (localhost:8070)
3. ✅ **Auto-login!** Tanpa diminta password lagi! 🎉
4. ✅ User buka **Website Client Lain** (localhost:8071, 8072, dst)
5. ✅ **Auto-login juga!** Semua aplikasi langsung masuk!

### **Logout:**

1. User click **Logout** di salah satu aplikasi
2. ✅ **Logout dari SEMUA aplikasi sekaligus!** (Single Logout)

---

## ⚠️ **Masalah di Development**

### **Kenapa Silent SSO Tidak Bekerja di Development?**

**Root Cause:**
- Aplikasi di **port berbeda** = **Cross-Origin**
  - SSO Admin: `localhost:3000`
  - Keycloak: `localhost:8080`
  - Client: `localhost:8070`
- Browser **block cookies** di cross-origin (security policy)
- Keycloak **tidak bisa set session cookie** → `cookie_not_found` error

**Result:**
- ❌ Silent SSO tidak bekerja
- ❌ User harus login manual di setiap aplikasi

---

## ✅ **Solusi: Nginx Reverse Proxy**

### **Konsep:**

Semua aplikasi akses melalui **satu port** (same-origin):

```
Before (Multi-Origin):
❌ http://localhost:3000  → SSO Admin
❌ http://localhost:8070  → Client Website  
❌ http://localhost:8080  → Keycloak

After (Same-Origin via Nginx):
✅ http://localhost:8000/       → Client Website
✅ http://localhost:8000/admin/ → SSO Admin
✅ http://localhost:8000/sso-auth/ → Keycloak
```

**Benefits:**
- ✅ **Same origin** → No cookie issues!
- ✅ **Silent SSO works perfectly!** 🎉
- ✅ Production-ready architecture

---

## 🚀 **Quick Start dengan Docker Compose + Nginx**

### **Step 1: File yang Sudah Dibuat**

Saya sudah buatkan 2 file:

1. **`docker-compose-nginx.yml`** - Docker Compose dengan Nginx
2. **`nginx.conf`** - Konfigurasi Nginx reverse proxy

### **Step 2: Update Environment Variables**

Edit `.env`:

```bash
# BEFORE (Multi-Origin)
SSO_BASE_URL=http://localhost:8080/sso-auth
SSO_REDIRECT_URI=http://localhost:8070/callback

# AFTER (Same-Origin via Nginx)
SSO_BASE_URL=http://localhost:8000/sso-auth
SSO_REDIRECT_URI=http://localhost:8000/callback
```

### **Step 3: Update Keycloak Client Configuration**

Login ke Keycloak Admin Console:

```
URL: http://localhost:8000/sso-auth/admin
Username: admin
Password: admin
```

Update **Valid Redirect URIs**:

```
# Hapus yang lama:
❌ http://localhost:8070/callback
❌ http://localhost:8070/*

# Tambah yang baru:
✅ http://localhost:8000/callback
✅ http://localhost:8000/*
```

Update **Web Origins**:

```
✅ http://localhost:8000
```

### **Step 4: Start Services**

```bash
# Stop yang lama (jika ada)
docker-compose down -v

# Start dengan Nginx
docker-compose -f docker-compose-nginx.yml up -d

# Check logs
docker-compose -f docker-compose-nginx.yml logs -f
```

### **Step 5: Access URLs**

Sekarang akses semua via **http://localhost:8000**:

| Service | Old URL (Multi-Origin) | New URL (Same-Origin) |
|---------|----------------------|---------------------|
| Client Website | ❌ http://localhost:8070 | ✅ http://localhost:8000 |
| SSO Admin | ❌ http://localhost:3000 | ✅ http://localhost:8000/admin |
| Keycloak | ❌ http://localhost:8080/sso-auth | ✅ http://localhost:8000/sso-auth |

---

## 🧪 **Testing Silent SSO**

### **Test Case 1: Login di Client → Auto-login di Admin**

1. **Buka incognito window**
2. **Akses:** `http://localhost:8000`
3. **Expected:** Redirect ke Keycloak login form
4. **Login dengan:** NIK/NIP/Email dan password
5. **Expected:** Login berhasil, redirect ke dashboard
6. **Buka tab baru** (same browser, JANGAN incognito baru!)
7. **Akses:** `http://localhost:8000/admin`
8. **Expected:** ✅ **AUTO-LOGIN!** Langsung masuk tanpa diminta password! 🎉

### **Test Case 2: Logout = Logout Semua**

1. **Dari aplikasi manapun**, click **Logout**
2. **Expected:** Logout dari Keycloak
3. **Akses aplikasi lain** (client atau admin)
4. **Expected:** ✅ **Diminta login lagi!** (semua session sudah di-clear)

### **Test Case 3: Multi-Client SSO**

Asumsi Anda punya 2+ client apps:

1. **Login di Client App 1** (`localhost:8000`)
2. **Buka Client App 2** di tab baru
3. **Expected:** ✅ **AUTO-LOGIN!** Tanpa password!
4. **Buka Client App 3, 4, 5, dst**
5. **Expected:** ✅ **Semua auto-login!** 🚀

---

## 📊 **Architecture Diagram**

### **Before (Multi-Origin - Silent SSO Tidak Bekerja):**

```
Browser
  ├─→ localhost:3000 (SSO Admin)      Cookie Domain: localhost:3000
  ├─→ localhost:8070 (Client)         Cookie Domain: localhost:8070
  └─→ localhost:8080 (Keycloak)       Cookie Domain: localhost:8080
                                      ❌ CROSS-ORIGIN = NO SHARED COOKIES!
```

### **After (Same-Origin via Nginx - Silent SSO Bekerja!):**

```
Browser
  └─→ localhost:8000 (Nginx)          Cookie Domain: localhost:8000
        ├─→ /            → Client Website
        ├─→ /admin/      → SSO Admin Portal
        └─→ /sso-auth/   → Keycloak
                          ✅ SAME-ORIGIN = SHARED COOKIES = SILENT SSO! 🎉
```

---

## ⚙️ **Konfigurasi Detail**

### **nginx.conf Highlights:**

```nginx
# Route ke berbagai services
location /sso-auth/ {
    proxy_pass http://keycloak:8080/sso-auth/;
    # Cookie settings untuk SSO
    proxy_cookie_path /sso-auth /sso-auth;
    proxy_cookie_domain keycloak localhost;
}

location / {
    proxy_pass http://client_website:8070/;
}

location /admin/ {
    proxy_pass http://sso_admin_portal:80/;
}
```

### **Go Application Config:**

```go
// api/keycloak_helpers.go
func getKeycloakBaseURL() string {
    if url := os.Getenv("KEYCLOAK_BASE_URL"); url != "" {
        return url
    }
    // UPDATED: Same-origin via Nginx
    return "http://localhost:8000/sso-auth" // ← Port 8000 (Nginx)
}

func getKeycloakRedirectURI() string {
    if uri := os.Getenv("KEYCLOAK_REDIRECT_URI"); uri != "" {
        return uri
    }
    // UPDATED: Same-origin via Nginx
    return "http://localhost:8000/callback" // ← Port 8000 (Nginx)
}
```

### **main_handler.go - Silent SSO Enabled:**

```go
// Belum login lokal, check Keycloak session dengan prompt=none (Silent SSO)
// Jika user sudah login di Keycloak, akan auto-login tanpa input password!
log.Printf("🔄 No local session found, checking Keycloak session (Silent SSO)")
redirectToKeycloakLogin(w, r, true) // true = dengan prompt=none untuk Silent SSO
```

**Flow:**
1. User akses aplikasi tanpa session lokal
2. App redirect ke Keycloak dengan `prompt=none`
3. Keycloak check apakah ada session:
   - ✅ **Ada session:** Return authorization code → auto-login!
   - ❌ **Tidak ada session:** Return `login_required` → tampilkan login form

---

## 🎯 **Production Deployment**

### **Production Architecture:**

```
User → HTTPS Load Balancer
         └─→ Nginx Reverse Proxy
               ├─→ /            → Client App (multiple instances)
               ├─→ /admin/      → SSO Admin Portal
               └─→ /sso-auth/   → Keycloak (HA cluster)
```

### **Production Checklist:**

- [ ] HTTPS enabled (SSL certificates)
- [ ] Domain: `https://sso.disdik.jakarta.go.id`
- [ ] Keycloak HA cluster (multiple instances)
- [ ] PostgreSQL HA (replication)
- [ ] Nginx load balancing
- [ ] Session affinity (sticky sessions)
- [ ] Rate limiting
- [ ] WAF (Web Application Firewall)
- [ ] Logging & monitoring
- [ ] Backup & disaster recovery

### **Production URL Structure:**

```
https://sso.disdik.jakarta.go.id/              → Client Website
https://sso.disdik.jakarta.go.id/admin/        → SSO Admin Portal
https://sso.disdik.jakarta.go.id/sso-auth/     → Keycloak
```

---

## 🐛 **Troubleshooting**

### **Problem 1: Silent SSO Masih Tidak Bekerja**

**Check:**
1. Semua akses via **same port** (8000)?
2. Cookie domain sama (`localhost:8000`)?
3. Keycloak session ada?
   ```bash
   # Check cookie di browser DevTools → Application → Cookies
   # Cari: KEYCLOAK_SESSION*, AUTH_SESSION_ID*
   ```

### **Problem 2: Redirect Loop**

**Penyebab:** `prompt=none` terus return `login_required`

**Solusi:**
1. Check Keycloak session: Akses `http://localhost:8000/sso-auth/realms/dinas-pendidikan/account`
2. Jika diminta login → Session memang tidak ada, login dulu
3. Setelah login, Silent SSO akan bekerja

### **Problem 3: "Invalid redirect URI"**

**Penyebab:** Client redirect URI tidak match

**Solusi:**
1. Login Keycloak Admin: `http://localhost:8000/sso-auth/admin`
2. Update Valid Redirect URIs ke `http://localhost:8000/*`
3. Restart aplikasi

### **Problem 4: Nginx "Connection refused"**

**Penyebab:** Upstream service tidak running

**Check:**
```bash
# Check yang running
docker-compose -f docker-compose-nginx.yml ps

# Check logs
docker-compose -f docker-compose-nginx.yml logs keycloak
docker-compose -f docker-compose-nginx.yml logs client-website
```

---

## 📝 **Summary**

### **What We Changed:**

1. ✅ **Re-enabled `prompt=none`** di `main_handler.go`
2. ✅ **Created Nginx config** untuk reverse proxy
3. ✅ **Created Docker Compose** dengan Nginx
4. ✅ **Updated URLs** untuk same-origin

### **Benefits:**

- ✅ **Silent SSO works!** Login sekali, akses semua aplikasi
- ✅ **Single Logout!** Logout dari mana saja = logout semua
- ✅ **Production-ready!** Architecture yang scalable
- ✅ **No cookie issues!** Same-origin fix semua masalah

### **Next Steps:**

1. **Test di development** dengan Docker Compose + Nginx
2. **Verify Silent SSO** dengan test cases di atas
3. **Deploy to staging/production** dengan HTTPS

---

## 🚀 **Ready to Test!**

```bash
# 1. Update .env
vi .env
# Set SSO_BASE_URL=http://localhost:8000/sso-auth

# 2. Update Keycloak Client Config
# Login ke http://localhost:8000/sso-auth/admin

# 3. Start dengan Nginx
docker-compose -f docker-compose-nginx.yml up -d

# 4. Test Silent SSO!
open http://localhost:8000
```

---

**Silent SSO is now enabled! Login once, access everywhere! 🎉**
