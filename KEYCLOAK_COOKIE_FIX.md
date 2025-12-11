# 🔧 FIX: Keycloak Cookie Not Found Error

## ❌ **Error yang Terjadi:**

```
LOGIN_ERROR: error="cookie_not_found"
WARN: Non-secure context detected; cookies are not secured
```

**Screenshot:** Internal Server Error setelah login di Keycloak

---

## 🔍 **Root Cause:**

Keycloak tidak bisa set cookie dengan benar karena **SameSite policy** dalam development environment.

### **Kenapa Terjadi:**

1. **Client website** di `localhost:8070`
2. **Keycloak** di `localhost:8080` (different port = cross-origin)
3. **Cookie policy:** Browser block cookies di cross-origin POST requests (untuk keamanan)
4. **Hasil:** Keycloak ga bisa track session → error `cookie_not_found`

---

## ✅ **Solusi 1: Disable Prompt=None (Temporary Fix)**

Untuk testing cepat, kita bisa disable `prompt=none` sementara. Ini akan:
- ✅ Skip auto-login check
- ✅ Langsung tampilkan form login (no redirect loop)
- ✅ Session cookie akan di-set setelah user submit form

### **Implementation:**

Edit `main_handler.go`, line ~232:

```go
// Belum login, check Keycloak session dengan prompt=none
log.Printf("🔄 No local session found, checking Keycloak session with prompt=none")
redirectToKeycloakLogin(w, r, true) // true = dengan prompt=none
```

**Ubah jadi:**

```go
// Belum login, redirect ke Keycloak login form (skip auto-login check)
log.Printf("🔄 No local session found, redirecting to Keycloak login form")
redirectToKeycloakLogin(w, r, false) // false = TANPA prompt=none
```

**Pros:**
- ✅ Simple fix
- ✅ Langsung work
- ✅ No configuration needed

**Cons:**
- ❌ Tidak ada "silent SSO" (selalu tampilkan login form, meski sudah login di app lain)
- ❌ User harus input password untuk setiap aplikasi

---

## ✅ **Solusi 2: Use Same-Origin (Recommended for Production)**

Gunakan **reverse proxy** agar Keycloak dan Client di domain/port yang sama.

### **Example dengan Nginx:**

```nginx
server {
    listen 8000;
    server_name localhost;

    # Client website
    location / {
        proxy_pass http://localhost:8070;
    }

    # Keycloak
    location /sso-auth {
        proxy_pass http://localhost:8080/sso-auth;
    }
}
```

**Access:**
- Client: `http://localhost:8000`
- Keycloak: `http://localhost:8000/sso-auth`

**Pros:**
- ✅ Same origin → no cookie issues
- ✅ Production-ready setup
- ✅ SSO bekerja sempurna

**Cons:**
- ❌ Butuh setup nginx/reverse proxy
- ❌ More complex

---

## ✅ **Solusi 3: Configure Keycloak for Development**

Add environment variable ke Keycloak untuk development mode:

```bash
KC_SPI_STICKY_SESSION_ENCODER_INFINISPAN_SHOULD_ATTACH_ROUTE=false
KC_COOKIE_SAME_SITE=None
```

**Restart Keycloak:**

```bash
docker restart dev-sso-keycloak-dinas-pendidikan-keycloak
```

**Pros:**
- ✅ SSO tetap work dengan prompt=none
- ✅ Multi-domain development

**Cons:**
- ❌ Security risk (don't use in production!)
- ❌ Requires HTTPS for SameSite=None (even in dev)

---

## 🎯 **Quick Fix untuk Sekarang:**

Gunakan **Solusi 1** (disable prompt=none):

1. Edit `main_handler.go`
2. Change line 232: `redirectToKeycloakLogin(w, r, false)`
3. Restart aplikasi

**Test:**
1. Buka `http://localhost:8070`
2. Form login langsung muncul (no redirect loop)
3. Input kredensial
4. Should login successfully! ✅

---

## 📝 **Long-term Solution:**

Untuk production, gunakan **Solusi 2** (reverse proxy):
- Deploy dengan HTTPS
- Single domain untuk semua services
- Cookie policy akan work perfectly

---

**Mau saya implement Solusi 1 sekarang?**
