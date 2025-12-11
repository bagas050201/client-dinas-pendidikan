# 🧪 Panduan Testing SSO - Cara Yang Benar

## ❓ **Pertanyaan: "Kenapa Sudah Login di SSO Admin Portal, Tapi Client Website Masih Minta Login?"**

### **Jawaban:**

**SSO Admin Portal (localhost:3000) ≠ Keycloak Session**

- **SSO Admin Portal** = Website untuk manage users, roles, applications (backend sistem)
- **Keycloak** = Identity Provider untuk authentication (sistem login)

Login di SSO Admin Portal **TIDAK otomatis** membuat session di Keycloak. Ini dua sistem yang berbeda!

---

## ✅ **Cara Kerja SSO yang Benar**

### **Step 1: First Login (Normal - Harus Input Password)**
1. User akses **Aplikasi Client Pertama** (misal: `localhost:8070`)
2. Redirect ke **Keycloak Login Page** ← **INI NORMAL!**  
3. User **input kredensial** (username/password)
4. Keycloak **create session** dan redirect balik ke aplikasi
5. User berhasil login ✅

### **Step 2: SSO Bekerja (Auto-Login Tanpa Password!)**
1. User akses **Aplikasi Client Kedua** (misal: `localhost:8071` atau aplikasi lain)
2. Keycloak **detect session yang sudah ada**
3. **Auto-redirect** dengan authorization code ← **INI SSO MAGIC! 🎉**
4. User langsung login **TANPA input password lagi!** ✅

---

## 🧪 **Test Case: Membuktikan SSO Bekerja**

### **Setup: Buat 2 Client Website**

Untuk test SSO, kita perlu **minimal 2 aplikasi client** yang terhubung ke Keycloak yang sama.

**Client 1:** (sudah ada)
- Port: `8070`
- Client ID: `localhost-8070-website-dinas-pendidikan`

**Client 2:** (untuk testing)
- Port: `8071`  
- Client ID: `localhost-8071-website-dinas-pendidikan`

---

### **Test Scenario 1: First Login (Diminta Input Password)**

1. **Buka Incognito/Private Window** (untuk session fresh)
2. **Akses:** `http://localhost:8070`
3. **Expected:**
   - ✅ Redirect ke Keycloak login page
   - ✅ Form login muncul
   - ✅ **INI NORMAL! Karena ini first login**
4. **Action:** Input kredensial (username: `111111`, password: `password123` atau sesuai user Anda)
5. **Expected:**
   - ✅ Login berhasil
   - ✅ Redirect ke dashboard `localhost:8070/dashboard`

---

### **Test Scenario 2: SSO Auto-Login (TANPA Input Password!)**

**PENTING:** Jangan tutup browser! Gunakan window/tab yang sama setelah login di step 1.

1. **Buka Tab Baru** (masih di browser yang sama, JANGAN incognito baru!)
2. **Akses:** `http://localhost:8071` (atau client app kedua)
3. **Expected:**
   - ✅ **TIDAK** menampilkan form login Keycloak
   - ✅ **Langsung auto-redirect** dengan authorization code
   - ✅ **Auto-login ke dashboard** tanpa input password
   - ✅ **INI SSO BEKERJA! 🎉**

**Atau, kalau belum punya client kedua:**

1. **Logout** dari `localhost:8070` (tapi jangan logout dari Keycloak!)
2. **Hapus cookie** `client_dinas_session` dari `localhost:8070` (via DevTools → Application → Cookies)
3. **Akses lagi:** `http://localhost:8070`
4. **Expected:**
   - ✅ **Langsung auto-login** tanpa diminta password
   - ✅ Karena Keycloak session masih valid

---

### **Test Scenario 3: Logout SSO (Logout dari Semua Aplikasi)**

1. **Dari aplikasi manapun**, click tombol **Logout**
2. **Expected:**
   - ✅ Redirect ke Keycloak logout endpoint
   - ✅ **Session Keycloak dihapus**
   - ✅ User logout dari **SEMUA aplikasi** yang terhubung ke Keycloak

3. **Akses lagi aplikasi manapun** (`localhost:8070` atau `localhost:8071`)
4. **Expected:**
   - ✅ Diminta login lagi (karena Keycloak session sudah di-logout)

---

## 🔧 **Cara Membuat Client Kedua untuk Testing**

### **Option 1: Via Keycloak Admin Console**

1. **Buka:** `http://localhost:8080/sso-auth/admin`
2. **Login:** admin / admin
3. **Select Realm:** `dinas-pendidikan`
4. **Click:** Clients → Create client
5. **Settings:**
   ```
   Client ID: localhost-8071-website-dinas-pendidikan
   Client type: OpenID Connect
   ```
6. **Click:** Next
7. **Capability Config:**
   - ✅ Standard flow: ON
   - ✅ Direct access grants: ON
   - ❌ Client authentication: OFF
8. **Click:** Next
9. **Login Settings:**
   ```
   Root URL: http://localhost:8071
   Valid Redirect URIs: 
     - http://localhost:8071/callback
     - http://localhost:8071/*
   Web origins: http://localhost:8070
   ```
10. **Click:** Save

### **Option 2: Copy & Run Client di Port 8071**

Duplicate folder client website ini dan jalankan di port berbeda:

```bash
# Copy environment file
cp .env .env.8071

# Edit .env.8071
# Ubah PORT=8071
# Ubah KEYCLOAK_CLIENT_ID=localhost-8071-website-dinas-pendidikan
# Ubah KEYCLOAK_REDIRECT_URI=http://localhost:8071/callback

# Run dengan env berbeda
env $(cat .env.8071 | xargs) go run dev.go
```

---

## 📊 **Expected Results Summary**

| Scenario | Browser State | Action | Expected Result |
|----------|---------------|--------|-----------------|
| **First Login** | Fresh/Incognito | Akses `localhost:8070` | ❌ Form login muncul (NORMAL!) |
| **Already Logged In** | Same browser session | Akses `localhost:8070` | ✅ Auto-redirect ke dashboard |
| **SSO to App 2** | Same browser session | Akses `localhost:8071` | ✅ Auto-login tanpa password! 🎉 |
| **After Logout** | After SSO logout | Akses any app | ❌ Form login muncul lagi |

---

## 🔍 **Debugging: Check Keycloak Session**

### **Cek Apakah Keycloak Punya Session:**

1. **Buka:** `http://localhost:8080/sso-auth/realms/dinas-pendidikan/account`
2. **Expected:**
   - Kalau ada session: Menampilkan halaman account user
   - Kalau tidak ada session: Redirect ke login page

### **Cek Session via Cookie:**

1. **Buka:** `http://localhost:8080/sso-auth`
2. **DevTools → Application → Cookies**
3. **Cari cookie:** `KEYCLOAK_SESSION*` atau `AUTH_SESSION_ID*`
4. **Expected:**
   - Kalau ada: Berarti session valid
   - Kalau tidak ada: Berarti belum login di Keycloak

---

## ✅ **Kesimpulan**

### **Yang NORMAL:**
- ✅ **First login** diminta input password di Keycloak
- ✅ Login di SSO Admin Portal (localhost:3000) **TIDAK sama** dengan login di Keycloak
- ✅ Setiap website client **butuh client config** di Keycloak

### **Yang SSO:**
- ✅ Setelah login sekali, akses aplikasi client lain **langsung auto-login**
- ✅ Logout dari satu aplikasi = logout dari **semua aplikasi** (single logout)

### **Kalau SSO Tidak Bekerja:**
- ❌ Akses aplikasi kedua masih diminta password → Ada masalah!
- ❌ Check:
  1. Keycloak session masih valid?
  2. Browser sama (bukan incognito baru)?
  3. Client kedua sudah registered di Keycloak?
  4. Cookie tidak di-block?

---

## 🎯 **Next Steps**

1. **Test Scenario 1** dulu: Pastikan bisa login dengan input password
2. **Test Scenario 2**: Pastikan SSO auto-login bekerja (tanpa password!)
3. Kalau kedua test case itu works → **SSO sudah bekerja perfect!** 🎉

---

**Semoga jelas! 😊**
