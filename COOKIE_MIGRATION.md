# Cookie Migration: sso_admin_session → client_dinas_session

## 🔄 Perubahan Cookie Name

Client website sekarang menggunakan cookie name yang berbeda dari SSO server:
- **SSO server (localhost:8080)**: `sso_admin_session` (tetap)
- **Client website (localhost:8070)**: `client_dinas_session` (baru)

## ⚠️ Penting: Clear Cookie Lama di Browser

Karena perubahan cookie name, user perlu **clear cookie lama** di browser:

### Cara Clear Cookie di Chrome DevTools:

1. Buka Chrome DevTools (F12 atau Cmd+Option+I)
2. Buka tab **Application**
3. Di sidebar kiri, expand **Cookies** → `http://localhost:8070`
4. Cari cookie `sso_admin_session`
5. Klik kanan → **Delete** atau klik icon trash
6. Refresh halaman (F5 atau Cmd+R)

### Atau Clear Semua Cookie:

1. Buka Chrome DevTools (F12 atau Cmd+Option+I)
2. Buka tab **Application**
3. Di sidebar kiri, klik **Cookies** → `http://localhost:8070`
4. Klik icon **Clear** (trash icon) di toolbar
5. Refresh halaman (F5 atau Cmd+R)

## 🧪 Testing Setelah Clear Cookie

1. **Clear cookie lama** di browser (lihat cara di atas)
2. **Logout** di client website (localhost:8070) jika masih login
3. **Logout** di SSO server (localhost:8080) jika masih login
4. **Login di SSO server** (localhost:8080) sebagai "Administrator SSO"
5. **Buka client website** (localhost:8070)
6. **Seharusnya TIDAK otomatis login** (harus klik "Login dengan SSO")
7. **Klik "Login dengan SSO"** dan authorize aplikasi
8. **Setelah authorize**, seharusnya redirect ke dashboard dengan cookie `client_dinas_session`
9. **Cek di DevTools** → Application → Cookies → `http://localhost:8070`
10. **Seharusnya ada cookie `client_dinas_session`**, bukan `sso_admin_session`

## 📋 Checklist

- [x] Semua kode sudah menggunakan `client_dinas_session` sebagai primary
- [x] Fallback ke `sso_admin_session` sudah dihapus
- [x] Logout handler sudah diupdate
- [ ] User sudah clear cookie lama di browser
- [ ] Test flow lengkap: login → authorize → dashboard

## 🔍 Verifikasi

Setelah clear cookie dan login ulang, cek di DevTools:

**Cookies untuk `http://localhost:8070`:**
- ✅ `client_dinas_session` (harus ada setelah login)
- ✅ `sso_access_token` (harus ada setelah SSO authorize)
- ✅ `sso_token_expires` (harus ada setelah SSO authorize)
- ❌ `sso_admin_session` (tidak boleh ada, ini cookie dari SSO server)

**Cookies untuk `http://localhost:8080`:**
- ✅ `sso_admin_session` (cookie SSO server sendiri)
- ❌ `client_dinas_session` (tidak boleh ada, ini cookie client website)

## 🐛 Troubleshooting

Jika masih membaca `sso_admin_session`:

1. **Clear cookie lama** di browser (lihat cara di atas)
2. **Restart server** client website
3. **Hard refresh** browser (Cmd+Shift+R atau Ctrl+Shift+R)
4. **Cek terminal logs** untuk melihat cookie mana yang dibaca
5. **Cek DevTools** → Application → Cookies untuk melihat cookie yang ada

