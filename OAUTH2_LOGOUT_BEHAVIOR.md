# OAuth 2.0 Logout Behavior - Best Practices

## 🎯 Prinsip Dasar

Menurut **OAuth 2.0 standard**, logout di client website **TIDAK** seharusnya logout dari SSO server secara otomatis. Ini adalah **Single Sign-Out (SSO)** yang memerlukan implementasi khusus.

## ✅ Behavior yang Benar (OAuth 2.0 Standard)

### Logout di Client Website (localhost:8070)
- ✅ Hanya menghapus session/client cookie sendiri
- ✅ Hanya menghapus access token client
- ✅ **TIDAK** logout dari SSO server (localhost:8080)
- ✅ User masih login di SSO server

### Logout di SSO Server (localhost:8080)
- ✅ Hanya menghapus session SSO server sendiri
- ✅ **TIDAK** logout dari client website secara otomatis
- ✅ Client website masih memiliki access token yang valid

## 🔄 Single Sign-Out (SSO) - Optional

Jika ingin implementasi **Single Sign-Out** (logout di satu tempat, logout di semua tempat), ada beberapa opsi:

### Opsi 1: OpenID Connect Session Management (RECOMMENDED)
- Menggunakan `check_session_iframe` untuk monitor session status
- Client website check session status secara periodik
- Jika SSO server logout, client website detect dan logout juga

### Opsi 2: Back-Channel Logout
- SSO server mengirim logout notification ke semua client
- Client website menerima notification dan logout user

### Opsi 3: Front-Channel Logout
- SSO server redirect ke semua client dengan logout parameter
- Client website logout user saat menerima redirect

## 🛠️ Masalah Saat Ini

### Root Cause: Shared Cookie Name

Kedua website menggunakan cookie dengan nama yang sama:
- SSO server: `sso_admin_session`
- Client website: `sso_admin_session` ❌

Karena domain sama (localhost), browser mengirim cookie yang sama ke kedua website.

### Solusi: Gunakan Cookie Name yang Berbeda

- SSO server: `sso_admin_session` (tetap)
- Client website: `client_session` atau `client_dinas_session` ✅

Dengan cookie name yang berbeda, cookie tidak akan di-share antara kedua website.

## 📋 Implementasi

1. **Client website menggunakan cookie name yang berbeda**
   - Ganti `sso_admin_session` → `client_dinas_session`
   - Hanya untuk session yang dibuat oleh client website sendiri

2. **SSO server tetap menggunakan `sso_admin_session`**
   - Tidak perlu diubah

3. **Logout behavior tetap terpisah**
   - Logout di client website hanya logout dari client website
   - Logout di SSO server hanya logout dari SSO server
   - Tidak ada shared logout (kecuali implementasi Single Sign-Out)

## 🧪 Testing

1. Login di SSO server (8080) → set cookie `sso_admin_session`
2. Login di client website (8070) → set cookie `client_dinas_session`
3. Logout di client website (8070) → hapus cookie `client_dinas_session`
4. ✅ User masih login di SSO server (8080)
5. Logout di SSO server (8080) → hapus cookie `sso_admin_session`
6. ✅ User masih login di client website (8070) (karena access token masih valid)

## 📝 Catatan

- **OAuth 2.0 standard**: Logout terpisah adalah behavior yang benar
- **Single Sign-Out**: Optional, memerlukan implementasi khusus
- **Cookie name berbeda**: Solusi untuk mencegah shared cookie

