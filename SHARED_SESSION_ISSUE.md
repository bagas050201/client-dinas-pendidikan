# Masalah: Shared Session Table Antara SSO Server dan Client Website

## 🔴 Masalah yang Ditemukan

Ketika user login di **localhost:8080** (SSO server), website **localhost:8070** (client) **otomatis ikut login** meskipun user belum authorize aplikasi.

### Root Cause

1. **SSO server** (localhost:8080) dan **client website** (localhost:8070) menggunakan **tabel `sesi_login` yang sama** di Supabase
2. Ketika user login di SSO server:
   - SSO server membuat session di tabel `sesi_login`
   - SSO server set cookie `sso_admin_session` atau `session_id` di browser
3. Ketika user akses client website (localhost:8070):
   - Client website mengecek cookie `sso_admin_session` atau `session_id`
   - Cookie ada! Client website mengecek apakah session valid di Supabase
   - Session valid! (karena dibuat oleh SSO server)
   - Client website menganggap user sudah login ❌

### Kenapa Ini Masalah?

1. **Security Issue**: Client website tidak seharusnya menggunakan session yang dibuat oleh SSO server
2. **OAuth 2.0 Violation**: User belum explicitly authorize aplikasi
3. **Privacy Issue**: Client website mengakses data user tanpa consent

## ✅ Solusi

### Opsi 1: Tambahkan Kolom `client_id` di Tabel `sesi_login` (RECOMMENDED)

Tambahkan kolom `client_id` untuk membedakan session dari SSO server vs client website:

```sql
ALTER TABLE sesi_login ADD COLUMN client_id TEXT;
```

- SSO server: `client_id = 'sso-server'`
- Client website: `client_id = 'client-dinas-pendidikan'`

Lalu filter session berdasarkan `client_id` saat validasi.

### Opsi 2: Client Website Hanya Gunakan OAuth 2.0 Access Token (SIMPLE)

Client website **TIDAK** boleh menggunakan cookie `sso_admin_session` yang dibuat oleh SSO server.

Client website hanya boleh:
- Menggunakan cookie `sso_access_token` (dari OAuth 2.0 Authorization Code Flow)
- Atau membuat session sendiri setelah user authorize via OAuth 2.0

### Opsi 3: Pisahkan Tabel Session (BEST PRACTICE)

Buat tabel session terpisah:
- `sesi_login_sso` untuk SSO server
- `sesi_login_client` untuk client website

## 🛠️ Implementasi yang Dipilih

Kita akan menggunakan **Opsi 2** (Simple): Client website hanya menggunakan OAuth 2.0 access token atau session yang dibuat oleh client website sendiri.

Perubahan:
1. `isAuthenticated()` hanya cek cookie `sso_access_token` (OAuth 2.0) atau `sso_admin_session` yang dibuat oleh client website sendiri
2. Jangan gunakan cookie `sso_admin_session` yang dibuat oleh SSO server
3. Client website hanya membuat session setelah user authorize via OAuth 2.0

