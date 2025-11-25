# SSO Troubleshooting Guide

## 🔍 SSO Simple - Troubleshooting

Website client sekarang menggunakan **SSO Simple** yang lebih mudah. Troubleshooting guide ini untuk versi SSO Simple.

## Error: "Gagal memproses SSO token"

### Penyebab
Backend tidak bisa decode atau memproses token dari Portal SSO.

### Solusi

#### 1. Cek Token di URL

Pastikan URL dari Portal SSO berisi token:
```
http://localhost:8070/?sso_token=...&sso_id_token=...
```

**Cek di browser DevTools:**
- Buka Network tab
- Lihat request ke `/` atau `/login`
- Cek query parameters: `sso_token` dan `sso_id_token` harus ada

#### 2. Cek Log Backend

Cek log backend untuk detail error:

```bash
# Di terminal dimana server berjalan
# Cari log yang dimulai dengan:
🔐 SSO token detected in root path, processing...
❌ ERROR parsing SSO token: ...
```

**Kemungkinan error:**
- `ERROR parsing SSO token` - Token format salah atau tidak bisa di-decode
- `ERROR: Email not found in token claims` - ID token tidak berisi email
- `ERROR creating session` - Gagal create session di database

#### 3. Cek Token Format

Token harus dalam format JWT (3 bagian dipisah titik):
```
eyJhbGci... . eyJleHAi... . signature...
```

**Test decode token manual:**
```bash
# Copy token dari URL
# Decode di https://jwt.io atau gunakan base64 decode
```

#### 4. Cek Email di Token Claims

Pastikan ID token berisi claim `email`:

```json
{
  "email": "admin@dinas-pendidikan.go.id",
  "name": "Administrator Sistem",
  ...
}
```

**Jika email tidak ada:**
- Update Keycloak client configuration untuk include email di ID token
- Atau gunakan `preferred_username` atau `sub` (jika seperti email)

## Error: "User tidak ditemukan di database"

### Penyebab
Email dari token tidak ada di database client.

### Solusi

#### 1. Cek User di Database

Pastikan user sudah ada di database dengan email yang sesuai:

```sql
-- Di Supabase SQL Editor
SELECT * FROM pengguna WHERE email = 'admin@dinas-pendidikan.go.id';
```

#### 2. Create User Manual

Jika user belum ada, create user manual:

```sql
INSERT INTO pengguna (email, nama_lengkap, peran, aktif, password_hash)
VALUES (
  'admin@dinas-pendidikan.go.id',
  'Administrator Sistem',
  'admin',
  true,
  '$2a$10$...' -- Hash password dummy
);
```

#### 3. Implement Auto-Create User (Opsional)

Jika ingin auto-create user, uncomment kode di `createSessionFromEmail` untuk auto-create user jika tidak ditemukan.

## Error: "RSA verify expects *rsa.PublicKey"

### Penyebab
`JWT_PUBLIC_KEY` di-set tapi format salah atau tidak bisa di-parse sebagai RSA public key.

### Solusi

#### Opsi 1: Unset JWT_PUBLIC_KEY (Development)

Hapus atau comment `JWT_PUBLIC_KEY` di `.env`:
```bash
# JWT_PUBLIC_KEY=...
```

Token akan didecode tanpa signature validation (development mode).

#### Opsi 2: Set JWT_PUBLIC_KEY dengan Format Benar (Production)

`JWT_PUBLIC_KEY` harus dalam format PEM:

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
```

**Cara mendapatkan public key dari Keycloak:**
1. Buka Keycloak Admin Console
2. Realm Settings → Keys
3. Copy public key dalam format PEM

## Error: "Token signature is invalid"

### Penyebab
Token signature tidak valid atau `JWT_PUBLIC_KEY` tidak match dengan token.

### Solusi

#### 1. Development Mode

Jika `JWT_PUBLIC_KEY` tidak di-set, sistem akan otomatis fallback ke decode tanpa signature validation.

**Cek log:**
```
⚠️ WARNING: RSA key parsing/signature validation failed, decoding token without signature validation (development mode)
✅ Token decoded without signature validation (development mode)
```

#### 2. Production Mode

Pastikan `JWT_PUBLIC_KEY` sesuai dengan public key dari Keycloak yang digunakan untuk sign token.

## Error: "Session tidak dibuat"

### Penyebab
Gagal create session di database Supabase.

### Solusi

#### 1. Cek Koneksi ke Supabase

Pastikan environment variables sudah di-set:
```bash
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key
```

#### 2. Cek Log Backend

Cek log untuk detail error dari Supabase:
```
❌ ERROR creating session in Supabase: Status 400, Body: ...
```

#### 3. Cek Database Schema

Pastikan tabel `sesi_login` sudah ada dan schema benar:
```sql
CREATE TABLE sesi_login (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    id_sesi TEXT UNIQUE NOT NULL,
    id_pengguna UUID REFERENCES pengguna(id_pengguna),
    ip TEXT,
    user_agent TEXT,
    kadaluarsa TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
```

## Error: "Redirect loop"

### Penyebab
User di-redirect terus-menerus antara login dan dashboard.

### Solusi

#### 1. Cek Cookie

Pastikan cookie `client_dinas_session` sudah di-set:
- Buka DevTools → Application → Cookies
- Cek apakah `client_dinas_session` ada

#### 2. Cek Session di Database

Pastikan session valid di database:
```sql
SELECT * FROM sesi_login 
WHERE id_sesi = 'SESSION_ID' 
AND kadaluarsa > NOW();
```

#### 3. Clear Cookie dan Coba Lagi

Clear semua cookie dan coba login lagi:
```javascript
// Di browser console
document.cookie.split(";").forEach(function(c) { 
    document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/"); 
});
```

## Error: "Tidak ada SSO token di URL"

### Penyebab
Portal SSO tidak mengirim token ke client website.

### Solusi

#### 1. Cek Portal SSO Configuration

Pastikan Portal SSO mengirim token dengan format benar:
```
http://localhost:8070/?sso_token=...&sso_id_token=...
```

#### 2. Cek Keycloak Client Configuration

Pastikan di Keycloak:
- Valid redirect URIs: `http://localhost:8070/*`
- Root URL: `http://localhost:8070`

#### 3. Cek Log Portal SSO

Cek log Portal SSO untuk melihat URL yang dikirim ke client.

## 🧪 Testing Checklist

- [ ] Portal SSO mengirim URL dengan `sso_token` dan `sso_id_token`
- [ ] Backend detect token di URL
- [ ] Backend decode ID token berhasil
- [ ] Email berhasil di-extract dari claims
- [ ] User ditemukan di database
- [ ] Session berhasil dibuat
- [ ] Cookie `client_dinas_session` di-set
- [ ] Redirect ke dashboard berhasil

## 📋 Debug Commands

### Cek Token di URL
```javascript
// Di browser console
const urlParams = new URLSearchParams(window.location.search);
console.log('sso_token:', urlParams.get('sso_token'));
console.log('sso_id_token:', urlParams.get('sso_id_token'));
```

### Decode JWT Token Manual
```javascript
// Di browser console
function decodeJWT(token) {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
}

const token = 'YOUR_TOKEN_HERE';
console.log(decodeJWT(token));
```

### Cek Session di Database
```sql
-- Di Supabase SQL Editor
SELECT 
    s.id_sesi,
    s.id_pengguna,
    s.kadaluarsa,
    p.email,
    p.nama_lengkap
FROM sesi_login s
JOIN pengguna p ON s.id_pengguna = p.id_pengguna
WHERE s.kadaluarsa > NOW()
ORDER BY s.created_at DESC
LIMIT 10;
```

## 🔗 Referensi

- **[SSO_SIMPLE_GUIDE.md](./SSO_SIMPLE_GUIDE.md)** - Panduan lengkap SSO Simple
- **[SSO_SERVER_REQUIREMENTS.md](./SSO_SERVER_REQUIREMENTS.md)** - Requirements untuk Portal SSO
