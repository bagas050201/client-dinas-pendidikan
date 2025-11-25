# Requirements untuk SSO Server (Portal SSO)

## ✅ SSO Simple - Versi Sekarang

Website client sekarang menggunakan **SSO Simple** yang lebih mudah dan sederhana.

### Format Token yang Dikirim

Ketika user klik aplikasi di Portal SSO, Portal SSO harus mengirim URL ke client website dengan format:

```
http://localhost:8070/?sso_token=<access_token>&sso_id_token=<id_token>
```

**Parameter yang diperlukan:**
- `sso_token` = access token (opsional, untuk verify token jika diperlukan)
- `sso_id_token` = ID token (berisi user info lengkap) **← PRIORITAS UTAMA**

### ID Token Requirements

ID token harus berisi claims berikut:

```json
{
  "sub": "user-id",
  "email": "admin@dinas-pendidikan.go.id",
  "name": "Administrator Sistem",
  "preferred_username": "admin",
  "email_verified": true,
  "given_name": "Administrator",
  "family_name": "Sistem",
  // ... dan lainnya
}
```

**Field yang WAJIB ada:**
- `email` - Email user (untuk mencari user di database client)
- `sub` - User ID dari Keycloak

**Field yang DISARANKAN:**
- `name` - Nama lengkap user
- `preferred_username` - Username user
- `email_verified` - Status verifikasi email

### Access Token (Opsional)

Access token (`sso_token`) digunakan sebagai fallback jika ID token gagal. Access token harus:
- Valid JWT token dari Keycloak
- Berisi claims yang sama dengan ID token (jika memungkinkan)

## 🔍 Yang Perlu Dipastikan di Portal SSO

### 1. Token Format

- ✅ Token harus dalam format JWT (3 bagian dipisah titik)
- ✅ ID token harus berisi user info lengkap (email, name, dll)
- ✅ Token harus valid dan tidak expired

### 2. Redirect URL

Portal SSO harus redirect ke client website dengan format:
```
{CLIENT_URL}/?sso_token={ACCESS_TOKEN}&sso_id_token={ID_TOKEN}
```

**Contoh:**
```
http://localhost:8070/?sso_token=eyJhbGci...&sso_id_token=eyJhbGci...
```

### 3. Cookie Management

**PENTING:** Portal SSO **TIDAK** boleh set cookie untuk client website.

Portal SSO hanya boleh:
- ✅ Set cookie untuk session Portal SSO sendiri
- ✅ Redirect ke client website dengan token di URL

Portal SSO **TIDAK** boleh:
- ❌ Set cookie untuk client website
- ❌ Share session dengan client website

### 4. Keycloak Client Configuration

Di Keycloak Admin Console, pastikan client configuration:

- **Client ID**: `localhost-8070-website-dinas-pendidikan` (atau sesuai)
- **Valid redirect URIs**: `http://localhost:8070/*` (development)
- **Web origins**: `http://localhost:8070` (development)
- **Root URL**: `http://localhost:8070` (development)
- **Home URL**: `http://localhost:8070/dashboard` (optional)

## 📋 Checklist untuk Portal SSO

- [x] Portal SSO mengirim `sso_token` dan `sso_id_token` ke client
- [x] ID token berisi claim `email` (wajib)
- [x] ID token berisi claim `name` atau `preferred_username` (disarankan)
- [x] Portal SSO tidak set cookie untuk client website
- [x] Redirect URL format benar: `/?sso_token=...&sso_id_token=...`

## 🧪 Testing

Untuk test Portal SSO, pastikan:

1. **User login di Portal SSO**
2. **User klik aplikasi di Portal SSO**
3. **Portal SSO redirect ke client dengan token:**
   ```
   http://localhost:8070/?sso_token=...&sso_id_token=...
   ```
4. **Client website decode ID token dan extract email**
5. **Client website create session dan redirect ke dashboard**

## 📝 Catatan

### Perbedaan dengan Versi Lama (Authorization Code Flow)

**Versi Lama:**
- Portal SSO redirect dengan `code` dan `state`
- Client website exchange `code` ke access token
- Client website call API `/userinfo` untuk dapat user info

**Versi Baru (SSO Simple):**
- Portal SSO redirect dengan `sso_token` dan `sso_id_token` langsung
- Client website decode ID token untuk dapat user info
- **TIDAK perlu call API** ke Keycloak

### Keuntungan SSO Simple

- ✅ **Lebih cepat** - Tidak ada network call ke Keycloak
- ✅ **Lebih sederhana** - Hanya decode JWT token
- ✅ **Lebih reliable** - Tidak bergantung pada ketersediaan Keycloak API
- ✅ **Lebih aman** - Token langsung dari SSO, tidak perlu verify lagi

## 🔗 Referensi

- **[SSO_SIMPLE_GUIDE.md](./SSO_SIMPLE_GUIDE.md)** - Panduan lengkap implementasi SSO Simple di client website
