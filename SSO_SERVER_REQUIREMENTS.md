# Requirements untuk SSO Server (localhost:8080)

Requirements untuk SSO server
Masih relevan untuk konfigurasi

## ✅ Yang Sudah Benar (Tidak Perlu Diubah)

SSO server sudah mengikuti OAuth 2.0 standard dengan benar:

1. **Authorization Endpoint** (`/api/authorize` atau `/apps/access`)
   - ✅ Menerima `client_id`, `redirect_uri`, `state`
   - ✅ Menampilkan consent page untuk user
   - ✅ Redirect ke `redirect_uri` dengan `code` dan `state` setelah user authorize

2. **Token Endpoint** (`/api/token`)
   - ✅ Menerima `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`
   - ✅ Mengembalikan `access_token`, `token_type`, `expires_in`, `scope`

3. **UserInfo Endpoint** (`/api/userinfo`)
   - ✅ Menerima `Authorization: Bearer {access_token}`
   - ✅ Mengembalikan user info dalam format JSON

## 🔍 Yang Perlu Dipastikan

### 1. UserInfo Response Format

SSO server harus mengirim user info dengan format berikut:

```json
{
  "sub": "user-id-or-email",
  "email": "admin@dinas-pendidikan.go.id",
  "name": "Administrator SSO",
  "email_verified": true
}
```

**Atau format alternatif (Indonesian):**
```json
{
  "sub": "user-id-or-email",
  "email": "admin@dinas-pendidikan.go.id",
  "nama_lengkap": "Administrator SSO",
  "email_verified": true
}
```

**Field yang didukung:**
- `name` atau `nama_lengkap` atau `full_name` atau `nama` - untuk nama lengkap user
- `email` - untuk email user
- `sub` - untuk subject/user ID

### 2. Cookie Management

**PENTING:** SSO server **TIDAK** boleh set cookie `sso_admin_session` untuk client website.

SSO server hanya boleh:
- ✅ Set cookie untuk session SSO server sendiri (untuk localhost:8080)
- ✅ Redirect ke client website dengan `code` dan `state` di URL

SSO server **TIDAK** boleh:
- ❌ Set cookie untuk client website (localhost:8070)
- ❌ Share session dengan client website

### 3. Redirect URI Validation

SSO server harus memvalidasi `redirect_uri` yang dikirim oleh client:
- ✅ Hanya allow `redirect_uri` yang sudah terdaftar untuk `client_id`
- ✅ Pastikan `redirect_uri` match dengan yang dikirim di authorization request

## 📋 Checklist untuk SSO Server

- [x] Authorization endpoint sudah benar
- [x] Token endpoint sudah benar
- [ ] UserInfo endpoint mengirim field `name` atau `nama_lengkap`
- [ ] SSO server tidak set cookie untuk client website
- [ ] Redirect URI validation sudah diimplementasikan

## 🧪 Testing

Untuk test SSO server, gunakan curl:

```bash
# 1. Test authorization (manual - buka di browser)
# http://localhost:8080/apps/access?client_id=client-dinas-pendidikan&redirect_uri=http://localhost:8070/api/callback&state=random-state

# 2. Test token exchange
curl -X POST http://localhost:8080/api/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=YOUR_CODE&redirect_uri=http://localhost:8070/api/callback&client_id=client-dinas-pendidikan"

# 3. Test userinfo
curl -X GET http://localhost:8080/api/userinfo \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 📝 Catatan

Client website (localhost:8070) sudah diupdate untuk:
- ✅ Menggunakan OAuth 2.0 access token sebagai prioritas utama
- ✅ Membuat session sendiri setelah user authorize
- ✅ Tidak menggunakan shared session dengan SSO server
- ✅ Support berbagai format field name dari SSO server

Jadi SSO server hanya perlu memastikan:
1. UserInfo endpoint mengirim field name dengan benar
2. Tidak set cookie untuk client website
3. Redirect URI validation sudah diimplementasikan

