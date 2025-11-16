# Integrasi SSO untuk Client Dinas Pendidikan

## Overview

Website client telah diintegrasikan dengan SSO (Single Sign-On) menggunakan OAuth 2.0 Authorization Code flow dengan PKCE (Proof Key for Code Exchange) untuk keamanan tambahan.

## Environment Variables

Tambahkan environment variables berikut ke `.env`:

```bash
# SSO Configuration
SSO_SERVER_URL=https://sso-dinas-pendidikan.vercel.app
SSO_CLIENT_ID=your-client-id
SSO_REDIRECT_URI=https://client-dinas-pendidikan.vercel.app/callback
SSO_STATE_SECRET=your-state-secret  # Optional, untuk validasi state tambahan
```

## Flow SSO

### 1. User Memulai SSO Login

User klik tombol **"Login dengan SSO"** di halaman login.

**Endpoint:** `GET /sso/authorize`

**Yang Terjadi:**
- Generate PKCE `code_verifier` dan `code_challenge`
- Generate `state` untuk CSRF protection
- Simpan `code_verifier` dan `state` di cookie (expires 10 menit)
- Redirect ke SSO authorize endpoint dengan parameters:
  - `response_type=code`
  - `client_id=<SSO_CLIENT_ID>`
  - `redirect_uri=<SSO_REDIRECT_URI>`
  - `code_challenge=<PKCE_CHALLENGE>`
  - `code_challenge_method=S256`
  - `state=<RANDOM_STATE>`
  - `scope=openid profile email`

### 2. SSO Redirect ke Callback

Setelah user login di SSO, SSO akan redirect ke callback URL dengan authorization code.

**Endpoint:** `GET /callback?code=<AUTHORIZATION_CODE>&state=<STATE>`

**Yang Terjadi:**
1. Validasi `state` parameter (bandingkan dengan cookie)
2. Ambil `code_verifier` dari cookie
3. Exchange authorization code ke access token via POST ke `/api/token`
4. Ambil user info dari SSO via GET ke `/api/userinfo`
5. Cari atau buat user di database client
6. Buat session user di database
7. Set cookie `sso_admin_session`
8. Redirect ke `/dashboard`

### 3. Error Handling

Jika terjadi error di setiap step:
- Error dari SSO → redirect ke `/login?error=sso_error&message=<ERROR>`
- Code tidak valid → redirect ke `/login?error=missing_code`
- State mismatch → redirect ke `/login?error=state_mismatch`
- Token exchange gagal → redirect ke `/login?error=token_exchange_failed`
- User info gagal → redirect ke `/login?error=userinfo_failed`

## Security Features

### 1. PKCE (Proof Key for Code Exchange)

- **Code Verifier**: Random 32-byte string, base64URL encoded
- **Code Challenge**: SHA256(code_verifier), base64URL encoded
- **Method**: S256 (SHA256)

PKCE mencegah authorization code interception attack.

### 2. State Parameter

- Random 16-byte string, base64URL encoded
- Disimpan di cookie saat memulai flow
- Divalidasi saat callback untuk CSRF protection

### 3. Cookie Security

- `sso_code_verifier`: HttpOnly, Path=/, MaxAge=600 (10 menit)
- `sso_state`: HttpOnly, Path=/, MaxAge=600 (10 menit)
- `sso_admin_session`: HttpOnly, Path=/, MaxAge=86400 (24 jam)

### 4. Token Storage

- Access token **TIDAK** disimpan di client
- Hanya digunakan untuk get user info, kemudian dibuang
- Session dibuat di database client untuk authentication

## API Endpoints

### SSO Server Endpoints

1. **Authorize**: `GET https://sso-dinas-pendidikan.vercel.app/api/authorize`
   - Memulai SSO flow
   - Redirect ke SSO login page jika belum login

2. **Token**: `POST https://sso-dinas-pendidikan.vercel.app/api/token`
   - Exchange authorization code ke access token
   - Content-Type: `application/x-www-form-urlencoded`
   - Body: `grant_type=authorization_code&code=<CODE>&redirect_uri=<URI>&client_id=<ID>&code_verifier=<VERIFIER>`

3. **UserInfo**: `GET https://sso-dinas-pendidikan.vercel.app/api/userinfo`
   - Get user information
   - Header: `Authorization: Bearer <ACCESS_TOKEN>`

### Client Endpoints

1. **SSO Authorize**: `GET /sso/authorize`
   - Memulai SSO flow
   - Generate PKCE dan state
   - Redirect ke SSO

2. **SSO Callback**: `GET /callback?code=<CODE>&state=<STATE>`
   - Handle callback dari SSO
   - Exchange code, get user info, create session
   - Redirect ke dashboard

## Testing

### 1. Test dengan Browser

1. Buka `http://localhost:8070/login`
2. Klik tombol **"Login dengan SSO"**
3. Login di SSO (jika belum login)
4. Harus redirect kembali ke client dan login berhasil
5. Cek cookie `sso_admin_session` di DevTools
6. Harus redirect ke `/dashboard`

### 2. Test Error Cases

**Test expired code:**
- Tunggu 10 menit setelah dapat code
- Coba akses callback dengan code yang sama
- Harus return error

**Test invalid state:**
- Manipulasi state di URL callback
- Harus return error state_mismatch

**Test missing code:**
- Akses `/callback` tanpa parameter code
- Harus return error missing_code

### 3. Test dengan curl

```bash
# Test SSO authorize (akan redirect ke SSO)
curl -i http://localhost:8070/sso/authorize

# Test callback dengan valid code (harus dari SSO)
curl -i "http://localhost:8070/callback?code=VALID_CODE&state=VALID_STATE" \
  -H "Cookie: sso_code_verifier=VERIFIER; sso_state=STATE"
```

## Troubleshooting

### 1. Redirect URI Mismatch

**Error:** `invalid_request` atau `redirect_uri_mismatch`

**Solusi:**
- Pastikan `SSO_REDIRECT_URI` di `.env` sama dengan yang didaftarkan di SSO admin panel
- Pastikan URL exact match (termasuk trailing slash, http vs https)

### 2. Client ID Invalid

**Error:** `invalid_client`

**Solusi:**
- Pastikan `SSO_CLIENT_ID` di `.env` sesuai dengan yang didaftarkan di SSO
- Pastikan client sudah terdaftar dan aktif di SSO admin panel

### 3. Code Already Used

**Error:** `invalid_grant` dengan message "code already used"

**Solusi:**
- Authorization code hanya bisa digunakan sekali
- Jika error ini muncul, user harus memulai flow dari awal

### 4. Code Expired

**Error:** `invalid_grant` dengan message "code expired"

**Solusi:**
- Authorization code berlaku 10 menit
- User harus memulai flow dari awal jika code expired

### 5. PKCE Verification Failed

**Error:** `invalid_grant` dengan message "code_verifier invalid"

**Solusi:**
- Pastikan code_verifier yang digunakan sama dengan yang digunakan saat generate code_challenge
- Pastikan cookie `sso_code_verifier` tidak expired atau terhapus

## Best Practices

1. **Selalu gunakan HTTPS di production**
   - Jangan gunakan HTTP untuk komunikasi dengan SSO
   - Set `Secure=true` untuk cookie di production

2. **Validasi semua input**
   - Validasi state parameter
   - Validasi authorization code format
   - Validasi user info dari SSO

3. **Error handling yang baik**
   - Jangan expose error teknis ke user
   - Gunakan pesan error yang user-friendly
   - Log error untuk debugging

4. **Session management**
   - Set expiration time yang reasonable (24 jam)
   - Revoke session saat logout
   - Validasi session di setiap protected route

5. **Monitoring**
   - Monitor failed SSO attempts
   - Monitor token exchange failures
   - Alert jika ada suspicious activity

## File Structure

```
api/
  ├── ui_sso.go          # SSO handlers (authorize, callback)
  ├── ui_login.go        # Login handler (updated dengan tombol SSO)
  └── main_handler.go    # Main router (updated dengan SSO routes)

internal/
  └── session_helper.go  # Session management (reused untuk SSO)
```

## Dependencies

Tidak ada dependency tambahan yang diperlukan. Semua menggunakan standard library Go:
- `crypto/rand` untuk generate random bytes
- `crypto/sha256` untuk PKCE code challenge
- `encoding/base64` untuk encoding
- `net/http` untuk HTTP requests

## Next Steps

1. Daftarkan client di SSO admin panel
2. Set environment variables di production
3. Test flow lengkap di staging
4. Deploy ke production
5. Monitor logs untuk error atau issue

