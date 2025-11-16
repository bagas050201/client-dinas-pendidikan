# 🔍 Panduan Debugging SSO Integration

## Cara Cek Error SSO

### 1. Cek Server Logs di Terminal

Ketika menjalankan server dengan `go run dev.go`, semua log akan muncul di terminal.

**Langkah:**
1. Buka terminal dimana server berjalan
2. Lakukan SSO login
3. Perhatikan log yang muncul, terutama:
   - `🔄 Exchanging code to token` - Mulai exchange
   - `📡 Token URL` - URL yang dipanggil
   - `📤 Request body` - Data yang dikirim
   - `📥 Response` - Response dari SSO server
   - `❌ ERROR` - Jika ada error

**Contoh log yang baik:**
```
🔄 Exchanging code to token: code=ABC123..., redirect_uri=http://localhost:8070/api/callback, client_id=client-dinas-pendidikan
📡 Token URL: http://localhost:8080/api/token
📤 Request body: grant_type=authorization_code&code=ABC123...&redirect_uri=http://localhost:8070/api/callback&client_id=client-dinas-pendidikan
📥 Response: Status 200, Body: {"access_token":"...","token_type":"Bearer","expires_in":3600}
✅ Token exchange berhasil: token_type=Bearer, expires_in=3600
```

**Contoh log error:**
```
🔄 Exchanging code to token: code=ABC123..., redirect_uri=http://localhost:8070/api/callback, client_id=client-dinas-pendidikan
📡 Token URL: http://localhost:8080/api/token
📤 Request body: grant_type=authorization_code&code=ABC123...&redirect_uri=http://localhost:8070/api/callback&client_id=client-dinas-pendidikan
📥 Response: Status 500, Body: {"error":"server_error","error_description":"Error membuat token"}
❌ ERROR exchanging code for token: server_error: Error membuat token
```

### 2. Cek Browser DevTools

**Network Tab:**
1. Buka DevTools (F12 atau Cmd+Option+I)
2. Pilih tab **Network**
3. Lakukan SSO login
4. Cari request ke `/api/callback`
5. Klik request tersebut
6. Lihat:
   - **Headers** → Request URL, Request Headers, Response Headers
   - **Payload** → Query parameters (code, state)
   - **Response** → Error message dari server

**Console Tab:**
1. Buka tab **Console**
2. Cek apakah ada JavaScript errors
3. Cek apakah ada network errors

### 3. Test Token Exchange dengan curl

Test langsung ke SSO server untuk melihat response:

```bash
# Ganti CODE dengan authorization code yang sebenarnya
curl -X POST http://localhost:8080/api/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_CODE_HERE" \
  -d "redirect_uri=http://localhost:8070/api/callback" \
  -d "client_id=client-dinas-pendidikan" \
  -v
```

**Output yang diharapkan (success):**
```
< HTTP/1.1 200 OK
< Content-Type: application/json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email"
}
```

**Output error:**
```
< HTTP/1.1 500 Internal Server Error
< Content-Type: application/json
{
  "error": "server_error",
  "error_description": "Error membuat token"
}
```

### 4. Cek Environment Variables

Pastikan environment variables sudah benar:

```bash
# Di terminal, cek env vars
echo $SSO_SERVER_URL
echo $SSO_CLIENT_ID
echo $SSO_REDIRECT_URI

# Atau cek di .env file
cat .env | grep SSO
```

**Harus ada:**
- `SSO_SERVER_URL=http://localhost:8080` (atau URL SSO production)
- `SSO_CLIENT_ID=client-dinas-pendidikan`
- `SSO_REDIRECT_URI=http://localhost:8070/api/callback`

### 5. Cek SSO Server Logs

Jika SSO server juga berjalan di localhost:8080, cek logs di terminal SSO server juga.

**Error "Error membuat token" biasanya berarti:**
- SSO server tidak bisa membuat JWT token
- Database error di SSO server
- Configuration error di SSO server
- Authorization code sudah expired atau invalid

### 6. Checklist Debugging

**✅ Cek di Client (localhost:8070):**
- [ ] Server running dan bisa diakses
- [ ] Environment variables sudah di-set
- [ ] Logs muncul di terminal
- [ ] Request ke `/api/callback` diterima

**✅ Cek di SSO Server (localhost:8080):**
- [ ] SSO server running
- [ ] Endpoint `/api/token` bisa diakses
- [ ] Client ID terdaftar di SSO
- [ ] Redirect URI sesuai dengan yang didaftarkan
- [ ] Authorization code valid dan belum expired

**✅ Cek Request/Response:**
- [ ] Request body format benar (application/x-www-form-urlencoded)
- [ ] Semua parameter ada (grant_type, code, redirect_uri, client_id)
- [ ] Response status code
- [ ] Response body berisi error message

## Common Errors dan Solusinya

### Error: "server_error: Error membuat token"

**Kemungkinan penyebab:**
1. SSO server tidak bisa membuat JWT token (masalah di SSO server)
2. Database error di SSO server
3. Authorization code sudah expired (10 menit)
4. Authorization code sudah digunakan sebelumnya

**Solusi:**
1. Cek logs SSO server untuk detail error
2. Coba dengan authorization code baru (login ulang)
3. Pastikan SSO server database connection OK
4. Pastikan SSO server JWT configuration OK

### Error: "invalid_client"

**Kemungkinan penyebab:**
- Client ID tidak terdaftar di SSO
- Client ID salah

**Solusi:**
- Pastikan `SSO_CLIENT_ID=client-dinas-pendidikan` sesuai dengan yang didaftarkan di SSO admin panel

### Error: "invalid_grant"

**Kemungkinan penyebab:**
- Authorization code sudah expired (10 menit)
- Authorization code sudah digunakan
- Redirect URI tidak sesuai

**Solusi:**
- Login ulang untuk mendapatkan code baru
- Pastikan redirect URI exact match dengan yang didaftarkan

### Error: "redirect_uri_mismatch"

**Kemungkinan penyebab:**
- Redirect URI tidak sesuai dengan yang didaftarkan di SSO

**Solusi:**
- Pastikan `SSO_REDIRECT_URI` exact match (termasuk http vs https, trailing slash, dll)
- Daftarkan redirect URI di SSO admin panel

## Script Testing

Buat file `test_sso.sh` untuk test cepat:

```bash
#!/bin/bash

# Test SSO Token Exchange
echo "Testing SSO Token Exchange..."
echo ""

# Ganti dengan code yang sebenarnya
CODE="YOUR_AUTHORIZATION_CODE_HERE"

curl -X POST http://localhost:8080/api/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$CODE" \
  -d "redirect_uri=http://localhost:8070/api/callback" \
  -d "client_id=client-dinas-pendidikan" \
  -v | jq .

echo ""
echo "Done!"
```

## Tips Debugging

1. **Gunakan logging yang detail** - Semua log sudah ditambahkan di kode
2. **Cek kedua server** - Client dan SSO server
3. **Test dengan curl** - Untuk isolate masalah
4. **Cek network tab** - Untuk melihat request/response actual
5. **Cek browser console** - Untuk JavaScript errors

## Next Steps

Jika masih error setelah cek semua di atas:
1. Copy paste log lengkap dari terminal
2. Copy paste response dari SSO server
3. Cek SSO server logs juga
4. Pastikan SSO server configuration benar

