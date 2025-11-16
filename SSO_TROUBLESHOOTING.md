# SSO Troubleshooting Guide

## Error: "The deployment could not be found on Vercel" (404)

### Penyebab
Client website mencoba exchange token ke SSO server di production (`https://sso-dinas-pendidikan.vercel.app`), tapi SSO server belum di-deploy atau URL-nya salah.

### Solusi

#### 1. Development (Localhost)

**Pastikan SSO server berjalan di `localhost:8080`**

```bash
# Di terminal SSO server
cd sso-dinas-pendidikan
go run dev.go
# Server harus berjalan di http://localhost:8080
```

**Set environment variable di client website:**

Buat file `.env` di root project:
```bash
SSO_SERVER_URL=http://localhost:8080
SSO_REDIRECT_URI=http://localhost:8070/api/callback
SSO_CLIENT_ID=client-dinas-pendidikan
```

**Restart client server:**
```bash
go run dev.go
```

#### 2. Production (Vercel)

**Pastikan SSO server sudah di-deploy ke Vercel:**
- SSO server harus di-deploy ke `https://sso-dinas-pendidikan.vercel.app`
- Atau update `SSO_SERVER_URL` di client website sesuai URL SSO server yang benar

**Set environment variables di Vercel Dashboard:**

1. Buka Vercel Dashboard → Project → Settings → Environment Variables
2. Tambahkan:
   ```
   SSO_SERVER_URL=https://sso-dinas-pendidikan.vercel.app
   SSO_REDIRECT_URI=https://client-dinas-pendidikan.vercel.app/api/callback
   SSO_CLIENT_ID=client-dinas-pendidikan
   ```
3. Redeploy client website

### Auto-Detection

Kode akan auto-detect environment:
- **Default untuk development**: `http://localhost:8080` (jika `SSO_SERVER_URL` tidak di-set)
- **Untuk production**: Set `SSO_SERVER_URL` di Vercel environment variables

### Testing

#### Test di Development

1. **Start SSO server:**
   ```bash
   cd sso-dinas-pendidikan
   go run dev.go
   # Server berjalan di http://localhost:8080
   ```

2. **Start client server:**
   ```bash
   cd client-dinas-pendidikan
   # Pastikan .env sudah di-set
   go run dev.go
   # Server berjalan di http://localhost:8070
   ```

3. **Test SSO flow:**
   - Buka `http://localhost:8070/login`
   - Klik "Login dengan SSO"
   - Login di SSO server
   - Klik "Lanjut ke Aplikasi"
   - Seharusnya redirect ke client dashboard

#### Test di Production

1. **Pastikan SSO server sudah di-deploy:**
   ```bash
   # Cek apakah SSO server accessible
   curl https://sso-dinas-pendidikan.vercel.app/api/token
   ```

2. **Pastikan environment variables sudah di-set di Vercel**

3. **Test SSO flow:**
   - Buka `https://client-dinas-pendidikan.vercel.app/login`
   - Klik "Login dengan SSO"
   - Login di SSO server
   - Klik "Lanjut ke Aplikasi"
   - Seharusnya redirect ke client dashboard

### Debugging

#### Cek Logs

**Client website logs:**
- Cari log dengan emoji: 🔄, 📤, 📥, ❌
- Log akan menunjukkan:
  - SSO Server URL yang digunakan
  - Request yang dikirim
  - Response yang diterima

**SSO server logs:**
- Cek terminal SSO server untuk melihat request yang diterima
- Pastikan endpoint `/api/token` sudah ada dan berfungsi

#### Common Issues

1. **404 Not Found**
   - SSO server belum di-deploy
   - URL SSO server salah
   - Solusi: Deploy SSO server atau perbaiki `SSO_SERVER_URL`

2. **500 Internal Server Error**
   - Error di SSO server saat membuat token
   - Solusi: Cek logs SSO server untuk detail error

3. **CORS Error**
   - SSO server tidak allow request dari client
   - Solusi: Set CORS headers di SSO server

4. **State Mismatch**
   - State cookie tidak match dengan state dari SSO
   - Solusi: Clear cookies dan coba lagi

### Checklist

- [ ] SSO server berjalan (development) atau di-deploy (production)
- [ ] `SSO_SERVER_URL` sudah di-set dengan benar
- [ ] `SSO_REDIRECT_URI` sudah di-set dengan benar
- [ ] `SSO_CLIENT_ID` sudah di-set dengan benar
- [ ] Client ID sudah terdaftar di SSO server
- [ ] Redirect URI sudah terdaftar di SSO server
- [ ] Cookies tidak di-block oleh browser
- [ ] Network tidak block request ke SSO server

