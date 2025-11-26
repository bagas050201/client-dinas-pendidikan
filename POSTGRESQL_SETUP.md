# PostgreSQL Database Setup

## 📋 Overview

Website client menggunakan **PostgreSQL** sebagai database utama untuk user authentication dan session management.

## ⚙️ Konfigurasi Database

### Environment Variables

Tambahkan ke `.env`:

```bash
# PostgreSQL Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5433
POSTGRES_DB=dinas_pendidikan
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres123

# Supabase Configuration (untuk session storage saja)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key

# JWT Configuration (Optional)
JWT_PUBLIC_KEY=your-jwt-public-key

# Server Configuration
PORT=8070
```

### Database Schema

#### PostgreSQL (Database Utama)

Tabel `pengguna` dengan struktur:

```sql
CREATE TABLE pengguna (
    id_pengguna UUID PRIMARY KEY,
    nama_pengguna VARCHAR(100),
    email VARCHAR(255) UNIQUE NOT NULL,
    nama_lengkap VARCHAR(255) NOT NULL,
    peran VARCHAR(50) NOT NULL,
    password VARCHAR(255),
    aktif BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Contoh data:**
```sql
INSERT INTO pengguna (id_pengguna, nama_pengguna, email, nama_lengkap, peran, aktif) VALUES 
('05374820-444f-45a4-b9e1-487284b35206', 'kepsek', 'kepsek@dinas-pendidikan.go.id', 'Kepala Sekolah', 'kepsek', true),
('8fde272f-a694-4d1a-96c7-85a2a64b3352', 'bagas123', 'bagas123@gmail.com', 'Bagas Pradana', 'admin', true);
```

## 🔄 Flow SSO dengan PostgreSQL

```
1. SSO Login → Extract email dari token
2. Lookup user di PostgreSQL berdasarkan email
3. Jika ditemukan → Create session di Supabase
4. Redirect ke dashboard
```

## 🔍 Cara Kerja

### 1. User Authentication

```go
// Cek PostgreSQL untuk user
pgUser, err := getUserFromPostgreSQL(email)
if err == nil {
    user = pgUser
    userSource = "PostgreSQL"
} else {
    // User tidak ditemukan
    return error
}
```

### 2. Session Storage

**Session disimpan di Supabase** untuk konsistensi dengan sistem lain:
- User dari PostgreSQL → Session di Supabase
- Sistem otomatis sync user ke Supabase jika diperlukan

### 3. Log Output

```
🔍 Checking PostgreSQL database for user: kepsek@dinas-pendidikan.go.id
✅ User found in PostgreSQL database: kepsek@dinas-pendidikan.go.id
📋 User found in PostgreSQL - Name: Kepala Sekolah, Role: kepsek
✅ Session created successfully for user from PostgreSQL
```

## 🧪 Testing

### 1. Setup Database

1. **Pastikan PostgreSQL berjalan di port 5433**
2. **Create database `dinas_pendidikan`**
3. **Create tabel `pengguna` dengan schema di atas**
4. **Insert test user**

### 2. Test Connection

```bash
# Test koneksi PostgreSQL
psql -h localhost -p 5433 -U postgres -d dinas_pendidikan
```

### 3. Test SSO Login

1. **Buat user di PostgreSQL**
2. **Test SSO login dari Portal SSO**
3. **Expected log:**
   ```
   ✅ User found in PostgreSQL database
   📋 User found in PostgreSQL - Name: [nama], Role: [peran]
   ✅ Session created successfully
   ```

## 🔧 Troubleshooting

### Error: "failed to connect to PostgreSQL"

**Penyebab:** PostgreSQL tidak berjalan atau konfigurasi salah.

**Solusi:**
1. Pastikan PostgreSQL berjalan di port 5433
2. Cek kredensial di environment variables
3. Test koneksi manual

### Error: "user not found"

**Penyebab:** User belum dibuat di PostgreSQL.

**Solusi:**
1. Buat user di PostgreSQL dengan email yang sesuai
2. Pastikan field `aktif = true`

### Error: "Supabase session error"

**Penyebab:** Session storage ke Supabase gagal.

**Solusi:**
1. Set environment variables Supabase
2. Supabase diperlukan untuk session storage

## 📊 Database Structure

| Field | Type | Description |
|-------|------|-------------|
| `id_pengguna` | UUID | Primary Key |
| `nama_pengguna` | VARCHAR(100) | Username |
| `email` | VARCHAR(255) | Email (unique) |
| `nama_lengkap` | VARCHAR(255) | Full name |
| `peran` | VARCHAR(50) | User role |
| `password` | VARCHAR(255) | Password hash |
| `aktif` | BOOLEAN | Active status |
| `created_at` | TIMESTAMP | Created date |
| `updated_at` | TIMESTAMP | Updated date |

## 🎯 Benefits

1. **Performance:** Direct PostgreSQL access lebih cepat
2. **Consistency:** Semua user data di satu tempat
3. **Reliability:** Tidak bergantung pada multiple database
4. **Simplicity:** Satu source of truth untuk user data

## 🔗 Referensi

- **[SSO_SIMPLE_GUIDE.md](./SSO_SIMPLE_GUIDE.md)** - Panduan SSO Simple
- **[SSO_TROUBLESHOOTING.md](./SSO_TROUBLESHOOTING.md)** - Troubleshooting SSO
