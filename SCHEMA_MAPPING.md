# Schema Mapping: Kode vs Database Supabase

## Tabel `sesi_login`

### Mapping Kolom

| Kode (Go) | Database Supabase | Keterangan |
|-----------|-------------------|------------|
| `user_id` | `id_pengguna` | Foreign key ke tabel `pengguna` |
| `session_id` | `id_sesi` | Session ID unik |
| `expires_at` | `kadaluarsa` | Timestamp expiration |
| `ip_address` | `ip` | IP address user |
| `user_agent` | `user_agent` | User agent browser |
| `aktif` | ❌ Tidak ada | Tidak ada kolom aktif di schema |

### Schema Database

```sql
CREATE TABLE sesi_login (
  id UUID PRIMARY KEY,
  id_sesi TEXT NOT NULL,
  id_pengguna UUID REFERENCES pengguna(id_pengguna),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  kadaluarsa TIMESTAMPTZ NOT NULL,
  ip TEXT,
  user_agent TEXT
);
```

### Query Examples

**Create Session:**
```go
sessionData := map[string]interface{}{
    "id_pengguna": userID,
    "id_sesi":     sessionID,
    "ip":          ipAddress,
    "user_agent":  userAgent,
    "kadaluarsa": expiresAt,
}
```

**Validate Session:**
```sql
SELECT id_pengguna 
FROM sesi_login 
WHERE id_sesi = ? AND kadaluarsa > NOW()
```

**Get Session with User:**
```sql
SELECT *, pengguna(*) 
FROM sesi_login 
WHERE id_sesi = ? AND kadaluarsa > NOW()
```

**Delete Session:**
```sql
DELETE FROM sesi_login 
WHERE id_sesi = ?
```

## Tabel `pengguna`

### Kolom yang Digunakan

| Kode (Go) | Database Supabase | Keterangan |
|-----------|-------------------|------------|
| `id` | `id_pengguna` | Primary key (UUID) |
| `email` | `email` | Email user |
| `nama_lengkap` | `nama_lengkap` | Nama lengkap |
| `peran` | `peran` | Role user |
| `aktif` | `aktif` | Status aktif |
| `password_hash` | `password_hash` | Bcrypt hash |
| `password` | `password` | Plain text (fallback) |

## File yang Sudah Diupdate

1. ✅ `internal/session_helper.go`
   - `CreateSession()` - menggunakan `id_pengguna`, `id_sesi`, `ip`, `kadaluarsa`
   - `ValidateSession()` - query menggunakan `id_sesi`, `kadaluarsa`, `id_pengguna`
   - `ClearSession()` - DELETE menggunakan `id_sesi`

2. ✅ `api/main_handler.go`
   - Semua `sessionData` menggunakan nama kolom baru
   - Semua query ke `sesi_login` menggunakan `id_sesi`, `kadaluarsa`
   - Semua DELETE menggunakan `id_sesi`

## Testing

Setelah update, test:
1. Login via SSO → cek apakah session dibuat di database
2. Login direct → cek apakah session dibuat di database
3. Akses protected route → cek apakah session divalidasi
4. Logout → cek apakah session terhapus

## Troubleshooting

Jika masih error "column does not exist":
1. Cek apakah semua query sudah menggunakan nama kolom baru
2. Cek apakah semua insert sudah menggunakan nama kolom baru
3. Cek server logs untuk melihat query yang dikirim ke Supabase

