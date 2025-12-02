# 🚨 Database Connection Failed

## The Problem
The error `Failed to create session` is happening because the Client Website (`localhost:8070`) **cannot connect to your local PostgreSQL database**.

My debug script returned:
```
❌ Connection failed: pq: password authentication failed for user "postgres"
```

This means the default password `postgres123` is incorrect for your database.

---

## ✅ The Solution

You need to add your correct PostgreSQL credentials to the `.env` file in the `client-dinas-pendidikan` folder.

### Step 1: Open `.env` file
Open the file `/Users/muhammadbagaspradana/Documents/bagas 2025/Pusdatin Dinas Pendidikan/client-dinas-pendidikan/.env`

### Step 2: Add Database Config
Add these lines to the bottom of the file (replace `YOUR_PASSWORD` with your actual DB password):

```bash
# PostgreSQL Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5433
POSTGRES_DB=dinas_pendidikan
POSTGRES_USER=postgres
POSTGRES_PASSWORD=YOUR_REAL_PASSWORD_HERE
```

**Note:** If you don't know your password, try common ones like:
- `postgres`
- `admin`
- `123456`
- `root`
- (empty string)

### Step 3: Verify Connection
After updating `.env`, run the debug script again to verify:

```bash
go run debug_db.go
```

If it says `✅ Connected to database successfully!`, then you are fixed!

### Step 4: Restart Server
Don't forget to restart your server to load the new `.env` settings:

```bash
# Ctrl+C to stop
go run dev.go
```

---

## Why did this happen?
The code has default values (password: `postgres123`), but your local database uses a different password. Since these variables were missing from your `.env` file, it tried to use the wrong default password.
