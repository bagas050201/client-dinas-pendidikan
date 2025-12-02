# 🔧 Keycloak Client Setup for localhost:8070

## Problem
Getting "Internal Server Error" when accessing:
```
http://localhost:8080/realms/dinas-pendidikan/protocol/openid-connect/auth?client_id=localhost-8070-website-dinas-pendidikan&prompt=none...
```

**Cause:** The client `localhost-8070-website-dinas-pendidikan` doesn't exist or is misconfigured in Keycloak.

---

## Solution: Create the Client in Keycloak

### Step 1: Access Keycloak Admin Console

1. Open browser: **http://localhost:8080/admin**
2. Login dengan:
   - Username: `admin`
   - Password: `admin`
3. Select Realm: **dinas-pendidikan**

---

### Step 2: Create New Client

1. Click **Clients** di sidebar kiri
2. Click tombol **Create client**
3. Isi form:

**General Settings:**
```
Client type: OpenID Connect
Client ID: localhost-8070-website-dinas-pendidikan
```

4. Click **Next**

---

### Step 3: Capability Config

**Authentication flow:**
- ✅ **Standard flow** (checked) ← PENTING!
- ✅ **Direct access grants** (checked)
- ❌ Implicit flow (unchecked)
- ❌ Service accounts (unchecked)
- ❌ OAuth 2.0 Device Authorization Grant (unchecked)
- ❌ OIDC CIBA Grant (unchecked)

**Client authentication:**
- ❌ **OFF** ← PENTING! (ini public client, bukan confidential)

4. Click **Next**

---

### Step 4: Login Settings

**Root URL:**
```
http://localhost:8070
```

**Home URL:**
```
http://localhost:8070/
```

**Valid redirect URIs:** (SANGAT PENTING!)
```
http://localhost:8070/callback
http://localhost:8070/oauth/callback
http://localhost:8070/
http://localhost:8070/*
```

**Valid post logout redirect URIs:**
```
http://localhost:3000
http://localhost:3000/*
```

**Web origins:**
```
http://localhost:8070
```

5. Click **Save**

---

## Verification Checklist

After creating the client, verify:

### ✅ General Settings Tab
- [x] Client ID: `localhost-8070-website-dinas-pendidikan`
- [x] Name: (optional, e.g., "Client Website 8070")
- [x] Enabled: **ON**

### ✅ Access Settings Tab
- [x] Root URL: `http://localhost:8070`
- [x] Home URL: `http://localhost:8070/`
- [x] Valid Redirect URIs includes:
  - `http://localhost:8070/callback`
  - `http://localhost:8070/oauth/callback`
  - `http://localhost:8070/`
  - `http://localhost:8070/*`
- [x] Web origins: `http://localhost:8070`

### ✅ Capability Config Tab
- [x] Client authentication: **OFF** (public client)
- [x] Authorization: **OFF**
- [x] Authentication flow:
  - ✅ Standard flow: **ON**
  - ✅ Direct access grants: **ON**
  - ❌ Implicit flow: **OFF**
  - ❌ Service accounts: **OFF**

### ✅ Login Settings Tab
- [x] Login theme: (default or choose)
- [x] Consent required: **OFF** (optional, untuk skip consent screen)

---

## Alternative: Use Script (Faster!)

If you have Keycloak CLI tools, you can create the client with this command:

```bash
# Navigate to Keycloak directory
cd /path/to/keycloak

# Create client
bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin

bin/kcadm.sh create clients -r dinas-pendidikan -s clientId=localhost-8070-website-dinas-pendidikan -s enabled=true -s publicClient=true -s standardFlowEnabled=true -s directAccessGrantsEnabled=true -s 'redirectUris=["http://localhost:8070/callback","http://localhost:8070/oauth/callback","http://localhost:8070/","http://localhost:8070/*"]' -s 'webOrigins=["http://localhost:8070"]' -s rootUrl=http://localhost:8070 -s baseUrl=http://localhost:8070/
```

---

## Testing After Setup

1. **Test the auth URL again:**
   ```
   http://localhost:8080/realms/dinas-pendidikan/protocol/openid-connect/auth?client_id=localhost-8070-website-dinas-pendidikan&prompt=none&redirect_uri=http%3A%2F%2Flocalhost%3A8070%2Fcallback&response_type=code&scope=openid+email+profile&state=test123
   ```

2. **Expected results:**
   - If NOT logged in: Returns `error=login_required` (redirect to client with error param) ✅
   - If already logged in: Returns authorization code (redirect to client with code param) ✅
   - Should NOT show "Internal Server Error" anymore! ✅

---

## Common Issues

### Issue 1: "Client not found"
**Solution:** Client ID typo. Make sure it's exactly `localhost-8070-website-dinas-pendidikan`

### Issue 2: "Invalid redirect_uri"
**Solution:** Add all variations to Valid Redirect URIs:
- `http://localhost:8070/callback`
- `http://localhost:8070/*` (wildcard untuk flexibility)

### Issue 3: "unauthorized_client"
**Solution:** 
- Make sure "Standard flow" is **enabled**
- Make sure "Client authentication" is **OFF** (public client)

---

## Visual Guide

Your Keycloak client settings should look similar to the Portal SSO client (`sso-dinas-pendidikan`), but with different URLs:

### Portal SSO (localhost:3000) ← Your existing working client
```
Client ID: sso-dinas-pendidikan
Root URL: http://localhost:3000
Valid Redirect URIs: http://localhost:3000/auth/callback, etc.
```

### Client Website (localhost:8070) ← New client to create
```
Client ID: localhost-8070-website-dinas-pendidikan
Root URL: http://localhost:8070
Valid Redirect URIs: http://localhost:8070/callback, etc.
```

Both should have:
- Client authentication: **OFF**
- Standard flow: **ON**

---

## Next Steps After Creating Client

1. **Restart your client website** (if needed):
   ```bash
   # Ctrl+C to stop current server
   go run dev.go
   ```

2. **Test the flow:**
   - Open incognito: `http://localhost:8070`
   - Should redirect to Keycloak
   - Should either show login form OR auto-redirect with code

3. **If still having issues:**
   - Check server logs for errors
   - Verify `.env` file has correct `KEYCLOAK_CLIENT_ID`
   - Verify all redirect URIs are exact matches

---

**Let me know if you need help with any step!**
