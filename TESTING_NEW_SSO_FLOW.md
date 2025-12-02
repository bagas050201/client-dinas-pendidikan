# 🧪 Testing Guide - New SSO Flow

## Prerequisites

1. **Keycloak**: Running on `localhost:8080`
2. **Portal SSO**: Running on `localhost:3000`
3. **Client Website (This)**: Running on `localhost:8070`
4. **PostgreSQL**: Running on `localhost:5433`

## Environment Variables

Make sure your `.env` file contains:

```bash
# Keycloak Configuration
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=dinas-pendidikan
KEYCLOAK_CLIENT_ID=localhost-8070-website-dinas-pendidikan
KEYCLOAK_REDIRECT_URI=http://localhost:8070/callback

# PostgreSQL Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5433
POSTGRES_DB=dinas_pendidikan
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres123

# Supabase Configuration (for session storage)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key

# Server Configuration
PORT=8070
```

## Keycloak Client Configuration

Register this client in Keycloak:

```bash
# Client ID
localhost-8070-website-dinas-pendidikan

# Valid Redirect URIs
http://localhost:8070/callback
http://localhost:8070/oauth/callback
http://localhost:8070/
http://localhost:8070/*

# Client Authentication
OFF (public client)

# Standard Flow Enabled
ON

# Direct Access Grants Enabled
OFF
```

## Test Scenarios

### ✅ Scenario 1: First Time Login (No Keycloak Session)

**Steps:**
1. Open **incognito/private window**
2. Navigate to: `http://localhost:8070`
3. **Expected:** Client checks local session → not found → redirects to Keycloak with `prompt=none`
4. **Expected:** Keycloak sees no session → returns `error=login_required`
5. **Expected:** Client detects error → redirects to Keycloak WITHOUT `prompt=none`
6. **Expected:** Keycloak login form appears
7. Login with test user (e.g., `bagas123` / `password`)
8. **Expected:** Keycloak redirects to `/callback?code=ABC123&state=XYZ789`
9. **Expected:** Client exchanges code for tokens
10. **Expected:** Client creates local session
11. **Expected:** Redirects to `/dashboard` ✅

**Console Logs to Watch:**
```
🔄 No local session found, checking Keycloak session with prompt=none
🔐 Redirecting to Keycloak (prompt=none: true): ...
🔄 Auto-login failed (login_required), redirecting to Keycloak login form
🔐 Redirecting to Keycloak (prompt=none: false): ...
🔐 Authorization code received, redirecting to /callback
🔐 OAuth Callback: Processing callback from Keycloak
✅ Received authorization code: ...
🔄 Exchanging authorization code for token...
✅ Token exchange successful
✅ User info extracted from ID token: email=...
✅ Session created: ...
```

---

### ✅ Scenario 2: Auto-Login (Has Keycloak Session)

**Prerequisites:** Complete Scenario 1 first (so Keycloak session exists)

**Steps:**
1. In **same browser**, open new tab
2. Navigate to Portal SSO: `http://localhost:3000`
3. **Expected:** Already logged in to Portal SSO
4. Click on "Client Website 8070" application card
5. **Expected:** Portal SSO redirects to: `http://localhost:8070` (plain URL, no tokens!)
6. **Expected:** Client checks local session → not found (new tab/cleared cookies)
7. **Expected:** Client redirects to Keycloak with `prompt=none`
8. **Expected:** Keycloak detects existing session → auto-returns authorization code
9. **Expected:** Client exchanges code for tokens
10. **Expected:** Client creates local session
11. **Expected:** Dashboard appears **WITHOUT login form!** ✅

**Console Logs to Watch:**
```
🔄 No local session found, checking Keycloak session with prompt=none
🔐 Redirecting to Keycloak (prompt=none: true): ...
🔐 Authorization code received, redirecting to /callback
🔐 OAuth Callback: Processing callback from Keycloak
✅ Token exchange successful
✅ Dashboard appears (Auto-login success!)
```

**Key Point:** NO login form shown! This is auto-login! 🎉

---

### ✅ Scenario 3: Has Local Session

**Prerequisites:** Complete Scenario 1 or 2

**Steps:**
1. In **same tab**, navigate to: `http://localhost:8070`
2. **Expected:** Client checks local session → **found!**
3. **Expected:** Directly redirects to `/dashboard` ✅
4. **Expected:** No Keycloak redirect needed

**Console Logs to Watch:**
```
✅ User already authenticated, redirecting to dashboard
```

---

### ✅ Scenario 4: Centralized Logout

**Steps:**
1. Complete Scenario 2 (auto-login) to have active sessions in multiple tabs
2. In one tab, click "Logout"
3. **Expected:** Clears local session
4. **Expected:** Redirects to Keycloak logout
5. **Expected:** Keycloak clears SSO session
6. **Expected:** Redirects to Portal SSO
7. Open other tabs with this website
8. **Expected:** Refreshing shows login form (session cleared globally) ✅

---

## Debugging Tips

### Check Cookies

In browser console:
```javascript
// Check local session cookie
document.cookie.split(';').forEach(c => console.log(c.trim()));

// Should see:
// client_dinas_session=...
// sso_access_token=...
// sso_id_token=...
```

### Decode ID Token

```javascript
// Get ID token from cookie
const idToken = document.cookie.split(';')
    .find(c => c.trim().startsWith('sso_id_token='))
    ?.split('=')[1];

// Decode JWT
function parseJwt(token) {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => 
        '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
    ).join(''));
    return JSON.parse(jsonPayload);
}

console.log('ID Token Claims:', parseJwt(idToken));
// Should see: email, name, sub, etc.
```

### Check Backend Logs

Look for these patterns:
```bash
# Auto-login flow
grep "prompt=none" server.log

# Token exchange
grep "Token exchange" server.log

# Session creation
grep "Session created" server.log

# Errors
grep "ERROR" server.log
grep "❌" server.log
```

---

## Common Issues & Solutions

### Issue 1: "Missing code"

 **Cause:** Callback handler not receiving authorization code
**Solution:** Check Keycloak redirect URI configuration

### Issue 2: "Invalid state"

**Cause:** State mismatch (CSRF protection)
**Solution:** Clear cookies and try again

### Issue 3: "Token exchange failed: 400"

**Cause:** Invalid redirect_uri or client_id
**Solution:** Verify Keycloak client configuration matches `.env`

### Issue 4: "Failed to create session for email"

**Cause:** User not found in PostgreSQL database
**Solution:** Check if user exists:
```sql
SELECT * FROM pengguna WHERE email = 'your-email@example.com';
```

### Issue 5: Infinite redirect loop

**Cause:** `prompt=none` always failing
**Solution:** Clear Keycloak session and try fresh login

---

## Success Criteria

✅ **Scenario 1:** Can login with Keycloak form  
✅ **Scenario 2:** Can auto-login without form (prompt=none)  
✅ **Scenario 3:** Can use local session without Keycloak redirect  
✅ **Scenario 4:** Logout clears all sessions (centralized)  
✅ **No tokens in URL**: Portal SSO redirects without query parameters  
✅ **Logs are clear**: Console shows expected flow for each scenario  

---

## Next Steps After Testing

1. ✅ Flow works locally
2. Update environment variables for production
3. Register production client in Keycloak
4. Update Portal SSO to redirect to production URL
5. Deploy and test in production
6. Monitor logs for any issues

**Happy Testing! 🚀**
