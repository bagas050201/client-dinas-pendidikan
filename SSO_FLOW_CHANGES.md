# 🔄 SSO Flow Update Summary

## What Changed?

Your client website (localhost:8070) has been updated from **SSO Simple (token in URL)** to **Standard OIDC Flow with Keycloak (Authorization Code Flow + prompt=none)**.

---

## ✅ Old Flow (SSO Simple)

```
Portal SSO → Client Website
localhost:3000 → localhost:8070/?sso_token=ABC123&sso_id_token=XYZ789
```

**Problem:** Tokens exposed in URL 🔓

---

## ✅ New Flow (Standard OIDC)

```
Portal SSO → Client (tanpa token)
localhost:3000 → localhost:8070

Client → Keycloak (dengan prompt=none)
localhost:8070 → localhost:8080/auth?prompt=none...

Keycloak → Client (dengan authorization code)
localhost:8080 → localhost:8070/callback?code=ABC123

Client → Exchange code untuk token (backend)
```

**Benefits:**  
✅ Tokens tidak exposed di URL (lebih aman)  
✅ Auto-login untuk semua website (true SSO)  
✅ Centralized logout  
✅ Standard OIDC flow  

---

## 📁 Files Created/Modified

### Created:
- ✅ `api/keycloak_helpers.go` - Keycloak integration functions
- ✅ `SSO_NEW_FLOW_IMPLEMENTATION.md` - Implementation guide
- ✅ `TESTING_NEW_SSO_FLOW.md` - Testing guide
- ✅ `SSO_FLOW_CHANGES.md` - This file

### Modified:
- ✅ `api/main_handler.go` - Updated root handler to use new flow
- ✅ `pkg/helpers/utils.go` - Added utility functions for JWT/OAuth

---

## 🔑 Key Changes in Code

### 1. Root Handler (`/`)

**Before:**
```go
// Check for sso_token in URL
ssoToken := r.URL.Query().Get("sso_token")
if ssoToken != "" {
    handleSSOTokenWithCookie(w, r, ssoToken)
}
```

**After:**
```go
// Check local session first
if isAuthenticated(r) {
    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
    return
}

// No session, redirect to Keycloak with prompt=none
redirectToKeycloakLogin(w, r, true) // true = prompt=none
```

### 2. OAuth Callback Handler (`/callback`)

**New:**
```go
func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
    // 1. Get code from Keycloak
    code := r.URL.Query().Get("code")
    
    // 2. Exchange code for tokens
    tokenData, err := exchangeCodeForToken(code)
    
    // 3. Get user info from ID token
    userInfo, err := getUserInfoFromIDToken(tokenData.IDToken)
    
    // 4. Create local session
    sessionID, _ := createSessionFromEmail(r, email)
    
    // 5. Set cookies and redirect
    helpers.SetCookie(w, r, "client_dinas_session", sessionID, 86400)
    http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
```

### 3. Helper Functions

**New functions in `api/keycloak_helpers.go`:**
- `redirectToKeycloakLogin(w, r, withPromptNone)` - Redirects to Keycloak
- `exchangeCodeForToken(code)` - Exchanges authorization code for tokens
- `getUserInfoFromIDToken(idToken)` - Extracts user info from JWT
- `handleOAuthCallback(w, r)` - Processes OAuth callback

**New functions in `pkg/helpers/utils.go`:**
- `Base64URLDecode(input)` - Decodes base64url (for JWT)
- `GenerateRandomString(length)` - Generates secure random string
- `DeleteCookie(w, name)` - Deletes cookie

---

## 🔧 Environment Variables

Add these to your `.env`:

```bash
# Keycloak Configuration (NEW!)
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=dinas-pendidikan
KEYCLOAK_CLIENT_ID=localhost-8070-website-dinas-pendidikan
KEYCLOAK_REDIRECT_URI=http://localhost:8070/callback
```

---

## 🧪 How to Test

See **[TESTING_NEW_SSO_FLOW.md](./TESTING_NEW_SSO_FLOW.md)** for detailed testing guide.

**Quick Test:**
1. Start server: `go run dev.go`
2. Open incognito: `http://localhost:8070`
3. Should redirect to Keycloak login form
4. Login with test user
5. Should create session and show dashboard ✅

**Auto-Login Test:**
1. Login via Portal SSO
2. In new tab, click "Client Website 8070" card
3. Should auto-login WITHOUT form! ✅

---

## 📚 Documentation

- **[SSO_NEW_FLOW_IMPLEMENTATION.md](./SSO_NEW_FLOW_IMPLEMENTATION.md)** - Full implementation guide with code examples
- **[TESTING_NEW_SSO_FLOW.md](./TESTING_NEW_SSO_FLOW.md)** - Testing scenarios and debugging tips
- Legacy docs (for reference):
  - `SSO_SIMPLE_GUIDE.md` (old flow)
  - `SSO_USER_DATA_FLOW.md` (old flow)

---

## 🚀 Deployment Checklist

Before deploying to production:

- [ ] Update environment variables in Vercel/production
- [ ] Register production client in Keycloak
  - Client ID: `your-domain-client-id`
  - Redirect URIs: `https://your-domain.com/callback`
- [ ] Update Portal SSO to redirect to production URL
- [ ] Test all flows in staging environment
- [ ] Monitor logs after deployment
- [ ] Update documentation with production URLs

---

## 🔍 Debugging

If something doesn't work:

1. **Check logs:** Look for `🔐`, `🔄`, `✅`, `❌` in console
2. **Check cookies:** Verify `client_dinas_session` is set
3. **Check Keycloak:** Verify client configuration
4. **Check environment:** Verify all `.env` variables are set
5. **Check database:** Verify user exists in PostgreSQL

See **[TESTING_NEW_SSO_FLOW.md](./TESTING_NEW_SSO_FLOW.md#debugging-tips)** for more debugging tips.

---

## 💬 Support

If you encounter issues:
1. Check the testing guide
2. Check console logs (backend and browser)
3. Verify Keycloak client configuration
4. Verify environment variables
5. Check if user exists in database

**Happy Coding! 🚀**
