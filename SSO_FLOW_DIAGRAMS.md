# 🔄 SSO Flow Diagram - Visual Guide

## Flow Comparison: Old vs New

### ❌ OLD FLOW (SSO Simple)

```
┌─────────────┐
│ Portal SSO  │
│ localhost:  │
│ 3000        │
└──────┬──────┘
       │
       │ User clicks app
       │
       ▼
   Redirect with TOKENS in URL! 🚨
   http://localhost:8070/?sso_token=ABC123&sso_id_token=XYZ789
       │
       │
       ▼
┌──────────────┐
│ Client Web   │
│ localhost:   │◄─── Tokens visible in browser history! 🚨
│ 8070         │
└──────────────┘
       │
       │ Process tokens
       │ Create session
       │
       ▼
   DASHBOARD ✅
```

**Problems:**
- 🚨 Tokens exposed in URL
- 🚨 Tokens visible in browser history
- 🚨 Tokens can be copied/shared
- ✅ But: Simple implementation

---

### ✅ NEW FLOW (Standard OIDC)

```
┌─────────────┐
│ Portal SSO  │
│ localhost:  │
│ 3000        │
└──────┬──────┘
       │
       │ User clicks app
       │
       ▼
   Redirect WITHOUT tokens ✅
   http://localhost:8070 (plain URL)
       │
       ▼
┌──────────────┐
│ Client Web   │
│ localhost:   │
│ 8070         │
└──────┬───────┘
       │
       │ 1. Check local session?
       │    ├─ Yes → DASHBOARD ✅
       │    └─ No  → Continue...
       │
       │ 2. Redirect to Keycloak
       │    with prompt=none
       │
       ▼
┌──────────────┐
│  Keycloak    │
│ localhost:   │
│ 8080         │
└──────┬───────┘
       │
       │ 3. Check Keycloak SSO session?
       │    ├─ Yes (logged in) → Return auth code ✅ (AUTO-LOGIN!)
       │    └─ No              → Show login form 📋
       │
       ▼
   User logs in (if needed)
       │
       ▼
   Redirect with authorization CODE
   http://localhost:8070/callback?code=ABC123&state=XYZ789
       │
       ▼
┌──────────────┐
│ Client Web   │
│ /callback    │
└──────┬───────┘
       │
       │ 4. Exchange code for tokens
       │    (BACKEND ONLY - not visible to user!)
       │
       │ 5. Get user info from ID token
       │    (JWT decode - no API call needed)
       │
       │ 6. Create local session
       │    Set cookies
       │
       ▼
   DASHBOARD ✅
```

**Benefits:**
- ✅ Tokens NEVER in URL
- ✅ Tokens NEVER in browser history  
- ✅ Auto-login after first login (TRUE SSO!)
- ✅ Centralized logout
- ✅ Standard & secure

---

## Detailed Auto-Login Flow

### Scenario: User Already Logged in to Keycloak

```
USER                CLIENT (8070)        KEYCLOAK (8080)
 │                       │                     │
 │ 1. Visit             │                     │
 ├──────────────────────►│                     │
 │  localhost:8070       │                     │
 │                       │                     │
 │                       │ 2. Check session    │
 │                       │    ❌ Not found     │
 │                       │                     │
 │                       │ 3. Redirect with    │
 │                       │    prompt=none      │
 │                       ├────────────────────►│
 │                       │                     │
 │                       │                     │ 4. Check Keycloak
 │                       │                     │    SSO cookie
 │                       │                     │    ✅ Found!
 │                       │                     │
 │                       │ 5. Return auth code │
 │                       │◄────────────────────┤
 │  (NO LOGIN FORM!)     │                     │
 │                       │                     │
 │                       │ 6. Exchange code    │
 │                       │    for tokens       │
 │                       ├────────────────────►│
 │                       │◄────────────────────┤
 │                       │    Access Token     │
 │                       │    ID Token         │
 │                       │                     │
 │                       │ 7. Create session   │
 │                       │    Set cookies      │
 │                       │                     │
 │ 8. Dashboard          │                     │
 │◄──────────────────────┤                     │
 │  ✅ AUTO-LOGIN!       │                     │
```

**Key:** Step 4-5 happens automatically without user interaction! 🎉

---

## The Magic of `prompt=none`

### Without `prompt=none`:
```
Client → Keycloak
Keycloak: "I need user to login"
→ Shows login form ALWAYS
```

### With `prompt=none`:
```
Client → Keycloak (prompt=none)
Keycloak: "Check if user already has session..."
   ├─ Has session? → Return auth code (NO FORM!)
   └─ No session?  → Return error "login_required"

Client receives error:
   → Redirect AGAIN but WITHOUT prompt=none
   → NOW shows login form
```

**Result:** Smart auto-login! User only sees form when truly needed!

---

## Cookie Flow

### What Cookies Are Set?

```
After successful login:

┌───────────────────────────────┐
│ client_dinas_session          │ ← Local session ID (24h)
├───────────────────────────────┤
│ sso_access_token              │ ← Access token from Keycloak
├───────────────────────────────┤
│ sso_id_token                  │ ← ID token (contains user info)
├───────────────────────────────┤
│ oauth_state                   │ ← CSRF protection (5 min, then deleted)
└───────────────────────────────┘

These cookies are:
- HttpOnly ✅ (not accessible to JavaScript)
- Secure in production ✅ (HTTPS only)
- SameSite=Lax ✅ (CSRF protection)
- Path=/ ✅ (available to all pages)
```

---

## Logout Flow

### Centralized Logout Diagram

```
USER                CLIENT (8070)        KEYCLOAK (8080)      PORTAL SSO (3000)
 │                       │                     │                     │
 │ 1. Click Logout      │                     │                     │
 ├──────────────────────►│                     │                     │
 │                       │                     │                     │
 │                       │ 2. Clear local      │                     │
 │                       │    session &        │                     │
 │                       │    cookies          │                     │
 │                       │                     │                     │
 │                       │ 3. Send logout      │                     │
 │                       │    request          │                     │
 │                       ├────────────────────►│                     │
 │                       │  (with id_token)    │                     │
 │                       │                     │                     │
 │                       │                     │ 4. Clear Keycloak   │
 │                       │                     │    SSO session      │
 │                       │                     │                     │
 │                       │                     │ 5. Notify all       │
 │                       │                     │    clients          │
 │                       │                     ├────────────────────►│
 │                       │                     │                     │
 │ 6. Redirect           │                     │                     │
 │◄──────────────────────┴─────────────────────┴─────────────────────┤
 │  to Portal SSO                                                    │
 │  (logged out)                                                     │
```

**Result:** Logout from anywhere = logout from everywhere! ✅

---

## Security Comparison

### Old Flow Security:
```
🚨 Token in URL:
   https://localhost:8070/?sso_token=eyJhbGciOiJSUzI1...
   
   Problems:
   - Visible in browser history
   - Can be shared/copied
   - Logged in proxy/gateway logs
   - Visible in referrer headers
```

### New Flow Security:
```
✅ Only authorization code in URL:
   https://localhost:8070/callback?code=abc123&state=xyz789
   
   Benefits:
   - Code is single-use (expires after exchange)
   - Code is short-lived (seconds)
   - State prevents CSRF attacks
   - Tokens exchanged in backend (never visible to user)
```

---

## Summary: Why This Is Better

| Feature | Old Flow | New Flow |
|---------|----------|----------|
| **Tokens in URL** | ❌ Yes (visible!) | ✅ No (secure!) |
| **Auto-Login** | ❌ Not really | ✅ Yes (true SSO!) |
| **Centralized Logout** | ⚠️ Partial | ✅ Full |
| **Standard Protocol** | ❌ Custom | ✅ OIDC Standard |
| **Security** | ⚠️ Medium | ✅ High |
| **Browser History** | ❌ Contains tokens | ✅ Clean |
| **Token Sharing Risk** | 🚨 High | ✅ Low |
| **Implementation** | ✅ Simple | ⚠️ More complex |

---

## Visual: Token Flow (Backend Only!)

```
┌──────────────────────────────────────────────────────────────┐
│                      BACKEND ONLY                             │
│  (User never sees these!)                                     │
│                                                                │
│  1. Authorization Code                                        │
│     ↓                                                         │
│  2. Exchange POST request to Keycloak                         │
│     ↓                                                         │
│  3. Keycloak validates code                                   │
│     ↓                                                         │
│  4. Return:                                                   │
│     - Access Token   (for API calls)                          │
│     - Refresh Token  (for token renewal)                      │
│     - ID Token       (for user info)                          │
│     ↓                                                         │
│  5. Decode ID Token (JWT) → Extract user info                 │
│     ↓                                                         │
│  6. Create local session in database                          │
│     ↓                                                         │
│  7. Set cookies (HttpOnly/Secure)                             │
│                                                                │
└──────────────────────────────────────────────────────────────┘
                           ↓
                    Show Dashboard
```

**User only sees:** Plain URLs and dashboard. No tokens! ✅

---

**END OF VISUAL GUIDE**

For implementation details, see:
- [SSO_NEW_FLOW_IMPLEMENTATION.md](./SSO_NEW_FLOW_IMPLEMENTATION.md)
- [TESTING_NEW_SSO_FLOW.md](./TESTING_NEW_SSO_FLOW.md)
- [IMPLEMENTATION_COMPLETE.md](./IMPLEMENTATION_COMPLETE.md)
