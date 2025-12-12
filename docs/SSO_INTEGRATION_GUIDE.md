# 🔐 Panduan Integrasi SSO Keycloak untuk Client

Panduan lengkap untuk mengintegrasikan Single Sign-On (SSO) Keycloak ke dalam website client Anda.

## Daftar Isi

1. [Arsitektur SSO](#arsitektur-sso)
2. [Prasyarat](#prasyarat)
3. [Konfigurasi Environment](#konfigurasi-environment)
4. [Flow Autentikasi](#flow-autentikasi)
5. [Implementasi Go](#implementasi-go)
6. [Implementasi JavaScript](#implementasi-javascript)
7. [Implementasi Laravel (PHP)](#implementasi-laravel-php)
8. [Implementasi Python (Flask)](#implementasi-python-flask)
9. [Implementasi Node.js](#implementasi-nodejs)
10. [Session Management](#session-management)
11. [Logout & Token Revocation](#logout--token-revocation)
12. [Troubleshooting](#troubleshooting)

---

## Arsitektur SSO

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   User Browser  │────▶│  Client App     │────▶│    Keycloak     │
│                 │     │  (Website Anda) │     │   SSO Server    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        │  1. Klik Login        │                       │
        │──────────────────────▶│                       │
        │                       │  2. Redirect ke SSO   │
        │                       │──────────────────────▶│
        │                       │                       │
        │  3. Login di Keycloak │                       │
        │──────────────────────────────────────────────▶│
        │                       │                       │
        │  4. Callback + Code   │                       │
        │◀──────────────────────────────────────────────│
        │                       │  5. Exchange Code     │
        │                       │──────────────────────▶│
        │                       │  6. Access Token      │
        │                       │◀──────────────────────│
        │  7. Session Created   │                       │
        │◀──────────────────────│                       │
```

---

## Prasyarat

1. **Keycloak Server** yang sudah dikonfigurasi
2. **Client terdaftar** di Keycloak realm
3. **Environment variables** yang benar

### Konfigurasi Client di Keycloak

1. Buka Keycloak Admin Console
2. Pilih Realm → Clients → Create Client
3. Setting:
   - **Client ID**: `your-client-id`
   - **Client Protocol**: `openid-connect`
   - **Access Type**: `public` (untuk flow PKCE) atau `confidential`
   - **Valid Redirect URIs**: `http://localhost:8070/sso/callback`
   - **Web Origins**: `http://localhost:8070`

---

## Konfigurasi Environment

```env
# SSO Keycloak Configuration
SSO_URL=http://localhost:8080              # URL Keycloak Server
SSO_REALM=dinas-pendidikan                 # Nama Realm
SSO_CLIENT_ID=client-dinas                 # Client ID
SSO_CLIENT_SECRET=your-secret              # Secret (jika confidential)
SSO_REDIRECT_URI=http://localhost:8070/sso/callback

# Server Configuration
PORT=8070
```

---

## Flow Autentikasi

### 1. Authorization Code Flow dengan PKCE (Recommended)

```
1. User klik "Login dengan SSO"
2. Generate code_verifier dan code_challenge (PKCE)
3. Redirect ke Keycloak Authorization Endpoint
4. User login di Keycloak
5. Keycloak redirect ke callback URL dengan authorization code
6. Exchange code + code_verifier untuk access token
7. Validasi token dan buat session lokal
```

---

## Implementasi Go

### File: `pkg/sso/keycloak.go`

```go
package sso

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "strings"
    "time"
)

// TokenResponse dari Keycloak
type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
    RefreshToken string `json:"refresh_token"`
    IDToken      string `json:"id_token"`
}

// UserInfo dari Keycloak
type UserInfo struct {
    Sub               string `json:"sub"`
    Email             string `json:"email"`
    EmailVerified     bool   `json:"email_verified"`
    Name              string `json:"name"`
    PreferredUsername string `json:"preferred_username"`
}

// GeneratePKCE membuat code_verifier dan code_challenge
func GeneratePKCE() (verifier string, challenge string, err error) {
    // Generate random bytes untuk code_verifier
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", "", err
    }
    verifier = base64.RawURLEncoding.EncodeToString(b)
    
    // Generate code_challenge (SHA256 hash dari verifier)
    h := sha256.Sum256([]byte(verifier))
    challenge = base64.RawURLEncoding.EncodeToString(h[:])
    
    return verifier, challenge, nil
}

// GetAuthorizationURL membuat URL untuk redirect ke Keycloak
func GetAuthorizationURL(state, codeChallenge string) string {
    ssoURL := os.Getenv("SSO_URL")
    realm := os.Getenv("SSO_REALM")
    clientID := os.Getenv("SSO_CLIENT_ID")
    redirectURI := os.Getenv("SSO_REDIRECT_URI")
    
    params := url.Values{}
    params.Set("client_id", clientID)
    params.Set("redirect_uri", redirectURI)
    params.Set("response_type", "code")
    params.Set("scope", "openid email profile")
    params.Set("state", state)
    params.Set("code_challenge", codeChallenge)
    params.Set("code_challenge_method", "S256")
    
    return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth?%s",
        ssoURL, realm, params.Encode())
}

// ExchangeCodeForToken menukar authorization code dengan access token
func ExchangeCodeForToken(code, codeVerifier string) (*TokenResponse, error) {
    ssoURL := os.Getenv("SSO_URL")
    realm := os.Getenv("SSO_REALM")
    clientID := os.Getenv("SSO_CLIENT_ID")
    clientSecret := os.Getenv("SSO_CLIENT_SECRET")
    redirectURI := os.Getenv("SSO_REDIRECT_URI")
    
    tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
        ssoURL, realm)
    
    data := url.Values{}
    data.Set("grant_type", "authorization_code")
    data.Set("client_id", clientID)
    data.Set("code", code)
    data.Set("redirect_uri", redirectURI)
    data.Set("code_verifier", codeVerifier)
    
    // Tambahkan client_secret jika confidential client
    if clientSecret != "" {
        data.Set("client_secret", clientSecret)
    }
    
    resp, err := http.PostForm(tokenURL, data)
    if err != nil {
        return nil, fmt.Errorf("failed to exchange code: %v", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("token exchange failed: %s", string(body))
    }
    
    var tokenResp TokenResponse
    if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
        return nil, err
    }
    
    return &tokenResp, nil
}

// GetUserInfo mengambil informasi user dari Keycloak
func GetUserInfo(accessToken string) (*UserInfo, error) {
    ssoURL := os.Getenv("SSO_URL")
    realm := os.Getenv("SSO_REALM")
    
    userInfoURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo",
        ssoURL, realm)
    
    req, _ := http.NewRequest("GET", userInfoURL, nil)
    req.Header.Set("Authorization", "Bearer "+accessToken)
    
    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("userinfo request failed: %d", resp.StatusCode)
    }
    
    var userInfo UserInfo
    if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
        return nil, err
    }
    
    return &userInfo, nil
}

// ValidateSession memeriksa apakah session SSO masih valid
func ValidateSession(accessToken string) bool {
    userInfo, err := GetUserInfo(accessToken)
    return err == nil && userInfo != nil
}

// Logout dari Keycloak
func Logout(idToken, redirectURI string) string {
    ssoURL := os.Getenv("SSO_URL")
    realm := os.Getenv("SSO_REALM")
    
    params := url.Values{}
    params.Set("id_token_hint", idToken)
    params.Set("post_logout_redirect_uri", redirectURI)
    
    return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout?%s",
        ssoURL, realm, params.Encode())
}

// ParseIDToken mengambil claims dari ID Token (tanpa validasi signature)
func ParseIDToken(idToken string) (map[string]interface{}, error) {
    parts := strings.Split(idToken, ".")
    if len(parts) != 3 {
        return nil, fmt.Errorf("invalid token format")
    }
    
    // Decode payload (bagian kedua)
    payload, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil {
        return nil, err
    }
    
    var claims map[string]interface{}
    if err := json.Unmarshal(payload, &claims); err != nil {
        return nil, err
    }
    
    return claims, nil
}
```

### File: `handlers/sso_handler.go`

```go
package handlers

import (
    "log"
    "net/http"
    "your-app/pkg/sso"
)

// SSOLoginHandler memulai flow SSO
func SSOLoginHandler(w http.ResponseWriter, r *http.Request) {
    // Generate PKCE
    verifier, challenge, err := sso.GeneratePKCE()
    if err != nil {
        http.Error(w, "Failed to generate PKCE", http.StatusInternalServerError)
        return
    }
    
    // Generate state (untuk CSRF protection)
    state := generateRandomString(32)
    
    // Simpan verifier dan state di cookie/session
    http.SetCookie(w, &http.Cookie{
        Name:     "pkce_verifier",
        Value:    verifier,
        Path:     "/",
        HttpOnly: true,
        MaxAge:   300, // 5 menit
    })
    http.SetCookie(w, &http.Cookie{
        Name:     "oauth_state",
        Value:    state,
        Path:     "/",
        HttpOnly: true,
        MaxAge:   300,
    })
    
    // Redirect ke Keycloak
    authURL := sso.GetAuthorizationURL(state, challenge)
    http.Redirect(w, r, authURL, http.StatusFound)
}

// SSOCallbackHandler menangani callback dari Keycloak
func SSOCallbackHandler(w http.ResponseWriter, r *http.Request) {
    // Ambil authorization code
    code := r.URL.Query().Get("code")
    state := r.URL.Query().Get("state")
    
    // Validasi state
    stateCookie, err := r.Cookie("oauth_state")
    if err != nil || stateCookie.Value != state {
        http.Error(w, "Invalid state", http.StatusBadRequest)
        return
    }
    
    // Ambil code_verifier
    verifierCookie, err := r.Cookie("pkce_verifier")
    if err != nil {
        http.Error(w, "Missing PKCE verifier", http.StatusBadRequest)
        return
    }
    
    // Exchange code untuk token
    tokenResp, err := sso.ExchangeCodeForToken(code, verifierCookie.Value)
    if err != nil {
        log.Printf("Token exchange error: %v", err)
        http.Error(w, "Failed to get token", http.StatusInternalServerError)
        return
    }
    
    // Ambil user info
    userInfo, err := sso.GetUserInfo(tokenResp.AccessToken)
    if err != nil {
        log.Printf("UserInfo error: %v", err)
        http.Error(w, "Failed to get user info", http.StatusInternalServerError)
        return
    }
    
    // Simpan token di cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "sso_access_token",
        Value:    tokenResp.AccessToken,
        Path:     "/",
        HttpOnly: true,
        MaxAge:   tokenResp.ExpiresIn,
    })
    http.SetCookie(w, &http.Cookie{
        Name:     "sso_id_token",
        Value:    tokenResp.IDToken,
        Path:     "/",
        HttpOnly: true,
        MaxAge:   tokenResp.ExpiresIn,
    })
    
    // Buat session lokal
    sessionID := createSession(userInfo.Email)
    http.SetCookie(w, &http.Cookie{
        Name:     "session_id",
        Value:    sessionID,
        Path:     "/",
        HttpOnly: true,
        MaxAge:   86400, // 24 jam
    })
    
    // Clear PKCE cookies
    http.SetCookie(w, &http.Cookie{Name: "pkce_verifier", MaxAge: -1, Path: "/"})
    http.SetCookie(w, &http.Cookie{Name: "oauth_state", MaxAge: -1, Path: "/"})
    
    // Redirect ke dashboard
    http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// SSOLogoutHandler menangani logout
func SSOLogoutHandler(w http.ResponseWriter, r *http.Request) {
    // Ambil ID token untuk logout hint
    idTokenCookie, _ := r.Cookie("sso_id_token")
    idToken := ""
    if idTokenCookie != nil {
        idToken = idTokenCookie.Value
    }
    
    // Clear semua cookies
    http.SetCookie(w, &http.Cookie{Name: "session_id", MaxAge: -1, Path: "/"})
    http.SetCookie(w, &http.Cookie{Name: "sso_access_token", MaxAge: -1, Path: "/"})
    http.SetCookie(w, &http.Cookie{Name: "sso_id_token", MaxAge: -1, Path: "/"})
    
    // Redirect ke Keycloak logout
    logoutURL := sso.Logout(idToken, "http://localhost:8070/login")
    http.Redirect(w, r, logoutURL, http.StatusFound)
}
```

---

## Implementasi JavaScript

### File: `sso-client.js`

```javascript
class SSOClient {
    constructor(config) {
        this.ssoUrl = config.ssoUrl;
        this.realm = config.realm;
        this.clientId = config.clientId;
        this.redirectUri = config.redirectUri;
    }
    
    // Generate PKCE
    async generatePKCE() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        const verifier = this.base64UrlEncode(array);
        
        const encoder = new TextEncoder();
        const data = encoder.encode(verifier);
        const hash = await crypto.subtle.digest('SHA-256', data);
        const challenge = this.base64UrlEncode(new Uint8Array(hash));
        
        return { verifier, challenge };
    }
    
    base64UrlEncode(array) {
        return btoa(String.fromCharCode(...array))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }
    
    // Mulai login flow
    async login() {
        const { verifier, challenge } = await this.generatePKCE();
        const state = this.generateState();
        
        // Simpan di sessionStorage
        sessionStorage.setItem('pkce_verifier', verifier);
        sessionStorage.setItem('oauth_state', state);
        
        const params = new URLSearchParams({
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            response_type: 'code',
            scope: 'openid email profile',
            state: state,
            code_challenge: challenge,
            code_challenge_method: 'S256'
        });
        
        window.location.href = 
            `${this.ssoUrl}/realms/${this.realm}/protocol/openid-connect/auth?${params}`;
    }
    
    // Handle callback
    async handleCallback() {
        const params = new URLSearchParams(window.location.search);
        const code = params.get('code');
        const state = params.get('state');
        
        // Validasi state
        const savedState = sessionStorage.getItem('oauth_state');
        if (state !== savedState) {
            throw new Error('Invalid state');
        }
        
        const verifier = sessionStorage.getItem('pkce_verifier');
        
        // Exchange code for token
        const tokenResponse = await this.exchangeCode(code, verifier);
        
        // Clear PKCE data
        sessionStorage.removeItem('pkce_verifier');
        sessionStorage.removeItem('oauth_state');
        
        return tokenResponse;
    }
    
    async exchangeCode(code, verifier) {
        const response = await fetch(
            `${this.ssoUrl}/realms/${this.realm}/protocol/openid-connect/token`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    grant_type: 'authorization_code',
                    client_id: this.clientId,
                    code: code,
                    redirect_uri: this.redirectUri,
                    code_verifier: verifier
                })
            }
        );
        
        if (!response.ok) {
            throw new Error('Token exchange failed');
        }
        
        return response.json();
    }
    
    // Logout
    logout(idToken) {
        const params = new URLSearchParams({
            id_token_hint: idToken,
            post_logout_redirect_uri: window.location.origin + '/login'
        });
        
        window.location.href = 
            `${this.ssoUrl}/realms/${this.realm}/protocol/openid-connect/logout?${params}`;
    }
    
    generateState() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return this.base64UrlEncode(array);
    }
}

// Penggunaan:
const sso = new SSOClient({
    ssoUrl: 'http://localhost:8080',
    realm: 'dinas-pendidikan',
    clientId: 'client-dinas',
    redirectUri: 'http://localhost:8070/callback'
});

// Login
document.getElementById('loginBtn').addEventListener('click', () => sso.login());

// Handle callback (di halaman callback)
if (window.location.search.includes('code=')) {
    sso.handleCallback()
        .then(tokens => {
            console.log('Login successful!', tokens);
            // Simpan tokens dan redirect
        })
        .catch(err => console.error(err));
}
```

---

## Implementasi Laravel (PHP)

### File: `app/Services/SSOService.php`

```php
<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class SSOService
{
    private string $ssoUrl;
    private string $realm;
    private string $clientId;
    private string $clientSecret;
    private string $redirectUri;
    
    public function __construct()
    {
        $this->ssoUrl = config('sso.url');
        $this->realm = config('sso.realm');
        $this->clientId = config('sso.client_id');
        $this->clientSecret = config('sso.client_secret');
        $this->redirectUri = config('sso.redirect_uri');
    }
    
    /**
     * Generate PKCE code verifier dan challenge
     */
    public function generatePKCE(): array
    {
        $verifier = Str::random(64);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        
        return [
            'verifier' => $verifier,
            'challenge' => $challenge
        ];
    }
    
    /**
     * Dapatkan URL authorization
     */
    public function getAuthorizationUrl(string $state, string $codeChallenge): string
    {
        $params = http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => 'openid email profile',
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256'
        ]);
        
        return "{$this->ssoUrl}/realms/{$this->realm}/protocol/openid-connect/auth?{$params}";
    }
    
    /**
     * Exchange authorization code untuk access token
     */
    public function exchangeCode(string $code, string $codeVerifier): array
    {
        $response = Http::asForm()->post(
            "{$this->ssoUrl}/realms/{$this->realm}/protocol/openid-connect/token",
            [
                'grant_type' => 'authorization_code',
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'code' => $code,
                'redirect_uri' => $this->redirectUri,
                'code_verifier' => $codeVerifier
            ]
        );
        
        if ($response->failed()) {
            throw new \Exception('Token exchange failed: ' . $response->body());
        }
        
        return $response->json();
    }
    
    /**
     * Dapatkan user info dari Keycloak
     */
    public function getUserInfo(string $accessToken): array
    {
        $response = Http::withToken($accessToken)->get(
            "{$this->ssoUrl}/realms/{$this->realm}/protocol/openid-connect/userinfo"
        );
        
        if ($response->failed()) {
            throw new \Exception('Failed to get user info');
        }
        
        return $response->json();
    }
    
    /**
     * Dapatkan URL logout
     */
    public function getLogoutUrl(string $idToken): string
    {
        $params = http_build_query([
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => url('/login')
        ]);
        
        return "{$this->ssoUrl}/realms/{$this->realm}/protocol/openid-connect/logout?{$params}";
    }
}
```

### File: `app/Http/Controllers/SSOController.php`

```php
<?php

namespace App\Http\Controllers;

use App\Services\SSOService;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class SSOController extends Controller
{
    private SSOService $sso;
    
    public function __construct(SSOService $sso)
    {
        $this->sso = $sso;
    }
    
    public function login(Request $request)
    {
        $pkce = $this->sso->generatePKCE();
        $state = Str::random(32);
        
        // Simpan di session
        session(['pkce_verifier' => $pkce['verifier']]);
        session(['oauth_state' => $state]);
        
        $authUrl = $this->sso->getAuthorizationUrl($state, $pkce['challenge']);
        
        return redirect($authUrl);
    }
    
    public function callback(Request $request)
    {
        // Validasi state
        if ($request->state !== session('oauth_state')) {
            abort(400, 'Invalid state');
        }
        
        // Exchange code
        $tokens = $this->sso->exchangeCode(
            $request->code,
            session('pkce_verifier')
        );
        
        // Get user info
        $userInfo = $this->sso->getUserInfo($tokens['access_token']);
        
        // Simpan tokens di session
        session([
            'sso_access_token' => $tokens['access_token'],
            'sso_id_token' => $tokens['id_token'],
            'user' => $userInfo
        ]);
        
        // Clear PKCE data
        session()->forget(['pkce_verifier', 'oauth_state']);
        
        return redirect('/dashboard');
    }
    
    public function logout(Request $request)
    {
        $idToken = session('sso_id_token');
        
        // Clear session
        session()->flush();
        
        // Redirect ke Keycloak logout
        return redirect($this->sso->getLogoutUrl($idToken));
    }
}
```

---

## Implementasi Python (Flask)

### File: `sso/keycloak.py`

```python
import os
import base64
import hashlib
import secrets
import requests
from urllib.parse import urlencode

class KeycloakSSO:
    def __init__(self):
        self.sso_url = os.getenv('SSO_URL')
        self.realm = os.getenv('SSO_REALM')
        self.client_id = os.getenv('SSO_CLIENT_ID')
        self.client_secret = os.getenv('SSO_CLIENT_SECRET')
        self.redirect_uri = os.getenv('SSO_REDIRECT_URI')
    
    def generate_pkce(self):
        """Generate PKCE code verifier dan challenge"""
        verifier = secrets.token_urlsafe(32)
        challenge_bytes = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(challenge_bytes).rstrip(b'=').decode()
        return verifier, challenge
    
    def get_authorization_url(self, state, code_challenge):
        """Dapatkan URL authorization"""
        params = urlencode({
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': 'openid email profile',
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        })
        return f"{self.sso_url}/realms/{self.realm}/protocol/openid-connect/auth?{params}"
    
    def exchange_code(self, code, code_verifier):
        """Exchange authorization code untuk access token"""
        token_url = f"{self.sso_url}/realms/{self.realm}/protocol/openid-connect/token"
        
        data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'code': code,
            'redirect_uri': self.redirect_uri,
            'code_verifier': code_verifier
        }
        
        if self.client_secret:
            data['client_secret'] = self.client_secret
        
        response = requests.post(token_url, data=data)
        response.raise_for_status()
        return response.json()
    
    def get_user_info(self, access_token):
        """Dapatkan user info dari Keycloak"""
        userinfo_url = f"{self.sso_url}/realms/{self.realm}/protocol/openid-connect/userinfo"
        
        response = requests.get(
            userinfo_url,
            headers={'Authorization': f'Bearer {access_token}'}
        )
        response.raise_for_status()
        return response.json()
    
    def get_logout_url(self, id_token):
        """Dapatkan URL logout"""
        params = urlencode({
            'id_token_hint': id_token,
            'post_logout_redirect_uri': f"{os.getenv('APP_URL')}/login"
        })
        return f"{self.sso_url}/realms/{self.realm}/protocol/openid-connect/logout?{params}"
```

### File: `app.py`

```python
from flask import Flask, redirect, request, session, url_for
from sso.keycloak import KeycloakSSO
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
sso = KeycloakSSO()

@app.route('/sso/login')
def sso_login():
    verifier, challenge = sso.generate_pkce()
    state = secrets.token_urlsafe(16)
    
    session['pkce_verifier'] = verifier
    session['oauth_state'] = state
    
    auth_url = sso.get_authorization_url(state, challenge)
    return redirect(auth_url)

@app.route('/sso/callback')
def sso_callback():
    # Validasi state
    if request.args.get('state') != session.get('oauth_state'):
        return 'Invalid state', 400
    
    # Exchange code
    code = request.args.get('code')
    tokens = sso.exchange_code(code, session['pkce_verifier'])
    
    # Get user info
    user_info = sso.get_user_info(tokens['access_token'])
    
    # Simpan di session
    session['sso_access_token'] = tokens['access_token']
    session['sso_id_token'] = tokens['id_token']
    session['user'] = user_info
    
    # Clear PKCE
    session.pop('pkce_verifier', None)
    session.pop('oauth_state', None)
    
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    id_token = session.get('sso_id_token')
    session.clear()
    return redirect(sso.get_logout_url(id_token))
```

---

## Implementasi Node.js

### File: `sso/keycloak.js`

```javascript
const crypto = require('crypto');
const axios = require('axios');

class KeycloakSSO {
    constructor() {
        this.ssoUrl = process.env.SSO_URL;
        this.realm = process.env.SSO_REALM;
        this.clientId = process.env.SSO_CLIENT_ID;
        this.clientSecret = process.env.SSO_CLIENT_SECRET;
        this.redirectUri = process.env.SSO_REDIRECT_URI;
    }
    
    generatePKCE() {
        const verifier = crypto.randomBytes(32).toString('base64url');
        const challenge = crypto
            .createHash('sha256')
            .update(verifier)
            .digest('base64url');
        return { verifier, challenge };
    }
    
    getAuthorizationUrl(state, codeChallenge) {
        const params = new URLSearchParams({
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            response_type: 'code',
            scope: 'openid email profile',
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256'
        });
        
        return `${this.ssoUrl}/realms/${this.realm}/protocol/openid-connect/auth?${params}`;
    }
    
    async exchangeCode(code, codeVerifier) {
        const tokenUrl = `${this.ssoUrl}/realms/${this.realm}/protocol/openid-connect/token`;
        
        const data = new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: this.clientId,
            code: code,
            redirect_uri: this.redirectUri,
            code_verifier: codeVerifier
        });
        
        if (this.clientSecret) {
            data.append('client_secret', this.clientSecret);
        }
        
        const response = await axios.post(tokenUrl, data);
        return response.data;
    }
    
    async getUserInfo(accessToken) {
        const userinfoUrl = `${this.ssoUrl}/realms/${this.realm}/protocol/openid-connect/userinfo`;
        
        const response = await axios.get(userinfoUrl, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        return response.data;
    }
    
    getLogoutUrl(idToken) {
        const params = new URLSearchParams({
            id_token_hint: idToken,
            post_logout_redirect_uri: `${process.env.APP_URL}/login`
        });
        
        return `${this.ssoUrl}/realms/${this.realm}/protocol/openid-connect/logout?${params}`;
    }
}

module.exports = new KeycloakSSO();
```

---

## Session Management

### Periodic Session Check

```javascript
// Cek session setiap 30 detik
setInterval(async () => {
    try {
        const response = await fetch('/auth/validate');
        if (response.status === 401) {
            // Session expired, redirect ke login
            window.location.href = '/login?error=session_expired';
        }
    } catch (error) {
        console.error('Session check failed:', error);
    }
}, 30000);

// Cek saat window focus
window.addEventListener('focus', async () => {
    const response = await fetch('/auth/validate');
    if (response.status === 401) {
        window.location.href = '/login?error=session_expired';
    }
});
```

---

## Logout & Token Revocation

### Endpoint Logout di Go

```go
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
    // Ambil tokens
    idToken, _ := r.Cookie("sso_id_token")
    accessToken, _ := r.Cookie("sso_access_token")
    
    // Revoke token di Keycloak (optional)
    if accessToken != nil {
        revokeToken(accessToken.Value)
    }
    
    // Clear semua cookies
    clearCookies := []string{
        "session_id",
        "sso_access_token",
        "sso_id_token",
        "sso_token_expires"
    }
    
    for _, name := range clearCookies {
        http.SetCookie(w, &http.Cookie{
            Name:   name,
            Value:  "",
            Path:   "/",
            MaxAge: -1,
        })
    }
    
    // Redirect ke Keycloak logout
    logoutURL := sso.Logout(idToken.Value, "http://localhost:8070/login")
    http.Redirect(w, r, logoutURL, http.StatusFound)
}
```

---

## Troubleshooting

### Error: "Missing parameter: code_challenge_method"

**Solusi**: Pastikan PKCE parameters dikirim saat redirect ke Keycloak:
```
code_challenge=xxx
code_challenge_method=S256
```

### Error: "Invalid redirect_uri"

**Solusi**: Pastikan redirect URI yang dikonfigurasi di Keycloak sama persis dengan yang dikirim.

### Error: "Invalid client credentials"

**Solusi**: 
- Untuk public client: Jangan kirim `client_secret`
- Untuk confidential client: Pastikan secret benar

### Session tidak sync dengan SSO

**Solusi**: Implementasi periodic session check menggunakan Keycloak UserInfo endpoint.

---

## Referensi

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [OAuth 2.0 PKCE](https://oauth.net/2/pkce/)
- [OpenID Connect](https://openid.net/connect/)

---

*Dokumen ini dibuat untuk membantu integrasi SSO Keycloak dengan berbagai platform client.*
