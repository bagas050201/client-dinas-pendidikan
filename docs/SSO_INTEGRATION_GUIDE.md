# 🔐 Panduan Integrasi SSO Keycloak

Panduan **copy-paste ready** untuk mengintegrasikan Single Sign-On (SSO) Keycloak ke website client Anda.

---

## Daftar Isi

1. [Quickstart (5 Menit)](#quickstart-5-menit)
2. [Konsep SSO](#konsep-sso)
3. [Environment Variables](#environment-variables)
4. [Implementasi Go (Golang)](#implementasi-go-golang)
5. [Implementasi JavaScript (Browser)](#implementasi-javascript-browser)
6. [Implementasi PHP (Laravel)](#implementasi-php-laravel)
7. [Implementasi Python (Flask)](#implementasi-python-flask)
8. [Implementasi Node.js (Express)](#implementasi-nodejs-express)
9. [Session Management](#session-management)
10. [Troubleshooting](#troubleshooting)

---

## Quickstart (5 Menit)

### Langkah 1: Daftarkan Client di Keycloak

```
1. Buka Keycloak Admin Console
2. Clients → Create Client
3. Isi:
   - Client ID: your-app-client
   - Client Protocol: openid-connect
   - Access Type: public (untuk PKCE)
4. Settings:
   - Valid Redirect URIs: http://localhost:YOUR_PORT/callback
   - Web Origins: http://localhost:YOUR_PORT
```

### Langkah 2: Set Environment Variables

```bash
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=dinas-pendidikan
KEYCLOAK_CLIENT_ID=your-app-client
KEYCLOAK_REDIRECT_URI=http://localhost:YOUR_PORT/callback
```

### Langkah 3: Implementasi Minimal

**Go:**
```go
// Login
http.Redirect(w, r, getKeycloakAuthURL(), http.StatusFound)

// Callback
token := exchangeCode(r.URL.Query().Get("code"))
userInfo := parseIDToken(token.IDToken)
```

---

## Konsep SSO

### Flow Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                         FLOW SSO KEYCLOAK                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   [1] User klik "Login"                                          │
│         │                                                        │
│         ▼                                                        │
│   [2] Redirect ke Keycloak                                       │
│       URL: /realms/{realm}/protocol/openid-connect/auth          │
│       + client_id                                                │
│       + redirect_uri                                             │
│       + code_challenge (PKCE)                                    │
│       + state (CSRF protection)                                  │
│         │                                                        │
│         ▼                                                        │
│   [3] User login di Keycloak                                     │
│         │                                                        │
│         ▼                                                        │
│   [4] Keycloak redirect ke callback URL                          │
│       + code (authorization code)                                │
│       + state                                                    │
│         │                                                        │
│         ▼                                                        │
│   [5] Website kirim POST ke token endpoint                       │
│       /realms/{realm}/protocol/openid-connect/token              │
│       + code                                                     │
│       + code_verifier (PKCE)                                     │
│         │                                                        │
│         ▼                                                        │
│   [6] Keycloak return access_token + id_token                    │
│         │                                                        │
│         ▼                                                        │
│   [7] Parse id_token → dapat user info                           │
│         │                                                        │
│         ▼                                                        │
│   [8] Buat session lokal → redirect ke dashboard                 │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Apa itu PKCE?

**PKCE (Proof Key for Code Exchange)** adalah mekanisme keamanan untuk mencegah authorization code interception.

```
┌─────────────────────────────────────────────────────────┐
│                        PKCE FLOW                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. Generate random string → code_verifier              │
│                                                         │
│  2. Hash dengan SHA256 → code_challenge                 │
│     code_challenge = BASE64URL(SHA256(code_verifier))   │
│                                                         │
│  3. Kirim code_challenge ke Keycloak (saat login)       │
│                                                         │
│  4. Kirim code_verifier ke Keycloak (saat token)        │
│                                                         │
│  5. Keycloak verify: SHA256(verifier) == challenge      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Environment Variables

```bash
# Wajib
KEYCLOAK_BASE_URL=http://localhost:8080     # URL Keycloak Server
KEYCLOAK_REALM=dinas-pendidikan             # Nama Realm
KEYCLOAK_CLIENT_ID=your-app-client          # Client ID
KEYCLOAK_REDIRECT_URI=http://localhost:8070/callback  # Callback URL

# Opsional (untuk confidential client)
KEYCLOAK_CLIENT_SECRET=your-secret
```

---

## Implementasi Go (Golang)

### File Lengkap: `sso/keycloak.go`

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
)

// ==================== KONFIGURASI ====================

type Config struct {
    BaseURL     string
    Realm       string
    ClientID    string
    RedirectURI string
}

func GetConfig() Config {
    return Config{
        BaseURL:     os.Getenv("KEYCLOAK_BASE_URL"),
        Realm:       os.Getenv("KEYCLOAK_REALM"),
        ClientID:    os.Getenv("KEYCLOAK_CLIENT_ID"),
        RedirectURI: os.Getenv("KEYCLOAK_REDIRECT_URI"),
    }
}

// ==================== PKCE ====================

type PKCE struct {
    Verifier  string
    Challenge string
}

func GeneratePKCE() (*PKCE, error) {
    // Generate random 32 bytes
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return nil, err
    }
    
    verifier := base64.RawURLEncoding.EncodeToString(b)
    hash := sha256.Sum256([]byte(verifier))
    challenge := base64.RawURLEncoding.EncodeToString(hash[:])
    
    return &PKCE{Verifier: verifier, Challenge: challenge}, nil
}

// ==================== AUTH URL ====================

func GetAuthURL(state, codeChallenge string) string {
    cfg := GetConfig()
    
    params := url.Values{
        "client_id":             {cfg.ClientID},
        "redirect_uri":          {cfg.RedirectURI},
        "response_type":         {"code"},
        "scope":                 {"openid email profile"},
        "state":                 {state},
        "code_challenge":        {codeChallenge},
        "code_challenge_method": {"S256"},
    }
    
    return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth?%s",
        cfg.BaseURL, cfg.Realm, params.Encode())
}

// ==================== TOKEN EXCHANGE ====================

type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    IDToken      string `json:"id_token"`
    RefreshToken string `json:"refresh_token"`
    ExpiresIn    int    `json:"expires_in"`
}

func ExchangeCode(code, codeVerifier string) (*TokenResponse, error) {
    cfg := GetConfig()
    
    tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
        cfg.BaseURL, cfg.Realm)
    
    data := url.Values{
        "grant_type":    {"authorization_code"},
        "client_id":     {cfg.ClientID},
        "code":          {code},
        "redirect_uri":  {cfg.RedirectURI},
        "code_verifier": {codeVerifier},
    }
    
    resp, err := http.PostForm(tokenURL, data)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("token error: %s", string(body))
    }
    
    var token TokenResponse
    json.NewDecoder(resp.Body).Decode(&token)
    return &token, nil
}

// ==================== PARSE ID TOKEN ====================

type UserInfo struct {
    Sub      string `json:"sub"`
    Email    string `json:"email"`
    Name     string `json:"name"`
    Username string `json:"preferred_username"`
}

func ParseIDToken(idToken string) (*UserInfo, error) {
    parts := strings.Split(idToken, ".")
    if len(parts) != 3 {
        return nil, fmt.Errorf("invalid token")
    }
    
    // Decode payload
    payload := parts[1]
    if len(payload)%4 != 0 {
        payload += strings.Repeat("=", 4-len(payload)%4)
    }
    
    decoded, err := base64.URLEncoding.DecodeString(payload)
    if err != nil {
        return nil, err
    }
    
    var user UserInfo
    json.Unmarshal(decoded, &user)
    return &user, nil
}

// ==================== LOGOUT URL ====================

func GetLogoutURL(idToken, postLogoutURI string) string {
    cfg := GetConfig()
    
    params := url.Values{
        "client_id":                {cfg.ClientID},
        "post_logout_redirect_uri": {postLogoutURI},
        "id_token_hint":            {idToken},
    }
    
    return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout?%s",
        cfg.BaseURL, cfg.Realm, params.Encode())
}
```

### Contoh Handler: `handlers/auth.go`

```go
package handlers

import (
    "net/http"
    "your-app/sso"
)

// LoginHandler - Mulai SSO flow
func LoginHandler(w http.ResponseWriter, r *http.Request) {
    // 1. Generate PKCE
    pkce, _ := sso.GeneratePKCE()
    
    // 2. Generate state
    state := generateRandomString(32)
    
    // 3. Simpan di cookie
    http.SetCookie(w, &http.Cookie{Name: "pkce_verifier", Value: pkce.Verifier, MaxAge: 300})
    http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: state, MaxAge: 300})
    
    // 4. Redirect ke Keycloak
    authURL := sso.GetAuthURL(state, pkce.Challenge)
    http.Redirect(w, r, authURL, http.StatusFound)
}

// CallbackHandler - Handle callback dari Keycloak
func CallbackHandler(w http.ResponseWriter, r *http.Request) {
    // 1. Validasi state
    stateCookie, _ := r.Cookie("oauth_state")
    if r.URL.Query().Get("state") != stateCookie.Value {
        http.Error(w, "Invalid state", 400)
        return
    }
    
    // 2. Ambil code
    code := r.URL.Query().Get("code")
    
    // 3. Ambil verifier
    verifierCookie, _ := r.Cookie("pkce_verifier")
    
    // 4. Exchange code
    token, err := sso.ExchangeCode(code, verifierCookie.Value)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    
    // 5. Parse user info
    user, _ := sso.ParseIDToken(token.IDToken)
    
    // 6. Buat session (implementasi Anda)
    sessionID := createSession(user.Email)
    
    // 7. Set cookies
    http.SetCookie(w, &http.Cookie{Name: "session_id", Value: sessionID, MaxAge: 86400})
    http.SetCookie(w, &http.Cookie{Name: "id_token", Value: token.IDToken, MaxAge: 86400})
    
    // 8. Clear PKCE cookies
    http.SetCookie(w, &http.Cookie{Name: "pkce_verifier", MaxAge: -1})
    http.SetCookie(w, &http.Cookie{Name: "oauth_state", MaxAge: -1})
    
    // 9. Redirect ke dashboard
    http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// LogoutHandler - Logout dari SSO
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
    // 1. Ambil ID token
    idTokenCookie, _ := r.Cookie("id_token")
    
    // 2. Clear session
    http.SetCookie(w, &http.Cookie{Name: "session_id", MaxAge: -1})
    http.SetCookie(w, &http.Cookie{Name: "id_token", MaxAge: -1})
    
    // 3. Redirect ke Keycloak logout
    logoutURL := sso.GetLogoutURL(idTokenCookie.Value, "http://localhost:8070/login")
    http.Redirect(w, r, logoutURL, http.StatusFound)
}
```

---

## Implementasi JavaScript (Browser)

### File: `sso-client.js`

```javascript
class SSOClient {
    constructor(config) {
        this.baseURL = config.baseURL;       // 'http://localhost:8080'
        this.realm = config.realm;           // 'dinas-pendidikan'
        this.clientId = config.clientId;     // 'your-app-client'
        this.redirectUri = config.redirectUri; // 'http://localhost:3000/callback'
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
    
    // Mulai login
    async login() {
        const { verifier, challenge } = await this.generatePKCE();
        const state = this.base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
        
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
        
        window.location.href = `${this.baseURL}/realms/${this.realm}/protocol/openid-connect/auth?${params}`;
    }
    
    // Handle callback
    async handleCallback() {
        const params = new URLSearchParams(window.location.search);
        const code = params.get('code');
        const state = params.get('state');
        
        // Validasi state
        if (state !== sessionStorage.getItem('oauth_state')) {
            throw new Error('Invalid state');
        }
        
        const verifier = sessionStorage.getItem('pkce_verifier');
        
        // Exchange code untuk token
        const response = await fetch(`${this.baseURL}/realms/${this.realm}/protocol/openid-connect/token`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: this.clientId,
                code: code,
                redirect_uri: this.redirectUri,
                code_verifier: verifier
            })
        });
        
        if (!response.ok) throw new Error('Token exchange failed');
        
        const tokens = await response.json();
        
        // Clear PKCE
        sessionStorage.removeItem('pkce_verifier');
        sessionStorage.removeItem('oauth_state');
        
        // Parse user info dari ID token
        const user = this.parseJwt(tokens.id_token);
        
        return { tokens, user };
    }
    
    // Parse JWT
    parseJwt(token) {
        const payload = token.split('.')[1];
        return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    }
    
    // Logout
    logout(idToken) {
        const params = new URLSearchParams({
            client_id: this.clientId,
            post_logout_redirect_uri: window.location.origin + '/login',
            id_token_hint: idToken
        });
        
        window.location.href = `${this.baseURL}/realms/${this.realm}/protocol/openid-connect/logout?${params}`;
    }
}

// Penggunaan:
const sso = new SSOClient({
    baseURL: 'http://localhost:8080',
    realm: 'dinas-pendidikan',
    clientId: 'your-app-client',
    redirectUri: 'http://localhost:3000/callback'
});

// Login
document.getElementById('loginBtn').onclick = () => sso.login();

// Callback (di halaman /callback)
if (window.location.pathname === '/callback') {
    sso.handleCallback()
        .then(({ tokens, user }) => {
            localStorage.setItem('access_token', tokens.access_token);
            localStorage.setItem('id_token', tokens.id_token);
            localStorage.setItem('user', JSON.stringify(user));
            window.location.href = '/dashboard';
        })
        .catch(err => console.error(err));
}
```

---

## Implementasi PHP (Laravel)

### File: `app/Services/KeycloakService.php`

```php
<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class KeycloakService
{
    private string $baseUrl;
    private string $realm;
    private string $clientId;
    private string $redirectUri;
    
    public function __construct()
    {
        $this->baseUrl = config('keycloak.base_url');
        $this->realm = config('keycloak.realm');
        $this->clientId = config('keycloak.client_id');
        $this->redirectUri = config('keycloak.redirect_uri');
    }
    
    public function generatePKCE(): array
    {
        $verifier = Str::random(64);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        return compact('verifier', 'challenge');
    }
    
    public function getAuthUrl(string $state, string $challenge): string
    {
        return "{$this->baseUrl}/realms/{$this->realm}/protocol/openid-connect/auth?" . http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => 'openid email profile',
            'state' => $state,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256'
        ]);
    }
    
    public function exchangeCode(string $code, string $verifier): array
    {
        $response = Http::asForm()->post(
            "{$this->baseUrl}/realms/{$this->realm}/protocol/openid-connect/token",
            [
                'grant_type' => 'authorization_code',
                'client_id' => $this->clientId,
                'code' => $code,
                'redirect_uri' => $this->redirectUri,
                'code_verifier' => $verifier
            ]
        );
        
        if ($response->failed()) {
            throw new \Exception('Token exchange failed: ' . $response->body());
        }
        
        return $response->json();
    }
    
    public function parseIdToken(string $idToken): array
    {
        $parts = explode('.', $idToken);
        $payload = base64_decode(strtr($parts[1], '-_', '+/'));
        return json_decode($payload, true);
    }
    
    public function getLogoutUrl(string $idToken): string
    {
        return "{$this->baseUrl}/realms/{$this->realm}/protocol/openid-connect/logout?" . http_build_query([
            'client_id' => $this->clientId,
            'post_logout_redirect_uri' => url('/login'),
            'id_token_hint' => $idToken
        ]);
    }
}
```

### File: `app/Http/Controllers/AuthController.php`

```php
<?php

namespace App\Http\Controllers;

use App\Services\KeycloakService;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    private KeycloakService $keycloak;
    
    public function __construct(KeycloakService $keycloak)
    {
        $this->keycloak = $keycloak;
    }
    
    public function login()
    {
        $pkce = $this->keycloak->generatePKCE();
        $state = Str::random(32);
        
        session(['pkce_verifier' => $pkce['verifier'], 'oauth_state' => $state]);
        
        return redirect($this->keycloak->getAuthUrl($state, $pkce['challenge']));
    }
    
    public function callback(Request $request)
    {
        if ($request->state !== session('oauth_state')) {
            abort(400, 'Invalid state');
        }
        
        $tokens = $this->keycloak->exchangeCode($request->code, session('pkce_verifier'));
        $user = $this->keycloak->parseIdToken($tokens['id_token']);
        
        session()->forget(['pkce_verifier', 'oauth_state']);
        session(['user' => $user, 'id_token' => $tokens['id_token']]);
        
        return redirect('/dashboard');
    }
    
    public function logout()
    {
        $idToken = session('id_token');
        session()->flush();
        return redirect($this->keycloak->getLogoutUrl($idToken));
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

class KeycloakSSO:
    def __init__(self):
        self.base_url = os.getenv('KEYCLOAK_BASE_URL')
        self.realm = os.getenv('KEYCLOAK_REALM')
        self.client_id = os.getenv('KEYCLOAK_CLIENT_ID')
        self.redirect_uri = os.getenv('KEYCLOAK_REDIRECT_URI')
    
    def generate_pkce(self):
        verifier = secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).rstrip(b'=').decode()
        return verifier, challenge
    
    def get_auth_url(self, state, challenge):
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': 'openid email profile',
            'state': state,
            'code_challenge': challenge,
            'code_challenge_method': 'S256'
        }
        query = '&'.join(f'{k}={v}' for k, v in params.items())
        return f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/auth?{query}"
    
    def exchange_code(self, code, verifier):
        response = requests.post(
            f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token",
            data={
                'grant_type': 'authorization_code',
                'client_id': self.client_id,
                'code': code,
                'redirect_uri': self.redirect_uri,
                'code_verifier': verifier
            }
        )
        response.raise_for_status()
        return response.json()
    
    def parse_id_token(self, id_token):
        payload = id_token.split('.')[1]
        # Add padding
        payload += '=' * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        import json
        return json.loads(decoded)
    
    def get_logout_url(self, id_token):
        from urllib.parse import urlencode
        params = {
            'client_id': self.client_id,
            'post_logout_redirect_uri': os.getenv('APP_URL') + '/login',
            'id_token_hint': id_token
        }
        return f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/logout?{urlencode(params)}"
```

### File: `app.py`

```python
from flask import Flask, redirect, request, session, url_for
from sso.keycloak import KeycloakSSO
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
sso = KeycloakSSO()

@app.route('/login')
def login():
    verifier, challenge = sso.generate_pkce()
    state = secrets.token_urlsafe(16)
    
    session['pkce_verifier'] = verifier
    session['oauth_state'] = state
    
    return redirect(sso.get_auth_url(state, challenge))

@app.route('/callback')
def callback():
    if request.args.get('state') != session.get('oauth_state'):
        return 'Invalid state', 400
    
    tokens = sso.exchange_code(request.args['code'], session['pkce_verifier'])
    user = sso.parse_id_token(tokens['id_token'])
    
    session.pop('pkce_verifier', None)
    session.pop('oauth_state', None)
    session['user'] = user
    session['id_token'] = tokens['id_token']
    
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    id_token = session.get('id_token')
    session.clear()
    return redirect(sso.get_logout_url(id_token))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    return f"Welcome, {session['user'].get('name', 'User')}!"
```

---

## Implementasi Node.js (Express)

### File: `sso/keycloak.js`

```javascript
const crypto = require('crypto');
const axios = require('axios');

class KeycloakSSO {
    constructor() {
        this.baseUrl = process.env.KEYCLOAK_BASE_URL;
        this.realm = process.env.KEYCLOAK_REALM;
        this.clientId = process.env.KEYCLOAK_CLIENT_ID;
        this.redirectUri = process.env.KEYCLOAK_REDIRECT_URI;
    }
    
    generatePKCE() {
        const verifier = crypto.randomBytes(32).toString('base64url');
        const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
        return { verifier, challenge };
    }
    
    getAuthUrl(state, challenge) {
        const params = new URLSearchParams({
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            response_type: 'code',
            scope: 'openid email profile',
            state,
            code_challenge: challenge,
            code_challenge_method: 'S256'
        });
        return `${this.baseUrl}/realms/${this.realm}/protocol/openid-connect/auth?${params}`;
    }
    
    async exchangeCode(code, verifier) {
        const response = await axios.post(
            `${this.baseUrl}/realms/${this.realm}/protocol/openid-connect/token`,
            new URLSearchParams({
                grant_type: 'authorization_code',
                client_id: this.clientId,
                code,
                redirect_uri: this.redirectUri,
                code_verifier: verifier
            })
        );
        return response.data;
    }
    
    parseIdToken(idToken) {
        const payload = idToken.split('.')[1];
        return JSON.parse(Buffer.from(payload, 'base64url').toString());
    }
    
    getLogoutUrl(idToken) {
        const params = new URLSearchParams({
            client_id: this.clientId,
            post_logout_redirect_uri: process.env.APP_URL + '/login',
            id_token_hint: idToken
        });
        return `${this.baseUrl}/realms/${this.realm}/protocol/openid-connect/logout?${params}`;
    }
}

module.exports = new KeycloakSSO();
```

### File: `app.js`

```javascript
const express = require('express');
const session = require('express-session');
const sso = require('./sso/keycloak');

const app = express();

app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true
}));

app.get('/login', (req, res) => {
    const { verifier, challenge } = sso.generatePKCE();
    const state = require('crypto').randomBytes(16).toString('base64url');
    
    req.session.pkceVerifier = verifier;
    req.session.oauthState = state;
    
    res.redirect(sso.getAuthUrl(state, challenge));
});

app.get('/callback', async (req, res) => {
    if (req.query.state !== req.session.oauthState) {
        return res.status(400).send('Invalid state');
    }
    
    try {
        const tokens = await sso.exchangeCode(req.query.code, req.session.pkceVerifier);
        const user = sso.parseIdToken(tokens.id_token);
        
        delete req.session.pkceVerifier;
        delete req.session.oauthState;
        
        req.session.user = user;
        req.session.idToken = tokens.id_token;
        
        res.redirect('/dashboard');
    } catch (err) {
        res.status(500).send(err.message);
    }
});

app.get('/logout', (req, res) => {
    const idToken = req.session.idToken;
    req.session.destroy();
    res.redirect(sso.getLogoutUrl(idToken));
});

app.get('/dashboard', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    res.send(`Welcome, ${req.session.user.name}!`);
});

app.listen(3000);
```

---

## Session Management

### Validasi Session Berkala

```javascript
// Cek session setiap 30 detik
setInterval(() => {
    fetch('/api/validate-session')
        .then(res => {
            if (res.status === 401) {
                window.location.href = '/login';
            }
        });
}, 30000);

// Cek saat window focus
window.addEventListener('focus', () => {
    fetch('/api/validate-session')
        .then(res => {
            if (res.status === 401) {
                window.location.href = '/login';
            }
        });
});
```

---

## Troubleshooting

### Error: "Missing code_challenge_method"

**Penyebab**: PKCE tidak dikirim dengan benar.

**Solusi**:
```
Pastikan parameter berikut ada di URL authorization:
- code_challenge=<challenge>
- code_challenge_method=S256
```

### Error: "Invalid redirect_uri"

**Penyebab**: Redirect URI tidak cocok dengan yang terdaftar di Keycloak.

**Solusi**:
1. Cek konfigurasi client di Keycloak Admin Console
2. Pastikan `Valid Redirect URIs` mengandung URL callback Anda
3. Pastikan protokol (http/https) dan port sama persis

### Error: "Invalid state"

**Penyebab**: Cookie state hilang atau tidak cocok.

**Solusi**:
1. Pastikan cookie `SameSite=Lax` atau `None` (dengan Secure)
2. Cek browser tidak memblokir third-party cookies
3. Pastikan state disimpan sebelum redirect

### Error: "Token exchange failed"

**Penyebab**: Code verifier tidak cocok dengan challenge.

**Solusi**:
1. Pastikan verifier disimpan saat generate challenge
2. Gunakan verifier yang sama saat exchange
3. Jangan encode verifier dua kali

---

## Referensi

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [OAuth 2.0 PKCE RFC](https://datatracker.ietf.org/doc/html/rfc7636)
- [OpenID Connect Specification](https://openid.net/specs/openid-connect-core-1_0.html)

---

*Panduan ini dibuat untuk integrasi SSO Keycloak dengan website client Dinas Pendidikan DKI Jakarta.*
