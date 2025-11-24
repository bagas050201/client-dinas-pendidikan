/**
 * SSO Keycloak Handler untuk Website Client (Authorization Code Flow)
 * File: static/sso-handler.js
 * 
 * Fungsi:
 * - Handle SSO callback dari Keycloak dengan authorization code
 * - Exchange authorization code untuk access token
 * - Verify token dengan Keycloak userinfo endpoint
 * - Auto-login user ke aplikasi
 * - Check atau create user di database
 * - Create session aplikasi
 */

// ============================================
// KONFIGURASI KEYCLOAK
// ============================================
// Auto-detect Keycloak URL berdasarkan environment
// Jika di localhost, gunakan local Keycloak (localhost:8080)
// Jika di production, gunakan production Keycloak (https://sso.dinas-pendidikan.go.id)
function getKeycloakBaseUrl() {
    // PENTING: Cek dulu apakah ada Keycloak URL yang disimpan di sessionStorage
    // Ini untuk handle kasus dimana authorization code berasal dari Keycloak yang berbeda
    // (misalnya: production website tapi redirect ke local Keycloak)
    const storedKeycloakUrl = sessionStorage.getItem('keycloak_base_url');
    if (storedKeycloakUrl) {
        console.log('📍 Using stored Keycloak URL from sessionStorage:', storedKeycloakUrl);
        return storedKeycloakUrl;
    }
    
    // Auto-detect berdasarkan hostname
    const hostname = window.location.hostname;
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
        return 'http://localhost:8080'; // Local Keycloak
    }
    return 'https://sso.dinas-pendidikan.go.id'; // Production Keycloak
}

const SSO_CONFIG = {
    keycloakBaseUrl: getKeycloakBaseUrl(),
    realm: 'dinas-pendidikan',
    clientId: 'localhost-8070-website-dinas-pendidikan', // GANTI dengan client ID aplikasi Anda
    // PENTING: redirectUri harus sesuai dengan yang di-set di Keycloak client settings
    // Keycloak redirect ke root (/) dengan code, lalu kita redirect ke /login dengan query params
    redirectUri: window.location.origin // Keycloak redirect ke root, bukan /login
};

// ============================================
// FUNGSI UTAMA: HANDLE SSO CALLBACK (AUTHORIZATION CODE FLOW)
// ============================================
async function handleSSOCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    const error = urlParams.get('error');
    const errorDescription = urlParams.get('error_description');

    // Handle error dari Keycloak
    if (error) {
        console.error('❌ Keycloak error:', error, errorDescription);
        alert(`Error dari SSO: ${errorDescription || error}. Silakan coba lagi.`);
        // Hapus error dari URL
        const url = new URL(window.location);
        url.searchParams.delete('error');
        url.searchParams.delete('error_description');
        url.searchParams.delete('code');
        url.searchParams.delete('state');
        window.history.replaceState({}, '', url);
        return;
    }

    // Jika ada code, exchange untuk token
    if (code) {
        console.log('🔐 Authorization code ditemukan, memulai exchange token...');
        
        // PENTING: Jika tidak ada Keycloak URL di sessionStorage, coba detect dari referrer
        // Ini untuk handle kasus dimana user mengakses production website tapi redirect ke local Keycloak
        if (!sessionStorage.getItem('keycloak_base_url')) {
            const referrer = document.referrer;
            if (referrer) {
                try {
                    const referrerUrl = new URL(referrer);
                    // Jika referrer adalah localhost:8080, gunakan local Keycloak
                    if (referrerUrl.hostname === 'localhost' && referrerUrl.port === '8080') {
                        sessionStorage.setItem('keycloak_base_url', 'http://localhost:8080');
                        console.log('📍 Detected local Keycloak from referrer, saved to sessionStorage');
                    } else if (referrerUrl.hostname === 'sso.dinas-pendidikan.go.id') {
                        sessionStorage.setItem('keycloak_base_url', 'https://sso.dinas-pendidikan.go.id');
                        console.log('📍 Detected production Keycloak from referrer, saved to sessionStorage');
                    }
                } catch (e) {
                    console.log('⚠️ Could not parse referrer URL:', e);
                }
            }
        }
        
        // Verify state (CSRF protection)
        const storedState = sessionStorage.getItem('oauth_state');
        if (state && storedState && state !== storedState) {
            console.error('❌ State mismatch - possible CSRF attack');
            alert('State tidak valid. Silakan coba lagi.');
            // Clear state dan redirect
            sessionStorage.removeItem('oauth_state');
            const url = new URL(window.location);
            url.searchParams.delete('code');
            url.searchParams.delete('state');
            window.history.replaceState({}, '', url);
            return;
        }

        // Exchange code untuk token
        const tokenData = await exchangeCodeForToken(code);
        if (tokenData && tokenData.access_token) {
            console.log('✅ Token exchange berhasil');
            
            // Verify token dan get user info
            const userInfo = await verifyToken(tokenData.access_token);
            if (userInfo) {
                console.log('✅ Token verified, user info:', userInfo);
                await autoLogin(userInfo, tokenData.access_token, tokenData.id_token);
                
                // Hapus code dan state dari URL (security)
                const url = new URL(window.location);
                url.searchParams.delete('code');
                url.searchParams.delete('state');
                window.history.replaceState({}, '', url);
            } else {
                console.error('❌ Token verification failed');
                alert('Gagal memverifikasi token. Silakan coba lagi.');
            }
        } else {
            console.error('❌ Token exchange failed');
            alert('Gagal menukar authorization code. Silakan coba lagi.');
        }
    } else {
        // Tidak ada code - check session Keycloak (silent check)
        console.log('🔍 Tidak ada authorization code di URL, tampilkan form login biasa');
        // Biarkan user login dengan form biasa atau klik button SSO
    }
}

// ============================================
// EXCHANGE AUTHORIZATION CODE UNTUK ACCESS TOKEN
// ============================================
async function exchangeCodeForToken(code) {
    try {
        // PENTING: Gunakan Keycloak URL yang sama dengan yang digunakan saat authorization
        // Cek dulu dari sessionStorage (disimpan saat redirect ke Keycloak)
        const keycloakBaseUrl = sessionStorage.getItem('keycloak_base_url') || SSO_CONFIG.keycloakBaseUrl;
        const tokenUrl = `${keycloakBaseUrl}/realms/${SSO_CONFIG.realm}/protocol/openid-connect/token`;
        
        console.log('🔄 Exchanging authorization code untuk token...');
        console.log('📍 Token URL:', tokenUrl);
        console.log('📍 Keycloak Base URL:', keycloakBaseUrl, '(from sessionStorage:', !!sessionStorage.getItem('keycloak_base_url'), ')');
        
        // Get code_verifier dari sessionStorage (untuk PKCE)
        const codeVerifier = sessionStorage.getItem('oauth_code_verifier');
        
        const params = {
            grant_type: 'authorization_code',
            client_id: SSO_CONFIG.clientId,
            code: code,
            redirect_uri: SSO_CONFIG.redirectUri
        };
        
        // Tambahkan code_verifier jika ada (PKCE)
        // PENTING: Jika Portal SSO tidak mengirim code_challenge, maka code_verifier tidak akan ada
        // Keycloak akan accept request tanpa code_verifier jika PKCE setting adalah "Not required" atau "Optional"
        if (codeVerifier) {
            params.code_verifier = codeVerifier;
            console.log('✅ Using PKCE code_verifier');
        } else {
            console.log('⚠️ No PKCE code_verifier found (Portal SSO mungkin tidak mengirim code_challenge)');
        }
        
        console.log('📤 Request params:', {
            grant_type: params.grant_type,
            client_id: params.client_id,
            code: code.substring(0, 20) + '...',
            redirect_uri: params.redirect_uri,
            has_code_verifier: !!params.code_verifier
        });
        
        const response = await fetch(tokenUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams(params)
        });

        if (response.ok) {
            const tokenData = await response.json();
            console.log('✅ Token exchange berhasil');
            return tokenData;
        } else {
            const errorText = await response.text().catch(() => 'Failed to read error response');
            let errorData;
            try {
                errorData = JSON.parse(errorText);
            } catch {
                errorData = { error: errorText };
            }
            console.error('❌ Token exchange failed:', response.status, errorData);
            console.error('📍 Failed URL:', tokenUrl);
            return null;
        }
    } catch (error) {
        console.error('❌ Error exchanging code:', error);
        console.error('📍 Error URL:', `${SSO_CONFIG.keycloakBaseUrl}/realms/${SSO_CONFIG.realm}/protocol/openid-connect/token`);
        if (error.message) {
            console.error('💬 Error message:', error.message);
        }
        return null;
    }
}

// ============================================
// VERIFY TOKEN DENGAN KEYCLOAK USERINFO ENDPOINT
// ============================================
async function verifyToken(accessToken) {
    try {
        // Gunakan Keycloak URL yang sama dengan yang digunakan saat token exchange
        const keycloakBaseUrl = sessionStorage.getItem('keycloak_base_url') || SSO_CONFIG.keycloakBaseUrl;
        const userinfoUrl = `${keycloakBaseUrl}/realms/${SSO_CONFIG.realm}/protocol/openid-connect/userinfo`;
        
        const response = await fetch(userinfoUrl, {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });

        if (response.ok) {
            const userInfo = await response.json();
            
            // Transform user info: ubah 'sub' menjadi 'id_user'
            const transformedUserInfo = {
                id_user: userInfo.sub, // sub dari Keycloak adalah ID user
                email: userInfo.email,
                name: userInfo.name || userInfo.preferred_username || userInfo.email,
                preferred_username: userInfo.preferred_username || userInfo.email,
                email_verified: userInfo.email_verified || false,
                // Extract peran/role jika ada
                peran: userInfo.peran || userInfo.role || 'user'
            };
            
            console.log('✅ Token verified, user info:', transformedUserInfo);
            return transformedUserInfo;
        } else {
            console.error('❌ Token verification failed:', response.status);
            return null;
        }
    } catch (error) {
        console.error('❌ Error verifying token:', error);
        return null;
    }
}

// ============================================
// AUTO-LOGIN USER KE APLIKASI
// ============================================
async function autoLogin(userInfo, accessToken, idToken) {
    try {
        // Simpan token di sessionStorage (bukan localStorage untuk security)
        sessionStorage.setItem('sso_access_token', accessToken);
        if (idToken) {
            sessionStorage.setItem('sso_id_token', idToken);
        }
        sessionStorage.setItem('sso_user_info', JSON.stringify(userInfo));

        // Prepare user data
        const userData = {
            id: userInfo.id_user || userInfo.sub, // Fallback ke sub untuk backward compatibility
            email: userInfo.email,
            name: userInfo.name || userInfo.preferred_username || userInfo.email,
            username: userInfo.preferred_username || userInfo.email
        };

        // Check atau create user di database
        const user = await checkOrCreateUser(userData, accessToken);
        
        if (!user) {
            console.error('❌ Gagal check/create user');
            alert('Gagal membuat atau menemukan user. Silakan coba lagi.');
            return;
        }

        // Create session aplikasi
        const sessionResult = await createAppSession(user, accessToken);
        
        if (!sessionResult) {
            console.error('❌ Gagal create session');
            alert('Gagal membuat session. Silakan coba lagi.');
            return;
        }

        console.log('✅ Auto-login berhasil!');
        
        // Redirect ke dashboard atau halaman yang diminta
        const redirectUrl = sessionStorage.getItem('redirect_after_login') || '/dashboard';
        sessionStorage.removeItem('redirect_after_login');
        sessionStorage.removeItem('oauth_state'); // Clear state setelah login berhasil
        sessionStorage.removeItem('oauth_code_verifier'); // Clear code_verifier setelah login berhasil
        sessionStorage.removeItem('keycloak_base_url'); // Clear Keycloak URL setelah login berhasil
        
        // Show loading message
        showLoadingMessage('Login berhasil! Mengalihkan...');
        
        setTimeout(() => {
            window.location.href = redirectUrl;
        }, 1000);

    } catch (error) {
        console.error('❌ Error during auto-login:', error);
        alert('Terjadi kesalahan saat auto-login. Silakan coba lagi.');
    }
}

// ============================================
// CHECK ATAU CREATE USER DI DATABASE
// ============================================
async function checkOrCreateUser(userData, accessToken) {
    try {
        const response = await fetch('/api/users/sso-login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${accessToken}`
            },
            body: JSON.stringify({
                email: userData.email,
                name: userData.name,
                keycloak_id: userData.id
            })
        });

        if (response.ok) {
            const result = await response.json();
            console.log('✅ User check/create berhasil:', result);
            return result.user;
        } else {
            const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
            console.error('❌ Error check/create user:', errorData);
            return null;
        }
    } catch (error) {
        console.error('❌ Error checking user:', error);
        return null;
    }
}

// ============================================
// CREATE SESSION APLIKASI
// ============================================
async function createAppSession(user, accessToken) {
    try {
        const response = await fetch('/api/auth/sso-login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${accessToken}`
            },
            body: JSON.stringify({
                email: user.email,
                keycloak_id: user.keycloak_id || user.id
            })
        });

        if (response.ok) {
            const data = await response.json();
            console.log('✅ Session created:', data);
            
            // Simpan session token jika ada
            if (data.session_token) {
                localStorage.setItem('app_session_token', data.session_token);
            }
            
            return data;
        } else {
            const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
            console.error('❌ Error creating session:', errorData);
            return null;
        }
    } catch (error) {
        console.error('❌ Error creating session:', error);
        return null;
    }
}

// ============================================
// REDIRECT KE KEYCLOAK UNTUK LOGIN (DENGAN PKCE)
// ============================================
function redirectToKeycloak() {
    // Simpan URL saat ini untuk redirect setelah login
    sessionStorage.setItem('redirect_after_login', window.location.pathname);
    
    // PENTING: Simpan Keycloak base URL yang akan digunakan
    // Ini memastikan token exchange menggunakan URL yang sama dengan authorization
    sessionStorage.setItem('keycloak_base_url', SSO_CONFIG.keycloakBaseUrl);
    console.log('💾 Saved Keycloak base URL to sessionStorage:', SSO_CONFIG.keycloakBaseUrl);
    
    // Generate state untuk CSRF protection
    const state = generateRandomString(32);
    sessionStorage.setItem('oauth_state', state);
    
    // Generate PKCE code_verifier dan code_challenge (S256)
    const codeVerifier = generateRandomString(128); // 43-128 characters untuk PKCE
    sessionStorage.setItem('oauth_code_verifier', codeVerifier);
    
    // Generate code_challenge dari code_verifier menggunakan SHA256 (S256)
    generateCodeChallenge(codeVerifier).then(codeChallenge => {
        // Build Keycloak authorization URL dengan state dan PKCE
        const authParams = new URLSearchParams({
            client_id: SSO_CONFIG.clientId,
            redirect_uri: SSO_CONFIG.redirectUri,
            response_type: 'code',
            scope: 'openid email profile',
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256' // Sesuai setting Keycloak
        });
        
        const authUrl = `${SSO_CONFIG.keycloakBaseUrl}/realms/${SSO_CONFIG.realm}/protocol/openid-connect/auth?${authParams.toString()}`;
        
        console.log('🔐 Redirecting to Keycloak dengan PKCE:', authUrl);
        window.location.href = authUrl;
    }).catch(error => {
        console.error('❌ Error generating code challenge:', error);
        // Fallback tanpa PKCE jika error
        const authParams = new URLSearchParams({
            client_id: SSO_CONFIG.clientId,
            redirect_uri: SSO_CONFIG.redirectUri,
            response_type: 'code',
            scope: 'openid email profile',
            state: state
        });
        const authUrl = `${SSO_CONFIG.keycloakBaseUrl}/realms/${SSO_CONFIG.realm}/protocol/openid-connect/auth?${authParams.toString()}`;
    window.location.href = authUrl;
    });
}

// ============================================
// GENERATE RANDOM STRING UNTUK STATE (CSRF PROTECTION)
// ============================================
function generateRandomString(length) {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    let result = '';
    const values = new Uint8Array(length);
    crypto.getRandomValues(values);
    for (let i = 0; i < length; i++) {
        result += charset[values[i] % charset.length];
    }
    return result;
}

// ============================================
// GENERATE CODE CHALLENGE DARI CODE VERIFIER (PKCE S256)
// ============================================
async function generateCodeChallenge(codeVerifier) {
    // Encode code_verifier ke UTF-8
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    
    // Hash dengan SHA256
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    
    // Convert ke base64url (bukan base64 biasa)
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const base64 = btoa(String.fromCharCode(...hashArray));
    
    // Convert base64 ke base64url (replace + dengan -, / dengan _, dan hapus padding =)
    const base64url = base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    
    return base64url;
}

// ============================================
// SHOW LOADING MESSAGE
// ============================================
function showLoadingMessage(message) {
    // Remove existing overlay if any
    const existing = document.getElementById('sso-loading-overlay');
    if (existing) {
        existing.remove();
    }
    
    // Create loading overlay
    const overlay = document.createElement('div');
    overlay.id = 'sso-loading-overlay';
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        justify-content: center;
        align-items: center;
        z-index: 9999;
        color: white;
        font-size: 18px;
    `;
    overlay.innerHTML = `
        <div style="text-align: center;">
            <div style="margin-bottom: 20px;">⏳</div>
            <div>${message}</div>
        </div>
    `;
    document.body.appendChild(overlay);
}

// ============================================
// CLEAR SSO SESSION (UNTUK LOGOUT)
// ============================================
function clearSSOSession() {
    sessionStorage.removeItem('sso_access_token');
    sessionStorage.removeItem('sso_id_token');
    sessionStorage.removeItem('sso_user_info');
    sessionStorage.removeItem('oauth_state');
    sessionStorage.removeItem('oauth_code_verifier');
    sessionStorage.removeItem('redirect_after_login');
    sessionStorage.removeItem('keycloak_base_url');
    localStorage.removeItem('app_session_token');
    console.log('✅ SSO session cleared');
}

// ============================================
// INITIALIZE SAAT PAGE LOAD
// ============================================
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 SSO Handler initialized (Authorization Code Flow)');
    console.log('📋 Config:', SSO_CONFIG);
    console.log('🌐 Keycloak URL:', SSO_CONFIG.keycloakBaseUrl, '(auto-detected from hostname:', window.location.hostname + ')');
    handleSSOCallback();
});

// Export functions untuk digunakan di tempat lain
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        handleSSOCallback,
        exchangeCodeForToken,
        verifyToken,
        autoLogin,
        checkOrCreateUser,
        createAppSession,
        redirectToKeycloak,
        generateRandomString,
        generateCodeChallenge,
        clearSSOSession
    };
}
