package main

// TokenResponse represents the response from Keycloak token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope,omitempty"`
}

// UserInfo represents the user information extracted from SSO
type UserInfo struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	EmailVerified     bool   `json:"email_verified"`
	Peran             string `json:"peran,omitempty"` // Peran dari SSO (admin, user, dll)
	Role              string `json:"role,omitempty"`  // Alternative field name untuk peran
}
