package api

import (
	"client-dinas-pendidikan/pkg/helpers"
	"net/http"
)

// RequireAuth telah dipindahkan ke main_handler.go

// GetAccessToken mengambil access token dari cookie (untuk digunakan di API calls)
func GetAccessToken(r *http.Request) (string, error) {
	return helpers.GetCookie(r, "sso_access_token")
}
