//go:build dev
// +build dev

package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"

	"client-dinas-pendidikan/api"
)

func loadEnvFile() {
	file, err := os.Open(".env")
	if err != nil {
		fmt.Println("⚠️  .env file not found, using system environment variables")
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// Remove quotes if present
			if len(value) > 0 && (value[0] == '"' || value[0] == '\'') {
				value = value[1 : len(value)-1]
			}
			os.Setenv(key, value)
		}
	}
	fmt.Println("✅ Loaded environment variables from .env")
}

func serveLogo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Write(api.LogoData)
}

func main() {
	// Load environment variables from .env file
	loadEnvFile()

	// Serve logo
	http.HandleFunc("/logo.png", serveLogo)

	// All routes go through the main handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		api.Handler(w, r)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8070"
	}

	fmt.Printf("🚀 Client Dinas Pendidikan running on http://localhost:%s\n", port)
	fmt.Println("Press Ctrl+C to stop")
	http.ListenAndServe(":"+port, nil)
}
