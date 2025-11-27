//go:build dev
// +build dev

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
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

func main() {
	// Load environment variables from .env file
	loadEnvFile()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8070"
	}

	// Kill any existing processes on port
	fmt.Printf("🧹 Cleaning up port %s...\n", port)
	killCmd := exec.Command("lsof", "-ti:"+port)
	if output, err := killCmd.Output(); err == nil && len(output) > 0 {
		pids := strings.TrimSpace(string(output))
		if pids != "" {
			for _, pid := range strings.Split(pids, "\n") {
				if pid != "" {
					exec.Command("kill", "-9", pid).Run()
				}
			}
			fmt.Printf("✅ Port %s cleaned up\n", port)
		}
	}

	// Wait a moment for port to be freed
	time.Sleep(2 * time.Second)

	fmt.Printf("🚀 Client Dinas Pendidikan starting on http://localhost:%s\n", port)
	fmt.Println("Building and running server...")

	// Build and run the server
	cmd := exec.Command("go", "run", "api/main_handler.go")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error running server: %v\n", err)
		os.Exit(1)
	}
}
