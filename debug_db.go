package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/lib/pq"
)

func loadEnv() {
	file, err := os.Open(".env")
	if err != nil {
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
			if len(value) > 0 && (value[0] == '"' || value[0] == '\'') {
				value = value[1 : len(value)-1]
			}
			os.Setenv(key, value)
		}
	}
}

func main() {
	loadEnv()

	host := os.Getenv("POSTGRES_HOST")
	if host == "" { host = "localhost" }
	
	port := os.Getenv("POSTGRES_PORT")
	if port == "" { port = "5433" }
	
	user := os.Getenv("POSTGRES_USER")
	if user == "" { user = "postgres" }
	
	password := os.Getenv("POSTGRES_PASSWORD")
	if password == "" { password = "postgres123" }
	
	dbname := os.Getenv("POSTGRES_DB")
	if dbname == "" { dbname = "dinas_pendidikan" }

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	fmt.Printf("🔌 Connecting to DB: %s (port %s)...\n", host, port)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatalf("❌ Connection failed: %v", err)
	}
	fmt.Println("✅ Connected to database successfully!")

	// Check for user
	emailToCheck := "bagas@dinas-pendidikan.go.id" // Replace with actual email if different
	fmt.Printf("🔍 Checking for user: %s\n", emailToCheck)

	var id, nama string
	var aktif bool
	query := `SELECT id_pengguna, nama_lengkap, aktif FROM pengguna WHERE email = $1`
	
	err = db.QueryRow(query, emailToCheck).Scan(&id, &nama, &aktif)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("❌ User '%s' NOT FOUND in 'pengguna' table!\n", emailToCheck)
			fmt.Println("👉 Solution: Insert this user into the database.")
		} else {
			fmt.Printf("❌ Error querying user: %v\n", err)
		}
	} else {
		fmt.Printf("✅ User FOUND!\nID: %s\nName: %s\nActive: %v\n", id, nama, aktif)
		if !aktif {
			fmt.Println("⚠️ User is inactive! Set aktif=true in database.")
		}
	}
}
