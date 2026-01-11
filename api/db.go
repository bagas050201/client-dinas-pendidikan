package main

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

var (
	dbInstance *sql.DB
	dbMutex    sync.Mutex
)

// GetDB returns a singleton database connection pool.
// It initializes the connection if it doesn't exist or is closed.
func GetDB() (*sql.DB, error) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	if dbInstance != nil {
		// Check if connection is still alive
		if err := dbInstance.Ping(); err == nil {
			return dbInstance, nil
		}
		// If ping fails, close and set to nil to reconnect
		dbInstance.Close()
		dbInstance = nil
	}

	var err error
	dbInstance, err = connectPostgreSQL()
	if err != nil {
		return nil, err
	}

	// Configure connection pool
	// For serverless (Vercel), we want to be careful with max connections
	// to avoid exhausting the database connection limit.
	dbInstance.SetMaxOpenConns(5) // Limit max connections
	dbInstance.SetMaxIdleConns(2) // Keep a few idle connections
	dbInstance.SetConnMaxLifetime(30 * time.Minute)

	return dbInstance, nil
}

// connectPostgreSQL creates a new connection to PostgreSQL
func connectPostgreSQL() (*sql.DB, error) {
	host := getPostgresHost()
	port := getPostgresPort()
	dbname := getPostgresDB()
	user := getPostgresUser()
	password := getPostgresPassword()

	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to open PostgreSQL connection: %v", err)
	}

	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping PostgreSQL database: %v", err)
	}

	return db, nil
}

// Environment variable getters

func getPostgresHost() string {
	return getEnvOrDefault("JAKEDU_PG_HOST", "localhost")
}

func getPostgresPort() string {
	return getEnvOrDefault("JAKEDU_PG_PORT", "5432")
}

func getPostgresDB() string {
	return getEnvOrDefault("JAKEDU_PG_DB", "dinas_pendidikan")
}

func getPostgresUser() string {
	return getEnvOrDefault("JAKEDU_PG_USER", "postgres")
}

func getPostgresPassword() string {
	return getEnvOrDefault("JAKEDU_PG_PASSWORD", "postgres")
}
