package config

import (
	"backend/model"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Database holds the database connection
type Database struct {
	DB *gorm.DB
}

// Global database instance
var db *gorm.DB

// GetDB returns the global database instance
func GetDB() *gorm.DB {
	return db
}

// NewDatabase creates a new database connection
func NewDatabase() *Database {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: .env file not found, using environment variables")
	}

	// Get database connection details from environment variables
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USERNAME", "postgres") // Changed from DB_USER to DB_USERNAME for consistency
	dbPassword := getEnv("DB_PASSWORD", "postgres")
	dbName := getEnv("DB_DATABASE", "user_management") // Changed from DB_NAME to DB_DATABASE for consistency
	dbSSLMode := getEnv("DB_SSL_MODE", "disable")

	// Create DSN string
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		dbHost, dbPort, dbUser, dbPassword, dbName, dbSSLMode)

	// Configure GORM logger
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  logger.Info,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)

	// Connect to database
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Failed to get database connection: %v", err)
	}

	// Set connection pool settings
	maxIdleConns := getEnvAsInt("DB_MAX_IDLE_CONNS", 10)
	maxOpenConns := getEnvAsInt("DB_MAX_OPEN_CONNS", 100)
	connMaxLifetime := getEnvAsDuration("DB_CONN_MAX_LIFETIME", time.Hour)

	sqlDB.SetMaxIdleConns(maxIdleConns)
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetConnMaxLifetime(connMaxLifetime)

	log.Println("Connected to database successfully")

	// Set global DB instance
	SetDB(db)

	return &Database{DB: db}
}

// SetDB sets the global database instance
func SetDB(database *gorm.DB) {
	db = database
}

// Close closes the database connection
func Close() error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	if err := sqlDB.Close(); err != nil {
		return fmt.Errorf("failed to close database connection: %w", err)
	}

	return nil
}

// Ping checks if the database connection is alive
func Ping() error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	return nil
}

// Migrate runs database migrations
func Migrate() error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	log.Println("Running database migrations...")

	// Add all models that need to be migrated here
	models := []interface{}{
		&model.User{},
		&model.Group{},
		&model.Role{},
		&model.Permission{},
		&model.UserGroup{},
		&model.UserRole{},
		&model.GroupRole{},
		&model.RolePermission{},
		&model.Session{},
		&model.PasswordHistory{},
		&model.FailedLoginAttempt{},
		&model.SecurityEvent{},
		&model.AuditLog{},
	}

	// Create UUID extension if it doesn't exist
	db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")

	for _, model := range models {
		if err := db.AutoMigrate(model); err != nil {
			return fmt.Errorf("failed to migrate model: %w", err)
		}
	}

	log.Println("Database migrations completed successfully")
	return nil
}

// getEnvAsInt gets an environment variable as an integer or returns a default value
func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getEnvAsDuration gets an environment variable as a duration or returns a default value
func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	value, err := time.ParseDuration(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}
