package config

import (
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

// Config represents the application configuration
type Config struct {
	Server    ServerConfig
	Database  DatabaseConfig
	JWT       JWTConfig
	Security  SecurityConfig
	RateLimit RateLimitConfig
	CORS      CORSConfig
	Logging   LoggingConfig
	Swagger   bool
	Mailer    MailerConfig
}

// ServerConfig contains server configuration
type ServerConfig struct {
	Port string
	Host string
	Env  string
}

// DatabaseConfig contains database configuration
type DatabaseConfig struct {
	Host            string
	Port            string
	User            string
	Password        string
	Name            string
	SSLMode         string
	MaxConnections  int
	IdleConnections int
	Lifetime        time.Duration
}

// JWTConfig contains JWT configuration
type JWTConfig struct {
	Secret                string
	PublicKeyPath         string
	PrivateKeyPath        string
	Algorithm             string
	TokenExpireMin        int
	RefreshExpireH        int
	SessionTimeout        time.Duration
	MaxConcurrentSessions int
}

// SecurityConfig contains security configuration
type SecurityConfig struct {
	PasswordMinLength       int
	PasswordHistorySize     int
	PasswordExpiryDays      int
	AccountLockoutThreshold int
	AccountLockoutDuration  time.Duration
	ResetTokenExpireMin     int
	SecurityHeaders         bool
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	Requests int
	Duration time.Duration
}

// CORSConfig contains CORS configuration
type CORSConfig struct {
	AllowedOrigins   string
	AllowedMethods   string
	AllowedHeaders   string
	ExposeHeaders    string
	AllowCredentials bool
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level        string
	Format       string
	FilePath     string
	MaxSize      int
	MaxBackups   int
	MaxAge       int
	Compress     bool
	AuditLogPath string
}

// MailerConfig contains mailer configuration
type MailerConfig struct {
	Host     string
	Port     string
	User     string
	Password string
}

// LoadConfig loads application configuration from environment variables
func LoadConfig() *Config {
	// Load .env file if it exists
	err := godotenv.Load()
	if err != nil {
		logrus.Warn("No .env file found or error loading it. Using environment variables.")
	}

	return &Config{
		Server: ServerConfig{
			Port: getEnv("SERVER_PORT", "8080"),
			Host: getEnv("SERVER_HOST", "0.0.0.0"),
			Env:  getEnv("ENV", "development"),
		},
		Database: DatabaseConfig{
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnv("DB_PORT", "5432"),
			User:            getEnv("DB_USER", "postgres"),
			Password:        getEnv("DB_PASSWORD", "postgres"),
			Name:            getEnv("DB_NAME", "user_management"),
			SSLMode:         getEnv("DB_SSL_MODE", "disable"),
			MaxConnections:  getEnvAsInt("DB_MAX_CONNECTIONS", 100),
			IdleConnections: getEnvAsInt("DB_MAX_IDLE_CONNECTIONS", 10),
			Lifetime:        getEnvAsDuration("DB_MAX_LIFETIME", time.Hour),
		},
		JWT: JWTConfig{
			Secret:                getEnv("JWT_SECRET", "your-super-secret-string"),
			PublicKeyPath:         getEnv("JWT_PUBLIC_KEY", "./keys/public.pem"),
			PrivateKeyPath:        getEnv("JWT_PRIVATE_KEY", "./keys/private.pem"),
			Algorithm:             getEnv("JWT_ALGO", "RS256"),
			TokenExpireMin:        getEnvAsInt("TOKEN_EXPIRE_MIN", 15),
			RefreshExpireH:        getEnvAsInt("REFRESH_TOKEN_EXPIRE_H", 72),
			SessionTimeout:        getEnvAsDuration("SESSION_TIMEOUT", 30*time.Minute),
			MaxConcurrentSessions: getEnvAsInt("MAX_CONCURRENT_SESSIONS", 3),
		},
		Security: SecurityConfig{
			PasswordMinLength:       getEnvAsInt("PASSWORD_MIN_LENGTH", 8),
			PasswordHistorySize:     getEnvAsInt("PASSWORD_HISTORY_SIZE", 5),
			PasswordExpiryDays:      getEnvAsInt("PASSWORD_EXPIRY_DAYS", 90),
			AccountLockoutThreshold: getEnvAsInt("ACCOUNT_LOCKOUT_THRESHOLD", 5),
			AccountLockoutDuration:  getEnvAsDuration("ACCOUNT_LOCKOUT_DURATION", 30*time.Minute),
			ResetTokenExpireMin:     getEnvAsInt("RESET_PASSWORD_TOKEN_EXPIRE_MIN", 15),
			SecurityHeaders:         getEnvAsBool("SECURITY_HEADERS", true),
		},
		RateLimit: RateLimitConfig{
			Requests: getEnvAsInt("RATE_LIMIT_REQUESTS", 100),
			Duration: getEnvAsDuration("RATE_LIMIT_DURATION", time.Minute),
		},
		CORS: CORSConfig{
			AllowedOrigins:   getEnv("CORS_ALLOWED_ORIGINS", "*"),
			AllowedMethods:   getEnv("CORS_ALLOWED_METHODS", "GET,POST,PUT,DELETE,OPTIONS"),
			AllowedHeaders:   getEnv("CORS_ALLOWED_HEADERS", "Content-Type,Authorization,X-CSRF-Token"),
			ExposeHeaders:    getEnv("CORS_EXPOSE_HEADERS", "Content-Length,Content-Type"),
			AllowCredentials: getEnvAsBool("CORS_ALLOW_CREDENTIALS", true),
		},
		Logging: LoggingConfig{
			Level:        getEnv("LOG_LEVEL", "info"),
			Format:       getEnv("LOG_FORMAT", "json"),
			FilePath:     getEnv("LOG_FILE_PATH", "./logs/app.log"),
			MaxSize:      getEnvAsInt("LOG_MAX_SIZE", 100),
			MaxBackups:   getEnvAsInt("LOG_MAX_BACKUPS", 3),
			MaxAge:       getEnvAsInt("LOG_MAX_AGE", 28),
			Compress:     getEnvAsBool("LOG_COMPRESS", true),
			AuditLogPath: getEnv("AUDIT_LOG_PATH", "./logs/audit.log"),
		},
		Swagger: getEnvAsBool("SWAGGER_ENABLE", true),
		Mailer: MailerConfig{
			Host:     getEnv("MAILER_HOST", "smtp.example.com"),
			Port:     getEnv("MAILER_PORT", "587"),
			User:     getEnv("MAILER_USER", "noreply@example.com"),
			Password: getEnv("MAILER_PASS", ""),
		},
	}
}

// Helper function to get an environment variable or a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// Helper function to get an environment variable as an integer
func getEnvAsInt(key string, defaultValue int) int {
	strValue := getEnv(key, "")
	if strValue == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(strValue)
	if err != nil {
		logrus.Warnf("Failed to parse %s as int: %v. Using default: %d", key, err, defaultValue)
		return defaultValue
	}
	return value
}

// Helper function to get an environment variable as a boolean
func getEnvAsBool(key string, defaultValue bool) bool {
	strValue := getEnv(key, "")
	if strValue == "" {
		return defaultValue
	}
	value, err := strconv.ParseBool(strValue)
	if err != nil {
		logrus.Warnf("Failed to parse %s as bool: %v. Using default: %t", key, err, defaultValue)
		return defaultValue
	}
	return value
}

// Helper function to get an environment variable as a duration
func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	strValue := getEnv(key, "")
	if strValue == "" {
		return defaultValue
	}
	value, err := time.ParseDuration(strValue)
	if err != nil {
		logrus.Warnf("Failed to parse %s as duration: %v. Using default: %s", key, err, defaultValue)
		return defaultValue
	}
	return value
}
