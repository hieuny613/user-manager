package config

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config holds the application configuration
type Config struct {
	Environment string
	Version     string
	Server      ServerConfig
	Security    SecurityConfig
	Database    DatabaseConfig
	JWT         JWTConfig
	Email       EmailConfig
	Storage     StorageConfig
	Logging     LoggingConfig
	Monitoring  MonitoringConfig
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	Host            string
	Port            int
	BaseURL         string
	ShutdownTimeout time.Duration
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	MaxHeaderBytes  int
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	CORSAllowOrigins  string
	CORSAllowMethods  string
	CORSAllowHeaders  string
	CSP               string
	HSTS              bool
	PasswordMinLength int
	PasswordMaxAge    time.Duration
	PasswordHistory   int
	MaxLoginAttempts  int
	LockoutDuration   time.Duration
	SessionTimeout    time.Duration
	MaxSessions       int
	RateLimit         RateLimitConfig
	CSRFSecret        string
	CSRFTokenExpiry   time.Duration
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled         bool
	StandardLimit   int           // Requests per window for standard endpoints
	StandardBurst   int           // Burst size for standard endpoints
	StandardWindow  time.Duration // Time window for standard endpoints
	SensitiveLimit  int           // Requests per window for sensitive endpoints
	SensitiveBurst  int           // Burst size for sensitive endpoints
	SensitiveWindow time.Duration // Time window for sensitive endpoints
}

// DatabaseConfig holds database-related configuration
type DatabaseConfig struct {
	Driver          string
	Host            string
	Port            int
	Username        string
	Password        string
	Database        string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// JWTConfig holds JWT-related configuration
type JWTConfig struct {
	AccessTokenSecret  string
	RefreshTokenSecret string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	Issuer             string
	Audience           string
}

// EmailConfig holds email-related configuration
type EmailConfig struct {
	Enabled        bool
	From           string
	SMTPHost       string
	SMTPPort       int
	SMTPUsername   string
	SMTPPassword   string
	SMTPEncryption string
}

// StorageConfig holds storage-related configuration
type StorageConfig struct {
	Type           string // local, s3, gcs, etc.
	BasePath       string // for local storage
	S3Bucket       string
	S3Region       string
	S3AccessKey    string
	S3SecretKey    string
	GCSBucket      string
	GCSCredentials string
}

// LoggingConfig holds logging-related configuration
type LoggingConfig struct {
	Level         string
	Format        string
	Output        string
	EnableConsole bool
	EnableFile    bool
	FilePath      string
	MaxSize       int
	MaxBackups    int
	MaxAge        int
	Compress      bool
}

// MonitoringConfig holds monitoring-related configuration
type MonitoringConfig struct {
	Enabled           bool
	PrometheusEnabled bool
	PrometheusPath    string
	TracingEnabled    bool
	TracingProvider   string
	TracingEndpoint   string
	MetricsEnabled    bool
	MetricsEndpoint   string
}

var (
	config     *Config
	configOnce sync.Once
)

// GetConfig returns the application configuration
func GetConfig() *Config {
	configOnce.Do(func() {
		config = loadConfig()
	})
	return config
}

// loadConfig loads the application configuration from environment variables
func loadConfig() *Config {
	return &Config{
		Environment: getEnv("APP_ENV", "development"),
		Version:     getEnv("APP_VERSION", "1.0.0"),
		Server: ServerConfig{
			Host:            getEnv("SERVER_HOST", ""),
			Port:            getEnvAsInt("SERVER_PORT", 8080),
			BaseURL:         getEnv("SERVER_BASE_URL", "http://localhost:8080"),
			ShutdownTimeout: getEnvAsDuration("SERVER_SHUTDOWN_TIMEOUT", 10*time.Second),
			ReadTimeout:     getEnvAsDuration("SERVER_READ_TIMEOUT", 5*time.Second),
			WriteTimeout:    getEnvAsDuration("SERVER_WRITE_TIMEOUT", 10*time.Second),
			IdleTimeout:     getEnvAsDuration("SERVER_IDLE_TIMEOUT", 120*time.Second),
			MaxHeaderBytes:  getEnvAsInt("SERVER_MAX_HEADER_BYTES", 1<<20), // 1 MB
		},
		Security: SecurityConfig{
			CORSAllowOrigins:  getEnv("SECURITY_CORS_ALLOW_ORIGINS", "*"),
			CORSAllowMethods:  getEnv("SECURITY_CORS_ALLOW_METHODS", "GET,POST,PUT,DELETE,OPTIONS"),
			CORSAllowHeaders:  getEnv("SECURITY_CORS_ALLOW_HEADERS", "Content-Type,Authorization,X-CSRF-Token"),
			CSP:               getEnv("SECURITY_CSP", "default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self'; img-src 'self'; media-src 'self'; frame-src 'none'; font-src 'self'; connect-src 'self'"),
			HSTS:              getEnvAsBool("SECURITY_HSTS", true),
			PasswordMinLength: getEnvAsInt("SECURITY_PASSWORD_MIN_LENGTH", 12),
			PasswordMaxAge:    getEnvAsDuration("SECURITY_PASSWORD_MAX_AGE", 90*24*time.Hour), // 90 days
			PasswordHistory:   getEnvAsInt("SECURITY_PASSWORD_HISTORY", 5),
			MaxLoginAttempts:  getEnvAsInt("SECURITY_MAX_LOGIN_ATTEMPTS", 5),
			LockoutDuration:   getEnvAsDuration("SECURITY_LOCKOUT_DURATION", 15*time.Minute),
			SessionTimeout:    getEnvAsDuration("SECURITY_SESSION_TIMEOUT", 30*time.Minute),
			MaxSessions:       getEnvAsInt("SECURITY_MAX_SESSIONS", 5),
			RateLimit: RateLimitConfig{
				Enabled:         getEnvAsBool("SECURITY_RATE_LIMIT_ENABLED", true),
				StandardLimit:   getEnvAsInt("SECURITY_RATE_LIMIT_STANDARD_LIMIT", 100),
				StandardBurst:   getEnvAsInt("SECURITY_RATE_LIMIT_STANDARD_BURST", 150),
				StandardWindow:  getEnvAsDuration("SECURITY_RATE_LIMIT_STANDARD_WINDOW", time.Minute),
				SensitiveLimit:  getEnvAsInt("SECURITY_RATE_LIMIT_SENSITIVE_LIMIT", 10),
				SensitiveBurst:  getEnvAsInt("SECURITY_RATE_LIMIT_SENSITIVE_BURST", 20),
				SensitiveWindow: getEnvAsDuration("SECURITY_RATE_LIMIT_SENSITIVE_WINDOW", time.Minute),
			},
			CSRFSecret:      getEnv("SECURITY_CSRF_SECRET", generateRandomString(32)),
			CSRFTokenExpiry: getEnvAsDuration("SECURITY_CSRF_TOKEN_EXPIRY", 1*time.Hour),
		},
		Database: DatabaseConfig{
			Driver:          getEnv("DB_DRIVER", "postgres"),
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnvAsInt("DB_PORT", 5432),
			Username:        getEnv("DB_USERNAME", "postgres"),
			Password:        getEnv("DB_PASSWORD", "postgres"),
			Database:        getEnv("DB_DATABASE", "auth_service"),
			SSLMode:         getEnv("DB_SSL_MODE", "disable"),
			MaxOpenConns:    getEnvAsInt("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvAsInt("DB_MAX_IDLE_CONNS", 25),
			ConnMaxLifetime: getEnvAsDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
		},
		JWT: JWTConfig{
			AccessTokenSecret:  getEnv("JWT_ACCESS_TOKEN_SECRET", generateRandomString(32)),
			RefreshTokenSecret: getEnv("JWT_REFRESH_TOKEN_SECRET", generateRandomString(32)),
			AccessTokenExpiry:  getEnvAsDuration("JWT_ACCESS_TOKEN_EXPIRY", 15*time.Minute),
			RefreshTokenExpiry: getEnvAsDuration("JWT_REFRESH_TOKEN_EXPIRY", 7*24*time.Hour), // 7 days
			Issuer:             getEnv("JWT_ISSUER", "auth-service"),
			Audience:           getEnv("JWT_AUDIENCE", "auth-service-clients"),
		},
		Email: EmailConfig{
			Enabled:        getEnvAsBool("EMAIL_ENABLED", true),
			From:           getEnv("EMAIL_FROM", "no-reply@example.com"),
			SMTPHost:       getEnv("EMAIL_SMTP_HOST", "smtp.example.com"),
			SMTPPort:       getEnvAsInt("EMAIL_SMTP_PORT", 587),
			SMTPUsername:   getEnv("EMAIL_SMTP_USERNAME", ""),
			SMTPPassword:   getEnv("EMAIL_SMTP_PASSWORD", ""),
			SMTPEncryption: getEnv("EMAIL_SMTP_ENCRYPTION", "tls"),
		},
		Storage: StorageConfig{
			Type:           getEnv("STORAGE_TYPE", "local"),
			BasePath:       getEnv("STORAGE_BASE_PATH", "./storage"),
			S3Bucket:       getEnv("STORAGE_S3_BUCKET", ""),
			S3Region:       getEnv("STORAGE_S3_REGION", ""),
			S3AccessKey:    getEnv("STORAGE_S3_ACCESS_KEY", ""),
			S3SecretKey:    getEnv("STORAGE_S3_SECRET_KEY", ""),
			GCSBucket:      getEnv("STORAGE_GCS_BUCKET", ""),
			GCSCredentials: getEnv("STORAGE_GCS_CREDENTIALS", ""),
		},
		Logging: LoggingConfig{
			Level:         getEnv("LOGGING_LEVEL", "info"),
			Format:        getEnv("LOGGING_FORMAT", "json"),
			Output:        getEnv("LOGGING_OUTPUT", "stdout"),
			EnableConsole: getEnvAsBool("LOGGING_ENABLE_CONSOLE", true),
			EnableFile:    getEnvAsBool("LOGGING_ENABLE_FILE", false),
			FilePath:      getEnv("LOGGING_FILE_PATH", "./logs/app.log"),
			MaxSize:       getEnvAsInt("LOGGING_MAX_SIZE", 10), // 10 MB
			MaxBackups:    getEnvAsInt("LOGGING_MAX_BACKUPS", 3),
			MaxAge:        getEnvAsInt("LOGGING_MAX_AGE", 30), // 30 days
			Compress:      getEnvAsBool("LOGGING_COMPRESS", true),
		},
		Monitoring: MonitoringConfig{
			Enabled:           getEnvAsBool("MONITORING_ENABLED", true),
			PrometheusEnabled: getEnvAsBool("MONITORING_PROMETHEUS_ENABLED", true),
			PrometheusPath:    getEnv("MONITORING_PROMETHEUS_PATH", "/metrics"),
			TracingEnabled:    getEnvAsBool("MONITORING_TRACING_ENABLED", false),
			TracingProvider:   getEnv("MONITORING_TRACING_PROVIDER", "jaeger"),
			TracingEndpoint:   getEnv("MONITORING_TRACING_ENDPOINT", ""),
			MetricsEnabled:    getEnvAsBool("MONITORING_METRICS_ENABLED", true),
			MetricsEndpoint:   getEnv("MONITORING_METRICS_ENDPOINT", ""),
		},
	}
}

// IsDevelopment checks if the application is running in development mode
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// IsProduction checks if the application is running in production mode
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsTest checks if the application is running in test mode
func (c *Config) IsTest() bool {
	return c.Environment == "test"
}

// Helper functions for environment variables

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
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

// getEnvAsBool gets an environment variable as a boolean or returns a default value
func getEnvAsBool(key string, defaultValue bool) bool {
	valueStr := getEnv(key, "")
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.ParseBool(valueStr)
	if err != nil {
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

// generateRandomString generates a random string of the specified length
func generateRandomString(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return strings.Repeat("x", length) // Fallback if random generation fails
	}
	return base64.URLEncoding.EncodeToString(b)[:length]
}
