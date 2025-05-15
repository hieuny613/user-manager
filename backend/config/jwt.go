package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTConfig holds JWT configuration
type JWTConfig struct {
	AccessTokenSecret  string
	RefreshTokenSecret string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	Issuer             string
}

// NewJWTConfig creates a new JWT configuration
func NewJWTConfig() *JWTConfig {
	// Get JWT configuration from environment variables
	accessTokenSecret := getEnv("JWT_ACCESS_TOKEN_SECRET", generateRandomSecret(32))
	refreshTokenSecret := getEnv("JWT_REFRESH_TOKEN_SECRET", generateRandomSecret(32))

	// Parse token expiry durations
	accessTokenExpiryStr := getEnv("JWT_ACCESS_TOKEN_EXPIRY", "15m")
	refreshTokenExpiryStr := getEnv("JWT_REFRESH_TOKEN_EXPIRY", "7d")

	accessTokenExpiry, err := parseDuration(accessTokenExpiryStr)
	if err != nil {
		accessTokenExpiry = 15 * time.Minute
	}

	refreshTokenExpiry, err := parseDuration(refreshTokenExpiryStr)
	if err != nil {
		refreshTokenExpiry = 7 * 24 * time.Hour
	}

	issuer := getEnv("JWT_ISSUER", "user-management-api")

	return &JWTConfig{
		AccessTokenSecret:  accessTokenSecret,
		RefreshTokenSecret: refreshTokenSecret,
		AccessTokenExpiry:  accessTokenExpiry,
		RefreshTokenExpiry: refreshTokenExpiry,
		Issuer:             issuer,
	}
}

// GenerateAccessToken generates a new JWT access token
func (c *JWTConfig) GenerateAccessToken(userID uuid.UUID, email string, sessionID uuid.UUID) (string, uuid.UUID, error) {
	// Generate a unique JWT ID
	tokenJTI := uuid.New()

	// Set token claims
	claims := jwt.MapClaims{
		"sub":   userID.String(),
		"email": email,
		"sid":   sessionID.String(),
		"jti":   tokenJTI.String(),
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(c.AccessTokenExpiry).Unix(),
		"iss":   c.Issuer,
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token with secret key
	tokenString, err := token.SignedString([]byte(c.AccessTokenSecret))
	if err != nil {
		return "", uuid.Nil, err
	}

	return tokenString, tokenJTI, nil
}

// GenerateRefreshToken generates a new JWT refresh token
func (c *JWTConfig) GenerateRefreshToken(userID uuid.UUID, sessionID uuid.UUID) (string, uuid.UUID, error) {
	// Generate a unique JWT ID
	tokenJTI := uuid.New()

	// Set token claims
	claims := jwt.MapClaims{
		"sub": userID.String(),
		"sid": sessionID.String(),
		"jti": tokenJTI.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(c.RefreshTokenExpiry).Unix(),
		"iss": c.Issuer,
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token with secret key
	tokenString, err := token.SignedString([]byte(c.RefreshTokenSecret))
	if err != nil {
		return "", uuid.Nil, err
	}

	return tokenString, tokenJTI, nil
}

// ValidateAccessToken validates a JWT access token
func (c *JWTConfig) ValidateAccessToken(tokenString string) (*jwt.Token, error) {
	// Parse and validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(c.AccessTokenSecret), nil
	})

	return token, err
}

// ValidateRefreshToken validates a JWT refresh token
func (c *JWTConfig) ValidateRefreshToken(tokenString string) (*jwt.Token, error) {
	// Parse and validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(c.RefreshTokenSecret), nil
	})

	return token, err
}

// GetClaimsFromToken extracts claims from a JWT token
func GetClaimsFromToken(token *jwt.Token) (jwt.MapClaims, error) {
	// Get claims from token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// generateRandomSecret generates a random secret key
func generateRandomSecret(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

// parseDuration parses a duration string
func parseDuration(durationStr string) (time.Duration, error) {
	// Try to parse as a standard duration
	duration, err := time.ParseDuration(durationStr)
	if err == nil {
		return duration, nil
	}

	// Try to parse as days
	if len(durationStr) > 1 && durationStr[len(durationStr)-1] == 'd' {
		days, err := strconv.Atoi(durationStr[:len(durationStr)-1])
		if err == nil {
			return time.Duration(days) * 24 * time.Hour, nil
		}
	}

	return 0, fmt.Errorf("invalid duration format: %s", durationStr)
}