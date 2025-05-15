package utils

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateToken generates a JWT token
func GenerateToken(claims jwt.MapClaims, secret string, expiresIn time.Duration) (string, error) {
	// Set expiry time
	claims["exp"] = time.Now().Add(expiresIn).Unix()

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateToken validates a JWT token
func ValidateToken(tokenString string, secret string) (jwt.MapClaims, error) {
	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}

		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	// Validate token
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Get claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	return claims, nil
}

// ExtractUserIDFromToken extracts the user ID from a JWT token
func ExtractUserIDFromToken(tokenString string, secret string) (string, error) {
	// Validate token
	claims, err := ValidateToken(tokenString, secret)
	if err != nil {
		return "", err
	}

	// Get user ID
	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", errors.New("invalid user ID")
	}

	return userID, nil
}

// ExtractSessionIDFromToken extracts the session ID from a JWT token
func ExtractSessionIDFromToken(tokenString string, secret string) (string, error) {
	// Validate token
	claims, err := ValidateToken(tokenString, secret)
	if err != nil {
		return "", err
	}

	// Get session ID
	sessionID, ok := claims["session_id"].(string)
	if !ok {
		return "", errors.New("invalid session ID")
	}

	return sessionID, nil
}

// IsTokenExpired checks if a JWT token is expired
func IsTokenExpired(tokenString string, secret string) bool {
	// Parse token without validating signature
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	// Check if token is valid
	if token == nil {
		return true
	}

	// Get claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return true
	}

	// Get expiry time
	exp, ok := claims["exp"].(float64)
	if !ok {
		return true
	}

	// Check if token is expired
	return float64(time.Now().Unix()) > exp
}

// UseCookiesForTokens returns whether to use cookies for tokens
func UseCookiesForTokens() bool {
	// TODO: Get from config
	return true
}
