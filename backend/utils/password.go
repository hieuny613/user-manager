package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// PasswordConfig holds the configuration for Argon2id password hashing
type PasswordConfig struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultPasswordConfig returns the default configuration for Argon2id password hashing
func DefaultPasswordConfig() *PasswordConfig {
	return &PasswordConfig{
		Memory:      64 * 1024, // 64MB
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// HashPassword hashes a password using Argon2id
func HashPassword(password string, config *PasswordConfig) (string, error) {
	// Generate a random salt
	salt := make([]byte, config.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Hash the password using Argon2id
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		config.Iterations,
		config.Memory,
		config.Parallelism,
		config.KeyLength,
	)

	// Encode the hash and parameters as a string
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=memory,t=iterations,p=parallelism$salt$hash
	encodedHash := fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		config.Memory,
		config.Iterations,
		config.Parallelism,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

// VerifyPassword verifies a password against a hash
func VerifyPassword(password, encodedHash string) (bool, error) {
	// Parse the encoded hash
	params, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Hash the password with the same parameters
	compareHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	// Compare the hashes in constant time
	return subtle.ConstantTimeCompare(hash, compareHash) == 1, nil
}

// decodeHash decodes an Argon2id hash string
func decodeHash(encodedHash string) (*PasswordConfig, []byte, []byte, error) {
	// Split the hash string
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, errors.New("invalid hash format")
	}

	// Check the algorithm
	if parts[1] != "argon2id" {
		return nil, nil, nil, errors.New("unsupported algorithm")
	}

	// Parse the parameters
	var version int
	var memory uint32
	var iterations uint32
	var parallelism uint8

	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, errors.New("invalid hash format")
	}

	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return nil, nil, nil, errors.New("invalid hash format")
	}

	// Decode the salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, errors.New("invalid salt encoding")
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, errors.New("invalid hash encoding")
	}

	config := &PasswordConfig{
		Memory:      memory,
		Iterations:  iterations,
		Parallelism: parallelism,
		SaltLength:  uint32(len(salt)),
		KeyLength:   uint32(len(hash)),
	}

	return config, salt, hash, nil
}

// ValidatePasswordStrength validates password strength
func ValidatePasswordStrength(password string, minLength int) (bool, string) {
	// Check password length
	if len(password) < minLength {
		return false, fmt.Sprintf("Password must be at least %d characters long", minLength)
	}

	// Check for uppercase letters
	hasUpper := false
	for _, char := range password {
		if 'A' <= char && char <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return false, "Password must contain at least one uppercase letter"
	}

	// Check for lowercase letters
	hasLower := false
	for _, char := range password {
		if 'a' <= char && char <= 'z' {
			hasLower = true
			break
		}
	}
	if !hasLower {
		return false, "Password must contain at least one lowercase letter"
	}

	// Check for digits
	hasDigit := false
	for _, char := range password {
		if '0' <= char && char <= '9' {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		return false, "Password must contain at least one digit"
	}

	// Check for special characters
	specialChars := "!@#$%^&*()-_=+[]{}|;:,.<>?/~"
	hasSpecial := false
	for _, char := range password {
		if strings.ContainsRune(specialChars, char) {
			hasSpecial = true
			break
		}
	}
	if !hasSpecial {
		return false, "Password must contain at least one special character"
	}

	return true, ""
}