package utils

import (
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
)

// Validator is a utility for validating input
type Validator struct {}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateEmail validates an email address
func (v *Validator) ValidateEmail(email string) error {
	// Check if email is empty
	if email == "" {
		return errors.New("email is required")
	}

	// Check if email is valid
	_, err := mail.ParseAddress(email)
	if err != nil {
		return errors.New("invalid email format")
	}

	// Check if email is too long
	if len(email) > 255 {
		return errors.New("email is too long")
	}

	return nil
}

// ValidatePassword validates a password
func (v *Validator) ValidatePassword(password string) error {
	// Check if password is empty
	if password == "" {
		return errors.New("password is required")
	}

	// Check if password is too short
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	// Check if password is too long
	if len(password) > 72 {
		return errors.New("password is too long")
	}

	// Check if password contains at least one uppercase letter
	hasUpper := false
	for _, c := range password {
		if unicode.IsUpper(c) {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}

	// Check if password contains at least one lowercase letter
	hasLower := false
	for _, c := range password {
		if unicode.IsLower(c) {
			hasLower = true
			break
		}
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}

	// Check if password contains at least one digit
	hasDigit := false
	for _, c := range password {
		if unicode.IsDigit(c) {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		return errors.New("password must contain at least one digit")
	}

	// Check if password contains at least one special character
	hasSpecial := false
	specialChars := "!@#$%^&*()-_=+[]{}|;:,.<>?/\""
	for _, c := range password {
		if strings.ContainsRune(specialChars, c) {
			hasSpecial = true
			break
		}
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

// ValidateUsername validates a username
func (v *Validator) ValidateUsername(username string) error {
	// Check if username is empty
	if username == "" {
		return errors.New("username is required")
	}

	// Check if username is too short
	if len(username) < 3 {
		return errors.New("username must be at least 3 characters long")
	}

	// Check if username is too long
	if len(username) > 30 {
		return errors.New("username is too long")
	}

	// Check if username contains only allowed characters
	validUsername := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validUsername.MatchString(username) {
		return errors.New("username can only contain letters, numbers, underscores, and hyphens")
	}

	return nil
}

// ValidateName validates a name
func (v *Validator) ValidateName(name string) error {
	// Check if name is empty
	if name == "" {
		return errors.New("name is required")
	}

	// Check if name is too long
	if len(name) > 50 {
		return errors.New("name is too long")
	}

	// Check if name contains only allowed characters
	validName := regexp.MustCompile(`^[a-zA-Z0-9\s'-]+$`)
	if !validName.MatchString(name) {
		return errors.New("name can only contain letters, numbers, spaces, apostrophes, and hyphens")
	}

	return nil
}

// ValidateUUID validates a UUID
func (v *Validator) ValidateUUID(uuid string) error {
	// Check if UUID is empty
	if uuid == "" {
		return errors.New("UUID is required")
	}

	// Check if UUID is valid
	validUUID := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !validUUID.MatchString(strings.ToLower(uuid)) {
		return errors.New("invalid UUID format")
	}

	return nil
}

// ValidateToken validates a token
func (v *Validator) ValidateToken(token string) error {
	// Check if token is empty
	if token == "" {
		return errors.New("token is required")
	}

	// Check if token is too short
	if len(token) < 10 {
		return errors.New("invalid token")
	}

	return nil
}

)
	if !validURL.MatchString(url) {
		return errors.New("invalid URL format")
	}

	return nil
}

	return nil
}

// ValidateIP validates an IP address
func (v *Validator) ValidateIP(ip string) error {
	// Check if IP is empty
	if ip == "" {
		return errors.New("IP address is required")
	}

	// Check if IP is valid
	validIPv4 := regexp.MustCompile(`^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	validIPv6 := regexp.MustCompile(`^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$`)
	if !validIPv4.MatchString(ip) && !validIPv6.MatchString(ip) {
		return errors.New("invalid IP address format")
	}

	return nil
}

// ValidateRequired validates that a string is not empty
func (v *Validator) ValidateRequired(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	return nil
}

// ValidateMaxLength validates that a string is not longer than the maximum length
func (v *Validator) ValidateMaxLength(field, value string, maxLength int) error {
	if len(value) > maxLength {
		return fmt.Errorf("%s cannot be longer than %d characters", field, maxLength)
	}
	return nil
}

// ValidateMinLength validates that a string is not shorter than the minimum length
func (v *Validator) ValidateMinLength(field, value string, minLength int) error {
	if len(value) < minLength {
		return fmt.Errorf("%s must be at least %d characters long", field, minLength)
	}
	return nil
}

// ValidateRange validates that a number is within a range
func (v *Validator) ValidateRange(field string, value, min, max int) error {
	if value < min || value > max {
		return fmt.Errorf("%s must be between %d and %d", field, min, max)
	}
	return nil
}

// SanitizeHTML sanitizes HTML content
func (v *Validator) SanitizeHTML(input string) string {
	// Replace HTML tags with their escaped versions
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")
	return input
}

// SanitizeSQL sanitizes SQL content
func (v *Validator) SanitizeSQL(input string) string {
	// Replace SQL injection characters
	input = strings.ReplaceAll(input, "'", "''")
	input = strings.ReplaceAll(input, "\"", "\"\"")
	input = strings.ReplaceAll(input, ";", "")
	input = strings.ReplaceAll(input, "--", "")
	input = strings.ReplaceAll(input, "/*", "")
	input = strings.ReplaceAll(input, "*/", "")
	return input
}