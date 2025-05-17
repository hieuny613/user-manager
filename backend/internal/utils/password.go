package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"

	"backend/config"
	"backend/internal/model"
)

// Các lỗi liên quan đến password
var (
	ErrInvalidHash              = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion      = errors.New("incompatible version of argon2")
	ErrPasswordTooShort         = errors.New("password is too short")
	ErrPasswordTooLong          = errors.New("password is too long")
	ErrPasswordNoLower          = errors.New("password must contain at least one lowercase letter")
	ErrPasswordNoUpper          = errors.New("password must contain at least one uppercase letter")
	ErrPasswordNoNumber         = errors.New("password must contain at least one number")
	ErrPasswordNoSpecial        = errors.New("password must contain at least one special character")
	ErrPasswordCommon           = errors.New("password is too common or easily guessable")
	ErrPasswordContainsPersonal = errors.New("password contains personal information")
	ErrPasswordReused           = errors.New("password has been used recently")
	ErrPasswordExpired          = errors.New("password has expired and must be changed")
)

// Argon2Params chứa thông số cho thuật toán hash Argon2id
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// PasswordPolicy chứa chính sách mật khẩu
type PasswordPolicy struct {
	MinLength        int
	MaxLength        int
	RequireLowercase bool
	RequireUppercase bool
	RequireNumbers   bool
	RequireSpecial   bool
	DisallowCommon   bool
	DisallowPersonal bool
	HistorySize      int
	ExpiryDays       int
}

// DefaultArgon2Params trả về thông số mặc định cho Argon2id
func DefaultArgon2Params() *Argon2Params {
	return &Argon2Params{
		Memory:      64 * 1024, // 64MB
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// LoadPasswordPolicy tải chính sách mật khẩu từ cấu hình
func LoadPasswordPolicy(cfg *config.Config) *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:        cfg.Security.PasswordMinLength,
		MaxLength:        128, // Giới hạn hợp lý
		RequireLowercase: true,
		RequireUppercase: true,
		RequireNumbers:   true,
		RequireSpecial:   true,
		DisallowCommon:   true,
		DisallowPersonal: true,
		HistorySize:      cfg.Security.PasswordHistorySize,
		ExpiryDays:       cfg.Security.PasswordExpiryDays,
	}
}

// GenerateRandomBytes tạo một chuỗi ngẫu nhiên với độ dài xác định
func GenerateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// HashPassword tạo một hash Argon2id từ password với thông số được cung cấp
func HashPassword(password string, params *Argon2Params) (string, error) {
	if params == nil {
		params = DefaultArgon2Params()
	}

	// Tạo salt ngẫu nhiên
	salt, err := GenerateRandomBytes(params.SaltLength)
	if err != nil {
		return "", err
	}

	// Tạo hash từ password và salt
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	// Mã hóa hash thành chuỗi dạng base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Tạo chuỗi hash hoàn chỉnh
	encodedHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

// VerifyPassword kiểm tra xem một password có khớp với hash đã cho hay không
func VerifyPassword(password, encodedHash string) (bool, error) {
	// Parse thông số từ chuỗi hash
	params, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Tạo lại hash từ password cần kiểm tra
	verifyHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	// So sánh hash mới với hash đã cho
	if subtle.ConstantTimeCompare(hash, verifyHash) == 1 {
		return true, nil
	}
	return false, nil
}

// decodeHash giải mã chuỗi hash để lấy thông số, salt và hash
func decodeHash(encodedHash string) (*Argon2Params, []byte, []byte, error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err := fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	params := &Argon2Params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	params.SaltLength = uint32(len(salt))

	hash, err := base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	params.KeyLength = uint32(len(hash))

	return params, salt, hash, nil
}

// CheckPasswordPolicy kiểm tra xem một password có đáp ứng các yêu cầu chính sách hay không

func CheckPasswordPolicy(password string, policy *PasswordPolicy, userData map[string]string) error {
	// Kiểm tra độ dài
	if len(password) < policy.MinLength {
		return ErrPasswordTooShort
	}
	if policy.MaxLength > 0 && len(password) > policy.MaxLength {
		return ErrPasswordTooLong
	}

	// Kiểm tra thông tin cá nhân trước (ưu tiên cao hơn)
	if policy.DisallowPersonal && containsPersonalInfo(password, userData) {
		return ErrPasswordContainsPersonal
	}

	// Kiểm tra yêu cầu về ký tự
	if policy.RequireLowercase && !strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz") {
		return ErrPasswordNoLower
	}
	if policy.RequireUppercase && !strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return ErrPasswordNoUpper
	}
	if policy.RequireNumbers && !strings.ContainsAny(password, "0123456789") {
		return ErrPasswordNoNumber
	}
	if policy.RequireSpecial && !strings.ContainsAny(password, "!@#$%^&*()_+-=[]{}|;:,.<>?/") {
		return ErrPasswordNoSpecial
	}

	// Kiểm tra mật khẩu phổ biến (chuyển xuống sau các kiểm tra ký tự)
	if policy.DisallowCommon && isCommonPassword(password) {
		return ErrPasswordCommon
	}

	return nil
}

// isCommonPassword kiểm tra xem một password có trong danh sách mật khẩu phổ biến hay không
func isCommonPassword(password string) bool {
	// Danh sách mật khẩu phổ biến
	commonPasswords := []string{
		"password", "123456", "qwerty", "admin", "welcome",
		"football", "monkey", "abc123", "123456789", "12345678",
		"password123", "admin123", "qwerty123", "welcome123", // Thêm các biến thể phổ biến
	}

	lowerPassword := strings.ToLower(password)

	for _, p := range commonPasswords {
		if lowerPassword == p {
			return true
		}
	}

	// Kiểm tra các mẫu phổ biến
	commonPatterns := []string{
		"password", "123456", "qwerty", "admin", "welcome",
	}

	for _, pattern := range commonPatterns {
		if strings.Contains(lowerPassword, pattern) {
			return true
		}
	}

	return false
}

// containsPersonalInfo kiểm tra xem password có chứa thông tin cá nhân của người dùng hay không
func containsPersonalInfo(password string, userData map[string]string) bool {
	lowerPassword := strings.ToLower(password)

	for _, value := range userData {
		if value == "" {
			continue
		}

		lowerValue := strings.ToLower(value)
		if len(lowerValue) >= 4 && strings.Contains(lowerPassword, lowerValue) {
			return true
		}
	}

	return false
}

// CheckPasswordHistory kiểm tra xem một password có trong lịch sử sử dụng gần đây hay không
func CheckPasswordHistory(password string, history []model.PasswordHistory) (bool, error) {
	for _, item := range history {
		matches, err := VerifyPassword(password, item.PasswordHash)
		if err != nil {
			return false, err
		}
		if matches {
			return true, nil
		}
	}

	return false, nil
}

// CreatePasswordHistory tạo một bản ghi lịch sử password mới
func CreatePasswordHistory(userID uuid.UUID, passwordHash string) model.PasswordHistory {
	return model.PasswordHistory{
		UserID:       userID,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
		IsExpired:    false,
	}
}

// CheckPasswordExpiry kiểm tra xem mật khẩu của người dùng đã hết hạn chưa
func CheckPasswordExpiry(user model.User, expiryDays int) bool {
	if user.PasswordChangedAt == nil {
		return true // Chưa đặt mật khẩu hoặc chưa ghi nhận thời gian thay đổi
	}

	expiryDate := user.PasswordChangedAt.AddDate(0, 0, expiryDays)
	return time.Now().After(expiryDate)
}
