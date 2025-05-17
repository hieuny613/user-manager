package utils

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"backend/config"
	"backend/internal/model"
)

func TestHashPassword(t *testing.T) {
	password := "SecurePassword123!"

	// Hash mật khẩu với thông số mặc định
	hash, err := HashPassword(password, nil)
	assert.NoError(t, err, "HashPassword should not return an error")
	assert.NotEmpty(t, hash, "Hash should not be empty")
	assert.Contains(t, hash, "$argon2id$", "Hash should be in argon2id format")

	// Kiểm tra với thông số tùy chỉnh
	params := &Argon2Params{
		Memory:      32 * 1024,
		Iterations:  2,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}

	customHash, err := HashPassword(password, params)
	assert.NoError(t, err, "HashPassword should not return an error with custom params")
	assert.NotEmpty(t, customHash, "Custom hash should not be empty")
	assert.Contains(t, customHash, "m=32768", "Custom hash should contain custom memory parameter")
}

func TestVerifyPassword(t *testing.T) {
	password := "SecurePassword123!"
	wrongPassword := "WrongPassword123!"

	// Hash một mật khẩu
	hash, err := HashPassword(password, nil)
	assert.NoError(t, err, "HashPassword should not return an error")

	// Xác minh với mật khẩu đúng
	valid, err := VerifyPassword(password, hash)
	assert.NoError(t, err, "VerifyPassword should not return an error")
	assert.True(t, valid, "Password verification should succeed with correct password")

	// Xác minh với mật khẩu sai
	valid, err = VerifyPassword(wrongPassword, hash)
	assert.NoError(t, err, "VerifyPassword should not return an error with wrong password")
	assert.False(t, valid, "Password verification should fail with wrong password")

	// Xác minh với hash không hợp lệ
	valid, err = VerifyPassword(password, "invalid$hash$format")
	assert.Error(t, err, "VerifyPassword should return an error with invalid hash")
	assert.False(t, valid, "Password verification should fail with invalid hash")
}

func TestCheckPasswordPolicy(t *testing.T) {
	// Tạo policy test
	policy := &PasswordPolicy{
		MinLength:        8,
		MaxLength:        64,
		RequireLowercase: true,
		RequireUppercase: true,
		RequireNumbers:   true,
		RequireSpecial:   true,
		DisallowCommon:   true,
		DisallowPersonal: true,
	}

	// Dữ liệu người dùng test
	userData := map[string]string{
		"username":  "testuser",
		"email":     "test@example.com",
		"firstName": "John",
		"lastName":  "Doe",
	}

	tests := []struct {
		name     string
		password string
		wantErr  error
	}{
		{"ValidPassword", "SecureP@ssw0rd", nil},
		{"TooShort", "Short1!", ErrPasswordTooShort},
		{"NoLowercase", "PASSWORD123!", ErrPasswordNoLower},
		{"NoUppercase", "password123!", ErrPasswordNoUpper},
		{"NoNumbers", "PasswordTest!", ErrPasswordNoNumber},
		{"NoSpecial", "Password123", ErrPasswordNoSpecial},
		{"CommonPassword", "Password123!", ErrPasswordCommon},
		{"ContainsUsername", "testuser123!", ErrPasswordContainsPersonal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckPasswordPolicy(tt.password, policy, userData)
			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckPasswordHistory(t *testing.T) {
	// Tạo một số hash mật khẩu để kiểm tra
	oldPassword1 := "OldPassword1!"
	oldPassword2 := "OldPassword2!"
	newPassword := "NewPassword3!"

	oldHash1, _ := HashPassword(oldPassword1, nil)
	oldHash2, _ := HashPassword(oldPassword2, nil)

	// Tạo lịch sử mật khẩu giả với UUID
	userID := uuid.New()
	history := []model.PasswordHistory{
		{
			ID:           uuid.New(),
			UserID:       userID,
			PasswordHash: oldHash1,
			CreatedAt:    time.Now().Add(-48 * time.Hour),
			IsExpired:    false,
		},
		{
			ID:           uuid.New(),
			UserID:       userID,
			PasswordHash: oldHash2,
			CreatedAt:    time.Now().Add(-24 * time.Hour),
			IsExpired:    false,
		},
	}

	// Kiểm tra mật khẩu cũ (nên trả về true - tìm thấy trong lịch sử)
	found, err := CheckPasswordHistory(oldPassword1, history)
	assert.NoError(t, err, "CheckPasswordHistory should not return an error")
	assert.True(t, found, "Old password should be found in history")

	// Kiểm tra mật khẩu mới (nên trả về false - không tìm thấy trong lịch sử)
	found, err = CheckPasswordHistory(newPassword, history)
	assert.NoError(t, err, "CheckPasswordHistory should not return an error")
	assert.False(t, found, "New password should not be found in history")
}

func TestCheckPasswordExpiry(t *testing.T) {
	// Tạo user test với UUID
	now := time.Now()

	// Trường hợp 1: Mật khẩu chưa bao giờ thay đổi
	userNeverChanged := model.User{
		ID:                uuid.New(),
		PasswordChangedAt: nil,
	}

	// Trường hợp 2: Mật khẩu thay đổi gần đây (chưa hết hạn)
	recentChange := now.Add(-10 * 24 * time.Hour) // 10 ngày trước
	userRecentChange := model.User{
		ID:                uuid.New(),
		PasswordChangedAt: &recentChange,
	}

	// Trường hợp 3: Mật khẩu thay đổi lâu rồi (đã hết hạn)
	oldChange := now.Add(-100 * 24 * time.Hour) // 100 ngày trước
	userOldChange := model.User{
		ID:                uuid.New(),
		PasswordChangedAt: &oldChange,
	}

	// Kiểm tra với expiryDays = 90
	expiryDays := 90

	// Mật khẩu chưa bao giờ thay đổi nên coi như đã hết hạn
	isExpired := CheckPasswordExpiry(userNeverChanged, expiryDays)
	assert.True(t, isExpired, "Password that was never changed should be considered expired")

	// Mật khẩu thay đổi gần đây (10 ngày) nên chưa hết hạn (90 ngày)
	isExpired = CheckPasswordExpiry(userRecentChange, expiryDays)
	assert.False(t, isExpired, "Recently changed password should not be expired")

	// Mật khẩu thay đổi lâu rồi (100 ngày) nên đã hết hạn (90 ngày)
	isExpired = CheckPasswordExpiry(userOldChange, expiryDays)
	assert.True(t, isExpired, "Old password should be expired")
}

func TestGenerateRandomBytes(t *testing.T) {
	// Test với các độ dài khác nhau
	lengths := []uint32{8, 16, 32, 64}

	for _, length := range lengths {
		bytes, err := GenerateRandomBytes(length)
		assert.NoError(t, err, "GenerateRandomBytes should not return an error")
		assert.Equal(t, int(length), len(bytes), "Generated bytes should have the requested length")
	}

	// Test hai lần gọi không trả về cùng một giá trị
	bytes1, _ := GenerateRandomBytes(16)
	bytes2, _ := GenerateRandomBytes(16)
	assert.NotEqual(t, bytes1, bytes2, "Two calls should generate different random bytes")
}

func TestCreatePasswordHistory(t *testing.T) {
	userID := uuid.New()
	passwordHash := "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$somehash"

	history := CreatePasswordHistory(userID, passwordHash)

	assert.Equal(t, userID, history.UserID, "UserID should match")
	assert.Equal(t, passwordHash, history.PasswordHash, "PasswordHash should match")
	assert.False(t, history.IsExpired, "New password history should not be expired")
	assert.WithinDuration(t, time.Now(), history.CreatedAt, 2*time.Second, "CreatedAt should be close to now")
}

func TestLoadPasswordPolicy(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			PasswordMinLength:   10,
			PasswordHistorySize: 5,
			PasswordExpiryDays:  60,
		},
	}

	policy := LoadPasswordPolicy(cfg)
	assert.Equal(t, 10, policy.MinLength, "MinLength should match config")
	assert.Equal(t, 5, policy.HistorySize, "HistorySize should match config")
	assert.Equal(t, 60, policy.ExpiryDays, "ExpiryDays should match config")
	assert.True(t, policy.RequireLowercase, "RequireLowercase should be true")
	assert.True(t, policy.RequireUppercase, "RequireUppercase should be true")
	assert.True(t, policy.RequireNumbers, "RequireNumbers should be true")
	assert.True(t, policy.RequireSpecial, "RequireSpecial should be true")
}

func TestDecodeHash(t *testing.T) {
	password := "TestPassword123!"
	hash, err := HashPassword(password, nil)
	assert.NoError(t, err, "HashPassword should not return an error")

	params, salt, hashBytes, err := decodeHash(hash)
	assert.NoError(t, err, "decodeHash should not return an error")
	assert.NotNil(t, params, "Params should not be nil")
	assert.NotNil(t, salt, "Salt should not be nil")
	assert.NotNil(t, hashBytes, "Hash bytes should not be nil")

	// Test với hash không hợp lệ
	_, _, _, err = decodeHash("invalid$hash")
	assert.Error(t, err, "decodeHash should return an error for invalid hash")
}
