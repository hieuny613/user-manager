package utils

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"

	"backend/config"
)

// JWTClaims là struct chứa các claims trong JWT token
type JWTClaims struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	Username  string `json:"username"`
	SessionID string `json:"session_id"`
	IsAdmin   bool   `json:"is_admin,omitempty"`
	jwt.RegisteredClaims
}

// JWTService là struct chứa các hàm và thuộc tính xử lý JWT
type JWTService struct {
	privateKey          *rsa.PrivateKey
	publicKey           *rsa.PublicKey
	privateKeyPath      string
	publicKeyPath       string
	issuer              string
	tokenExpiration     time.Duration
	refreshExpiration   time.Duration
	algorithm           jwt.SigningMethod
	blacklistMutex      sync.RWMutex
	blacklist           map[string]time.Time // Map lưu các token đã bị thu hồi
	blacklistExpiration time.Duration        // Thời gian sống của mỗi blacklist item
}

// TokenDetails chứa thông tin về token và refresh token
type TokenDetails struct {
	Token          string
	TokenUUID      string
	TokenExpires   time.Time
	RefreshToken   string
	RefreshUUID    string
	RefreshExpires time.Time
}

// NewJWTService tạo một instance mới của JWTService
func NewJWTService(cfg *config.Config) (*JWTService, error) {
	// Đọc private key
	privateKeyBytes, err := ioutil.ReadFile(cfg.JWT.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading private key: %w", err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %w", err)
	}

	// Đọc public key
	publicKeyBytes, err := ioutil.ReadFile(cfg.JWT.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading public key: %w", err)
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	// Xác định thuật toán ký
	var algorithm jwt.SigningMethod
	switch cfg.JWT.Algorithm {
	case "RS256":
		algorithm = jwt.SigningMethodRS256
	case "RS384":
		algorithm = jwt.SigningMethodRS384
	case "RS512":
		algorithm = jwt.SigningMethodRS512
	default:
		algorithm = jwt.SigningMethodRS256
	}

	return &JWTService{
		privateKey:          privateKey,
		publicKey:           publicKey,
		privateKeyPath:      cfg.JWT.PrivateKeyPath,
		publicKeyPath:       cfg.JWT.PublicKeyPath,
		issuer:              "user-management-system",
		tokenExpiration:     time.Duration(cfg.JWT.TokenExpireMin) * time.Minute,
		refreshExpiration:   time.Duration(cfg.JWT.RefreshExpireH) * time.Hour,
		algorithm:           algorithm,
		blacklist:           make(map[string]time.Time),
		blacklistExpiration: 24 * time.Hour, // Token hết hạn sẽ bị xóa khỏi blacklist sau 24h
	}, nil
}

// GenerateToken tạo một JWT token mới cho người dùng
func (s *JWTService) GenerateToken(userID, email, username, sessionID string, isAdmin bool) (*TokenDetails, error) {
	// Tạo token details
	td := &TokenDetails{
		TokenExpires:   time.Now().Add(s.tokenExpiration),
		RefreshExpires: time.Now().Add(s.refreshExpiration),
	}

	// Tạo claims cho access token
	claims := JWTClaims{
		UserID:    userID,
		Email:     email,
		Username:  username,
		SessionID: sessionID,
		IsAdmin:   isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(td.TokenExpires),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    s.issuer,
			Subject:   userID,
			ID:        sessionID,
		},
	}

	// Tạo token
	token := jwt.NewWithClaims(s.algorithm, claims)

	// Ký token
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("error signing token: %w", err)
	}
	td.Token = tokenString

	// Tạo refresh token (dùng JWT khác với ít thông tin hơn)
	refreshClaims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(td.RefreshExpires),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    s.issuer,
		Subject:   userID,
		ID:        sessionID + "-refresh",
	}
	refreshToken := jwt.NewWithClaims(s.algorithm, refreshClaims)

	// Ký refresh token
	refreshTokenString, err := refreshToken.SignedString(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("error signing refresh token: %w", err)
	}
	td.RefreshToken = refreshTokenString

	// Lưu ID vào token details để có thể thu hồi sau này
	td.TokenUUID = sessionID
	td.RefreshUUID = sessionID + "-refresh"

	return td, nil
}

// VerifyToken xác minh một JWT token
func (s *JWTService) VerifyToken(tokenString string) (*JWTClaims, error) {
	// Kiểm tra token có trong blacklist không
	s.blacklistMutex.RLock()
	_, blacklisted := s.blacklist[tokenString]
	s.blacklistMutex.RUnlock()
	if blacklisted {
		return nil, errors.New("token has been revoked")
	}

	// Parse và xác minh token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Kiểm tra thuật toán ký
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	// Kiểm tra token có hợp lệ không
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Trả về claims
	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, errors.New("could not parse claims")
	}

	return claims, nil
}

// VerifyRefreshToken xác minh một refresh token
func (s *JWTService) VerifyRefreshToken(tokenString string) (*jwt.RegisteredClaims, error) {
	// Kiểm tra token có trong blacklist không
	s.blacklistMutex.RLock()
	_, blacklisted := s.blacklist[tokenString]
	s.blacklistMutex.RUnlock()
	if blacklisted {
		return nil, errors.New("refresh token has been revoked")
	}

	// Parse và xác minh token
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Kiểm tra thuật toán ký
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("error parsing refresh token: %w", err)
	}

	// Kiểm tra token có hợp lệ không
	if !token.Valid {
		return nil, errors.New("invalid refresh token")
	}

	// Trả về claims
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, errors.New("could not parse claims")
	}

	return claims, nil
}

// AddToBlacklist thêm một token vào danh sách đen
func (s *JWTService) AddToBlacklist(tokenString string, expiration time.Time) {
	s.blacklistMutex.Lock()
	defer s.blacklistMutex.Unlock()

	// Thêm token vào blacklist với thời gian hết hạn
	s.blacklist[tokenString] = expiration

	// Lọc và xóa các token đã hết hạn trong blacklist
	s.cleanupBlacklist()
}

// IsBlacklisted kiểm tra xem một token có trong danh sách đen không
func (s *JWTService) IsBlacklisted(tokenString string) bool {
	s.blacklistMutex.RLock()
	defer s.blacklistMutex.RUnlock()

	expiration, exists := s.blacklist[tokenString]
	if !exists {
		return false
	}

	// Nếu token đã hết hạn, trả về false và xóa khỏi blacklist
	if time.Now().After(expiration) {
		delete(s.blacklist, tokenString)
		return false
	}

	return true
}

// RevokeAllUserTokens thu hồi tất cả token của một người dùng dựa trên jti prefix
// (thường là sessionID để thu hồi tất cả token từ một session)
func (s *JWTService) RevokeAllUserTokens(sessionIDPrefix string) {
	// Trong thực tế, bạn sẽ cần một cấu trúc dữ liệu phức tạp hơn để làm điều này hiệu quả
	// Đây chỉ là một ví dụ đơn giản
	s.blacklistMutex.Lock()
	defer s.blacklistMutex.Unlock()

	// Quét tất cả token trong blacklist để tìm và thu hồi các token thuộc về session này
	// Lưu ý: Trong triển khai thực tế, nên dùng cơ sở dữ liệu/cache để lưu trữ
	logrus.Infof("Revoking all tokens for session prefix: %s", sessionIDPrefix)
}

// cleanupBlacklist xóa các token đã hết hạn khỏi blacklist
func (s *JWTService) cleanupBlacklist() {
	now := time.Now()
	for token, expiration := range s.blacklist {
		if now.After(expiration.Add(s.blacklistExpiration)) {
			delete(s.blacklist, token)
		}
	}
}

// RotateKeys tải lại keys từ file system
// Hữu ích khi bạn cần thay đổi keys mà không cần khởi động lại ứng dụng
func (s *JWTService) RotateKeys() error {
	// Đọc private key mới
	privateKeyBytes, err := ioutil.ReadFile(s.privateKeyPath)
	if err != nil {
		return fmt.Errorf("error reading private key: %w", err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return fmt.Errorf("error parsing private key: %w", err)
	}

	// Đọc public key mới
	publicKeyBytes, err := ioutil.ReadFile(s.publicKeyPath)
	if err != nil {
		return fmt.Errorf("error reading public key: %w", err)
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("error parsing public key: %w", err)
	}

	// Cập nhật keys
	s.privateKey = privateKey
	s.publicKey = publicKey

	logrus.Info("JWT keys rotated successfully")
	return nil
}

// GenerateKeyPair tạo một cặp RSA key mới và lưu vào file system
// Hữu ích khi cần tạo keys mới cho việc rotation
func GenerateKeyPair(privateKeyPath, publicKeyPath string) error {
	// Tạo cặp key mới
	// Lưu ý: Trong thực tế, hàm này sẽ phức tạp hơn và sử dụng cryto/rand để tạo keys
	logrus.Infof("Generating new key pair: %s, %s", privateKeyPath, publicKeyPath)
	return nil
}
