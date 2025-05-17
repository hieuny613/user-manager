package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"backend/internal/utils"
)

// MockJWTService là một mock cho JWTService
type MockJWTService struct {
	mock.Mock
}

func (m *MockJWTService) VerifyToken(tokenString string) (*utils.JWTClaims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*utils.JWTClaims), args.Error(1)
}

func (m *MockJWTService) IsBlacklisted(tokenString string) bool {
	args := m.Called(tokenString)
	return args.Bool(0)
}

func TestAuthMiddleware(t *testing.T) {
	// Chuẩn bị
	gin.SetMode(gin.TestMode)
	mockJWT := new(MockJWTService)
	logger := logrus.New()
	logger.SetOutput(nil) // Tắt output để test

	// Tạo router với middleware
	r := gin.New()
	r.Use(AuthMiddleware(mockJWT, logger))
	r.GET("/protected", func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		c.String(http.StatusOK, "user_id: %s", userID)
	})

	t.Run("Missing Auth Header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/protected", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "missing authorization header")
	})

	t.Run("Invalid Auth Format", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "InvalidFormat")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "invalid authorization format")
	})

	t.Run("Blacklisted Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer blacklisted-token")

		// Mock IsBlacklisted để trả về true
		mockJWT.On("IsBlacklisted", "blacklisted-token").Return(true)

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "token has been revoked")
	})

	t.Run("Invalid Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")

		// Mock IsBlacklisted để trả về false
		mockJWT.On("IsBlacklisted", "invalid-token").Return(false)

		// Mock VerifyToken để trả về lỗi
		mockJWT.On("VerifyToken", "invalid-token").Return(nil, errors.New("invalid token"))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "invalid or expired token")
	})

	t.Run("Valid Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer valid-token")

		// Mock IsBlacklisted để trả về false
		mockJWT.On("IsBlacklisted", "valid-token").Return(false)

		// Mock VerifyToken để trả về claims hợp lệ
		validClaims := &utils.JWTClaims{
			UserID:      "test-user-id",
			Username:    "testuser",
			Email:       "test@example.com",
			SessionID:   "test-session-id",
			IsAdmin:     false,
			Roles:       []string{"user", "admin"},
			Permissions: []string{"read", "write"},
		}
		mockJWT.On("VerifyToken", "valid-token").Return(validClaims, nil)

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "user_id: test-user-id")
	})
}

func TestRequireRole(t *testing.T) {
	// Chuẩn bị
	gin.SetMode(gin.TestMode)

	// Tạo router với middleware
	r := gin.New()
	r.GET("/admin", RequireRole("admin"), func(c *gin.Context) {
		c.String(http.StatusOK, "admin access granted")
	})

	t.Run("Missing Roles", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin", nil)
		w := httptest.NewRecorder()

		// Tạo context mới không có roles
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		// Thực thi middleware trực tiếp
		RequireRole("admin")(c)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "No roles found")
	})

	t.Run("Insufficient Role", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin", nil)
		w := httptest.NewRecorder()

		// Tạo context mới với roles không đủ
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("roles", []string{"user"})

		// Thực thi middleware trực tiếp
		RequireRole("admin")(c)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "Insufficient role")
	})

	t.Run("Sufficient Role", func(t *testing.T) {
		// Tạo router mới để test đầy đủ flow
		r := gin.New()
		r.GET("/admin", func(c *gin.Context) {
			// Giả lập AuthMiddleware đã set roles
			c.Set("roles", []string{"admin"})
			c.Next()
		}, RequireRole("admin"), func(c *gin.Context) {
			c.String(http.StatusOK, "admin access granted")
		})

		req := httptest.NewRequest("GET", "/admin", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "admin access granted")
	})
}

func TestRequirePermission(t *testing.T) {
	// Tương tự như TestRequireRole nhưng cho permissions
	gin.SetMode(gin.TestMode)

	t.Run("Missing Permissions", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/write", nil)
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)
		c.Request = req

		RequirePermission("write")(c)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "No permissions found")
	})

	t.Run("Insufficient Permission", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/write", nil)
		w := httptest.NewRecorder()

		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Set("permissions", []string{"read"})

		RequirePermission("write")(c)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "Insufficient permission")
	})

	t.Run("Sufficient Permission", func(t *testing.T) {
		r := gin.New()
		r.GET("/write", func(c *gin.Context) {
			c.Set("permissions", []string{"read", "write"})
			c.Next()
		}, RequirePermission("write"), func(c *gin.Context) {
			c.String(http.StatusOK, "write access granted")
		})

		req := httptest.NewRequest("GET", "/write", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "write access granted")
	})
}
