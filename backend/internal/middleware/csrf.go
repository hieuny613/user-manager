package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Các lỗi liên quan đến CSRF
var (
	ErrMissingCSRFToken = errors.New("missing CSRF token")
	ErrInvalidCSRFToken = errors.New("invalid CSRF token")
)

// CSRFConfig chứa cấu hình cho CSRF protection
type CSRFConfig struct {
	CookieName     string
	CookiePath     string
	CookieDomain   string
	CookieMaxAge   int
	CookieSecure   bool
	CookieHTTPOnly bool
	CookieSameSite http.SameSite
	HeaderName     string
	FormFieldName  string
	TokenLength    int
	IgnoreMethods  []string
}

// DefaultCSRFConfig trả về cấu hình CSRF mặc định
func DefaultCSRFConfig() CSRFConfig {
	return CSRFConfig{
		CookieName:     "csrf_token",
		CookiePath:     "/",
		CookieDomain:   "",
		CookieMaxAge:   86400, // 24 giờ
		CookieSecure:   true,
		CookieHTTPOnly: true,
		CookieSameSite: http.SameSiteLaxMode,
		HeaderName:     "X-CSRF-Token",
		FormFieldName:  "csrf_token",
		TokenLength:    32,
		IgnoreMethods:  []string{"GET", "HEAD", "OPTIONS"},
	}
}

// generateCSRFToken tạo một token ngẫu nhiên
func generateCSRFToken(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// CSRFMiddleware tạo một middleware để bảo vệ chống CSRF
func CSRFMiddleware(config CSRFConfig, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Bỏ qua các methods không cần kiểm tra CSRF
		for _, method := range config.IgnoreMethods {
			if c.Request.Method == method {
				// Với GET request, luôn set cookie mới nếu chưa có
				if c.Request.Method == "GET" {
					cookieToken, err := c.Cookie(config.CookieName)
					if err != nil || cookieToken == "" {
						cookieToken = generateCSRFToken(config.TokenLength)
						c.SetCookie(
							config.CookieName,
							cookieToken,
							config.CookieMaxAge,
							config.CookiePath,
							config.CookieDomain,
							config.CookieSecure,
							config.CookieHTTPOnly,
						)
					}
				}
				c.Next()
				return
			}
		}

		// Lấy token từ cookie
		cookieToken, err := c.Cookie(config.CookieName)
		if err != nil || cookieToken == "" {
			// Nếu không có token, tạo token mới và set cookie
			cookieToken = generateCSRFToken(config.TokenLength)
			c.SetCookie(
				config.CookieName,
				cookieToken,
				config.CookieMaxAge,
				config.CookiePath,
				config.CookieDomain,
				config.CookieSecure,
				config.CookieHTTPOnly,
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": ErrMissingCSRFToken.Error(),
			})
			return
		}

		// Lấy token từ header hoặc form
		var requestToken string
		requestToken = c.GetHeader(config.HeaderName)
		if requestToken == "" {
			requestToken = c.PostForm(config.FormFieldName)
		}

		// Kiểm tra token
		if requestToken == "" {
			logger.WithFields(logrus.Fields{
				"request_id": c.GetString(RequestIDKey),
				"path":       c.Request.URL.Path,
				"method":     c.Request.Method,
			}).Warn("Missing CSRF token in request")

			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": ErrMissingCSRFToken.Error(),
			})
			return
		}

		// So sánh token
		if requestToken != cookieToken {
			logger.WithFields(logrus.Fields{
				"request_id": c.GetString(RequestIDKey),
				"path":       c.Request.URL.Path,
				"method":     c.Request.Method,
			}).Warn("Invalid CSRF token")

			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": ErrInvalidCSRFToken.Error(),
			})
			return
		}

		// Token hợp lệ, tiếp tục xử lý
		c.Next()
	}
}

// GetCSRFToken trả về CSRF token hiện tại hoặc tạo một token mới
func GetCSRFToken(c *gin.Context, config CSRFConfig) string {
	cookieToken, err := c.Cookie(config.CookieName)
	if err != nil || cookieToken == "" {
		cookieToken = generateCSRFToken(config.TokenLength)
		c.SetCookie(
			config.CookieName,
			cookieToken,
			config.CookieMaxAge,
			config.CookiePath,
			config.CookieDomain,
			config.CookieSecure,
			config.CookieHTTPOnly,
		)
	}
	return cookieToken
}

// CSRFProtection trả về một middleware đơn giản hơn cho CSRF protection
func CSRFProtection() gin.HandlerFunc {
	config := DefaultCSRFConfig()
	return func(c *gin.Context) {
		// Bỏ qua các methods an toàn
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
			// Set CSRF cookie nếu chưa có
			cookieToken, err := c.Cookie(config.CookieName)
			if err != nil || cookieToken == "" {
				cookieToken = generateCSRFToken(config.TokenLength)
				c.SetCookie(
					config.CookieName,
					cookieToken,
					config.CookieMaxAge,
					config.CookiePath,
					config.CookieDomain,
					config.CookieSecure,
					config.CookieHTTPOnly,
				)
			}
			c.Next()
			return
		}

		// Kiểm tra token cho các methods khác
		cookieToken, err := c.Cookie(config.CookieName)
		if err != nil || cookieToken == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "CSRF token required",
			})
			return
		}

		// Lấy token từ header hoặc form
		requestToken := c.GetHeader(config.HeaderName)
		if requestToken == "" {
			requestToken = c.PostForm(config.FormFieldName)
		}

		if requestToken == "" || requestToken != cookieToken {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Invalid CSRF token",
			})
			return
		}

		c.Next()
	}
}
