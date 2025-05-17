package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	// Chuẩn bị
	gin.SetMode(gin.TestMode)
	config := DefaultSecurityConfig()

	// Tạo router với middleware
	r := gin.New()
	r.Use(SecurityHeadersMiddleware(config))
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// Thực hiện request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Kiểm tra response
	assert.Equal(t, http.StatusOK, w.Code)

	// Kiểm tra các headers
	assert.NotEmpty(t, w.Header().Get("Content-Security-Policy"))
	assert.NotEmpty(t, w.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "SAMEORIGIN", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
	assert.NotEmpty(t, w.Header().Get("Permissions-Policy"))
	assert.Equal(t, "no-store, max-age=0", w.Header().Get("Cache-Control"))
}

func TestBasicSecurityHeadersMiddleware(t *testing.T) {
	// Chuẩn bị
	gin.SetMode(gin.TestMode)

	// Tạo router với middleware
	r := gin.New()
	r.Use(BasicSecurityHeadersMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// Thực hiện request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Kiểm tra response
	assert.Equal(t, http.StatusOK, w.Code)

	// Kiểm tra các headers
	assert.Equal(t, "SAMEORIGIN", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
	assert.NotEmpty(t, w.Header().Get("Content-Security-Policy"))
}

func TestBuildCSP(t *testing.T) {
	config := SecurityConfig{
		CSPDefaultSrc: []string{"'self'"},
		CSPScriptSrc:  []string{"'self'", "'unsafe-inline'"},
		CSPStyleSrc:   []string{"'self'", "'unsafe-inline'"},
	}

	csp := buildCSP(config)
	assert.Contains(t, csp, "default-src 'self'")
	assert.Contains(t, csp, "script-src 'self' 'unsafe-inline'")
	assert.Contains(t, csp, "style-src 'self' 'unsafe-inline'")
}

func TestBuildHSTS(t *testing.T) {
	config := SecurityConfig{
		HSTSMaxAge:            31536000,
		HSTSIncludeSubDomains: true,
		HSTSPreload:           true,
	}

	hsts := buildHSTS(config)
	assert.Contains(t, hsts, "max-age=31536000")
	assert.Contains(t, hsts, "includeSubDomains")
	assert.Contains(t, hsts, "preload")
}
