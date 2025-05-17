package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestCORSMiddleware(t *testing.T) {
	// Chuẩn bị
	gin.SetMode(gin.TestMode)
	config := DefaultCORSConfig()

	// Tạo router với middleware
	r := gin.New()
	r.Use(CORSMiddleware(config))
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// Test preflight request
	t.Run("Preflight Request", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("Access-Control-Request-Method", "GET")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
	})

	// Test actual request
	t.Run("Actual Request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
	})

	// Test disallowed origin
	t.Run("Disallowed Origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://evil.com")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	})
}

func TestCORSMiddlewareWithEnv(t *testing.T) {
	// Chuẩn bị
	gin.SetMode(gin.TestMode)
	allowedOrigins := "http://example.com, http://test.com"

	// Tạo router với middleware
	r := gin.New()
	r.Use(CORSMiddlewareWithEnv(allowedOrigins))
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// Test allowed origin
	t.Run("Allowed Origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "http://example.com", w.Header().Get("Access-Control-Allow-Origin"))
	})

	// Test disallowed origin
	t.Run("Disallowed Origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	})
}

func TestSimpleCORSMiddleware(t *testing.T) {
	// Chuẩn bị
	gin.SetMode(gin.TestMode)

	// Tạo router với middleware
	r := gin.New()
	r.Use(SimpleCORSMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// Test preflight request
	t.Run("Preflight Request", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	})

	// Test actual request
	t.Run("Actual Request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	})
}
