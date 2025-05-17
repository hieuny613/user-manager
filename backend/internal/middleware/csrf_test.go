package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestCSRFMiddleware(t *testing.T) {
	// Chuẩn bị
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetOutput(nil) // Tắt output để test
	config := DefaultCSRFConfig()

	// Tạo router với middleware
	r := gin.New()
	r.Use(CSRFMiddleware(config, logger))

	// Thêm route GET để lấy token
	r.GET("/csrf-token", func(c *gin.Context) {
		token := GetCSRFToken(c, config)
		c.String(http.StatusOK, token)
	})

	// Thêm route POST để test protection
	r.POST("/protected", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// Test GET request (không yêu cầu token)
	t.Run("GET Request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/csrf-token", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		// Kiểm tra cookie đã được set
		cookies := w.Result().Cookies()
		var csrfCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == config.CookieName {
				csrfCookie = cookie
				break
			}
		}
		assert.NotNil(t, csrfCookie, "CSRF cookie should be set")
		assert.Equal(t, w.Body.String(), csrfCookie.Value, "Token in body should match cookie")
	})

	// Test POST request không có token
	t.Run("POST Without Token", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/protected", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "missing CSRF token")
	})

	// Test POST request với token không đúng
	t.Run("POST With Invalid Token", func(t *testing.T) {
		// Đầu tiên lấy token
		req := httptest.NewRequest("GET", "/csrf-token", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		cookies := w.Result().Cookies()

		// Tạo request POST với token không đúng
		form := url.Values{}
		form.Add(config.FormFieldName, "invalid-token")
		req = httptest.NewRequest("POST", "/protected", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// Sử dụng cookie đã nhận được
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}

		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "invalid CSRF token")
	})

	// Test POST request với token đúng
	t.Run("POST With Valid Token", func(t *testing.T) {
		// Đầu tiên lấy token
		req := httptest.NewRequest("GET", "/csrf-token", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		cookies := w.Result().Cookies()
		token := w.Body.String()

		// Tạo request POST với token đúng
		form := url.Values{}
		form.Add(config.FormFieldName, token)
		req = httptest.NewRequest("POST", "/protected", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// Sử dụng cookie đã nhận được
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}

		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "success", w.Body.String())
	})

	// Test POST request với token trong header
	t.Run("POST With Token In Header", func(t *testing.T) {
		// Đầu tiên lấy token
		req := httptest.NewRequest("GET", "/csrf-token", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		cookies := w.Result().Cookies()
		token := w.Body.String()

		// Tạo request POST với token trong header
		req = httptest.NewRequest("POST", "/protected", nil)
		req.Header.Set(config.HeaderName, token)

		// Sử dụng cookie đã nhận được
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}

		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "success", w.Body.String())
	})
}

func TestCSRFProtection(t *testing.T) {
	// Chuẩn bị
	gin.SetMode(gin.TestMode)

	// Tạo router với middleware
	r := gin.New()
	r.Use(CSRFProtection())

	// Thêm routes
	r.GET("/get-token", func(c *gin.Context) {
		token, _ := c.Cookie("csrf_token")
		c.String(http.StatusOK, token)
	})

	r.POST("/protected", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// Test GET request
	t.Run("GET Request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/get-token", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Kiểm tra token đã được set trong cookie
		cookies := w.Result().Cookies()
		var csrfCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "csrf_token" {
				csrfCookie = cookie
			}
		}
		assert.NotNil(t, csrfCookie)
		assert.NotEmpty(t, csrfCookie.Value)
	})

	// Test POST request với token
	t.Run("POST With Valid Token", func(t *testing.T) {
		// Đầu tiên lấy token
		req := httptest.NewRequest("GET", "/get-token", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		// Lưu cookie
		cookies := w.Result().Cookies()
		token := w.Body.String()

		// Tạo POST request với token
		req = httptest.NewRequest("POST", "/protected", nil)
		req.Header.Set("X-CSRF-Token", token)

		// Thêm cookie
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}

		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
