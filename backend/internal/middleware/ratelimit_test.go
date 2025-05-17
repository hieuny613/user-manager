package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestRateLimitMiddleware(t *testing.T) {
	// Chuẩn bị
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetOutput(nil) // Tắt output để test

	// Tạo rate limiter với giới hạn thấp để test
	rl := NewRateLimiter(1, 1, 2, 2, logger)

	// Tạo router với middleware
	r := gin.New()
	r.Use(rl.RateLimitMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	t.Run("IP Rate Limit", func(t *testing.T) {
		// Thực hiện 3 request từ cùng một IP (burst = 2)
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// Request thứ 3 nên bị giới hạn
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})

	t.Run("User Rate Limit", func(t *testing.T) {
		// Tạo router mới với middleware và handler đặt user_id
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Set("user_id", "test-user")
			c.Next()
		})
		r.Use(rl.RateLimitMiddleware())
		r.GET("/user-test", func(c *gin.Context) {
			c.String(http.StatusOK, "success")
		})

		// Thực hiện 3 request từ cùng một user (burst = 2)
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/user-test", nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// Request thứ 3 nên bị giới hạn
		req := httptest.NewRequest("GET", "/user-test", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})
}

func TestSimpleRateLimitMiddleware(t *testing.T) {
	// Chuẩn bị
	gin.SetMode(gin.TestMode)

	// Tạo router với middleware
	r := gin.New()
	r.Use(SimpleRateLimitMiddleware(1, 2)) // 1 req/s, burst 2
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// Thực hiện 3 request (burst = 2)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// Request thứ 3 nên bị giới hạn
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// Đợi để token được nạp lại
	time.Sleep(1 * time.Second)

	// Request tiếp theo nên thành công
	req = httptest.NewRequest("GET", "/test", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
