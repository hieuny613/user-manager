package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestLoggerMiddleware(t *testing.T) {
	// Chuẩn bị logger với buffer để kiểm tra output
	var logBuffer bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&logBuffer)
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Chuẩn bị Gin router
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(LoggerMiddleware(logger))

	// Thêm route test
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "test response")
	})

	// Tạo request test
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "test-agent")

	// Thực hiện request
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Kiểm tra response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "test response", w.Body.String())

	// Kiểm tra log
	logOutput := logBuffer.String()
	assert.Contains(t, logOutput, "request_id")
	assert.Contains(t, logOutput, "test-agent")
	assert.Contains(t, logOutput, "/test")
	assert.Contains(t, logOutput, "200")
}

func TestGetRequestLogger(t *testing.T) {
	// Chuẩn bị logger
	logger := logrus.New()

	// Chuẩn bị Gin context
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	// Thêm request ID vào context
	testRequestID := "test-request-id"
	c.Set(RequestIDKey, testRequestID)

	// Lấy logger từ context
	logEntry := GetRequestLogger(c, logger)

	// Kiểm tra logger có request ID
	assert.Equal(t, testRequestID, logEntry.Data["request_id"])
}

func TestRequestLogger(t *testing.T) {
	// Chuẩn bị Gin router
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestLogger())

	// Thêm route test
	r.GET("/test", func(c *gin.Context) {
		requestID, exists := c.Get(RequestIDKey)
		assert.True(t, exists)
		assert.NotEmpty(t, requestID)
		c.String(http.StatusOK, "test")
	})

	// Tạo request test
	req := httptest.NewRequest("GET", "/test", nil)

	// Thực hiện request
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Kiểm tra response
	assert.Equal(t, http.StatusOK, w.Code)

	// Kiểm tra header
	assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
}
