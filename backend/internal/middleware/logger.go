package middleware

import (
	"bytes"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// RequestIDKey là key để lưu request ID trong context
const RequestIDKey = "request_id"

// LoggerMiddleware tạo một middleware để log thông tin request
func LoggerMiddleware(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Bắt đầu tính thời gian
		startTime := time.Now()

		// Tạo hoặc lấy request ID
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Lưu request ID vào context
		c.Set(RequestIDKey, requestID)
		c.Header("X-Request-ID", requestID)

		// Tạo buffer để lưu body request (nếu cần)
		var requestBodyBuffer bytes.Buffer
		if c.Request.Body != nil && c.Request.ContentLength > 0 && c.Request.ContentLength < 1024*1024 { // Giới hạn 1MB
			// Đọc body
			bodyBytes, _ := io.ReadAll(c.Request.Body)
			// Khôi phục body cho các middleware tiếp theo
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			// Lưu body vào buffer
			requestBodyBuffer.Write(bodyBytes)
		}

		// Tạo writer tùy chỉnh để capture response
		blw := &bodyLogWriter{body: bytes.NewBufferString(""), ResponseWriter: c.Writer}
		c.Writer = blw

		// Xử lý request
		c.Next()

		// Tính thời gian xử lý
		latency := time.Since(startTime)

		// Chuẩn bị log fields
		logFields := logrus.Fields{
			"status_code":  c.Writer.Status(),
			"latency":      latency,
			"client_ip":    c.ClientIP(),
			"method":       c.Request.Method,
			"path":         c.Request.URL.Path,
			"query":        c.Request.URL.RawQuery,
			"user_agent":   c.Request.UserAgent(),
			"request_id":   requestID,
			"referer":      c.Request.Referer(),
			"host":         c.Request.Host,
			"content_type": c.ContentType(),
			"content_len":  c.Writer.Size(),
		}

		// Thêm user ID nếu có
		if userID, exists := c.Get("user_id"); exists {
			logFields["user_id"] = userID
		}

		// Thêm body request nếu có và không quá lớn
		if requestBodyBuffer.Len() > 0 && requestBodyBuffer.Len() < 1024 { // Giới hạn log 1KB
			logFields["request_body"] = requestBodyBuffer.String()
		}

		// Thêm body response nếu không quá lớn
		if blw.body.Len() > 0 && blw.body.Len() < 1024 { // Giới hạn log 1KB
			logFields["response_body"] = blw.body.String()
		}

		// Thêm errors nếu có
		if len(c.Errors) > 0 {
			logFields["errors"] = c.Errors.String()
		}

		// Log theo status code
		statusCode := c.Writer.Status()
		switch {
		case statusCode >= 500:
			logger.WithFields(logFields).Error("Server error")
		case statusCode >= 400:
			logger.WithFields(logFields).Warn("Client error")
		case statusCode >= 300:
			logger.WithFields(logFields).Info("Redirection")
		default:
			logger.WithFields(logFields).Info("Success")
		}
	}
}

// bodyLogWriter là một wrapper cho gin.ResponseWriter để capture response body
type bodyLogWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

// Write ghi dữ liệu vào cả ResponseWriter gốc và buffer
func (w *bodyLogWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

// GetRequestLogger trả về một logger với request ID từ context
func GetRequestLogger(c *gin.Context, logger *logrus.Logger) *logrus.Entry {
	requestID, exists := c.Get(RequestIDKey)
	if !exists {
		requestID = "unknown"
	}

	fields := logrus.Fields{
		"request_id": requestID,
	}

	// Thêm user ID nếu có
	if userID, exists := c.Get("user_id"); exists {
		fields["user_id"] = userID
	}

	return logger.WithFields(fields)
}

// RequestLogger trả về một middleware đơn giản hơn chỉ gắn request ID
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Tạo hoặc lấy request ID
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Lưu request ID vào context
		c.Set(RequestIDKey, requestID)
		c.Header("X-Request-ID", requestID)

		c.Next()
	}
}
