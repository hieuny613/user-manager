package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"backend/config"
)

// RequestIDKey là key được sử dụng để lưu request ID trong context
const RequestIDKey = "request_id"

// Logger chứa các hàm và thuộc tính cho việc ghi log
type Logger struct {
	*logrus.Logger
	AuditLogger *logrus.Logger
	config      *config.Config
}

// NewLogger tạo một instance mới của Logger
func NewLogger(cfg *config.Config) *Logger {
	// Tạo logger chính
	logger := logrus.New()

	// Cấu hình format (JSON hoặc text)
	if strings.ToLower(cfg.Logging.Format) == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				filename := filepath.Base(f.File)
				return fmt.Sprintf("%s()", f.Function), fmt.Sprintf("%s:%d", filename, f.Line)
			},
		})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: time.RFC3339,
			FullTimestamp:   true,
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				filename := filepath.Base(f.File)
				return fmt.Sprintf("%s()", f.Function), fmt.Sprintf("%s:%d", filename, f.Line)
			},
		})
	}

	// Cấu hình log level
	level, err := logrus.ParseLevel(cfg.Logging.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Cấu hình output
	// Ghi log ra file và console
	outputs := []io.Writer{os.Stdout}

	// Nếu có đường dẫn file log
	if cfg.Logging.FilePath != "" {
		// Tạo thư mục chứa file log nếu chưa tồn tại
		logDir := filepath.Dir(cfg.Logging.FilePath)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			logger.Warnf("Failed to create log directory: %v", err)
		}

		// Cấu hình log rotation
		fileWriter := &lumberjack.Logger{
			Filename:   cfg.Logging.FilePath,
			MaxSize:    cfg.Logging.MaxSize, // megabytes
			MaxBackups: cfg.Logging.MaxBackups,
			MaxAge:     cfg.Logging.MaxAge, // days
			Compress:   cfg.Logging.Compress,
		}
		outputs = append(outputs, fileWriter)
	}

	// Ghi log vào nhiều output
	logger.SetOutput(io.MultiWriter(outputs...))

	// Bật caller logging
	logger.SetReportCaller(true)

	// Tạo audit logger
	auditLogger := logrus.New()
	auditLogger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
	})
	auditLogger.SetLevel(logrus.InfoLevel)

	// Cấu hình audit log
	if cfg.Logging.AuditLogPath != "" {
		// Tạo thư mục chứa file audit log nếu chưa tồn tại
		auditLogDir := filepath.Dir(cfg.Logging.AuditLogPath)
		if err := os.MkdirAll(auditLogDir, 0755); err != nil {
			logger.Warnf("Failed to create audit log directory: %v", err)
		}

		// Cấu hình audit log rotation
		auditFileWriter := &lumberjack.Logger{
			Filename:   cfg.Logging.AuditLogPath,
			MaxSize:    cfg.Logging.MaxSize, // megabytes
			MaxBackups: cfg.Logging.MaxBackups,
			MaxAge:     cfg.Logging.MaxAge, // days
			Compress:   cfg.Logging.Compress,
		}
		auditLogger.SetOutput(auditFileWriter)
	} else {
		auditLogger.SetOutput(io.MultiWriter(outputs...))
	}

	return &Logger{
		Logger:      logger,
		AuditLogger: auditLogger,
		config:      cfg,
	}
}

// RequestIDMiddleware là middleware để tạo và gắn request ID vào mỗi request
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Lấy request ID từ header nếu có
		requestID := c.GetHeader("X-Request-ID")

		// Nếu không có, tạo một ID mới
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Gắn request ID vào context
		c.Set(RequestIDKey, requestID)

		// Gắn request ID vào response header
		c.Header("X-Request-ID", requestID)

		c.Next()
	}
}

// LoggerMiddleware là middleware để ghi log cho mỗi request
func (l *Logger) LoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Thời gian bắt đầu
		startTime := time.Now()

		// Lấy request ID
		requestID, exists := c.Get(RequestIDKey)
		if !exists {
			requestID = uuid.New().String()
			c.Set(RequestIDKey, requestID)
		}

		// Xử lý request
		c.Next()

		// Thời gian kết thúc
		endTime := time.Now()
		latency := endTime.Sub(startTime)

		// Ghi log
		l.WithFields(logrus.Fields{
			"status":     c.Writer.Status(),
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"ip":         c.ClientIP(),
			"latency":    latency,
			"user_agent": c.Request.UserAgent(),
			"request_id": requestID,
			"query":      c.Request.URL.RawQuery,
			"error":      c.Errors.String(),
			"referrer":   c.Request.Referer(),
		}).Info("Request processed")
	}
}

// GetRequestLogger trả về một logger đã được gắn request ID
func (l *Logger) GetRequestLogger(c *gin.Context) *logrus.Entry {
	// Lấy request ID từ context
	requestID, exists := c.Get(RequestIDKey)
	if !exists {
		requestID = "unknown"
	}

	// Trả về logger với request ID
	return l.WithField("request_id", requestID)
}

// LogAudit ghi một bản ghi audit log
func (l *Logger) LogAudit(c *gin.Context, action, entity, entityID, status string, oldValue, newValue interface{}, actor string) {
	// Lấy request ID từ context
	requestID, exists := c.Get(RequestIDKey)
	if !exists {
		requestID = "unknown"
	}

	// Ghi audit log
	l.AuditLogger.WithFields(logrus.Fields{
		"action":     action,
		"entity":     entity,
		"entity_id":  entityID,
		"status":     status,
		"old_value":  oldValue,
		"new_value":  newValue,
		"actor":      actor,
		"ip":         c.ClientIP(),
		"user_agent": c.Request.UserAgent(),
		"request_id": requestID,
		"timestamp":  time.Now().Format(time.RFC3339),
	}).Info("Audit log")
}

// GetContextLogger trả về một logger với context chung
func (l *Logger) GetContextLogger(module string, contextFields map[string]interface{}) *logrus.Entry {
	fields := logrus.Fields{
		"module": module,
	}

	// Thêm các trường context
	for k, v := range contextFields {
		fields[k] = v
	}

	return l.WithFields(fields)
}
