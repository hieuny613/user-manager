package utils

import (
	"os"

	"github.com/sirupsen/logrus"

	"backend/config"
)

// Logger is a wrapper around logrus.Logger
type Logger struct {
	*logrus.Logger
}

// NewLogger creates a new logger
func NewLogger() *Logger {
	// Create logger
	logger := logrus.New()

	// Set output
	logger.SetOutput(os.Stdout)

	// Set formatter
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05.999Z07:00",
	})

	// Set log level based on environment
	cfg := config.GetConfig()
	if cfg.Environment == "development" {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	return &Logger{logger}
}

// WithFields adds fields to the logger
func (l *Logger) WithFields(fields map[string]interface{}) *logrus.Entry {
	return l.Logger.WithFields(fields)
}

// LogRequest logs an HTTP request
func (l *Logger) LogRequest(method, path, ip, userAgent, userID, requestID string, statusCode int, duration int64) {
	l.WithFields(map[string]interface{}{
		"method":      method,
		"path":        path,
		"ip":          ip,
		"user_agent":  userAgent,
		"user_id":     userID,
		"request_id":  requestID,
		"status_code": statusCode,
		"duration_ms": duration,
	}).Info("HTTP request")
}

// LogError logs an error
func (l *Logger) LogError(err error, message string, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["error"] = err.Error()
	l.WithFields(fields).Error(message)
}

// LogSecurity logs a security event
func (l *Logger) LogSecurity(event, userID, ip, userAgent string, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["event"] = event
	fields["user_id"] = userID
	fields["ip"] = ip
	fields["user_agent"] = userAgent
	l.WithFields(fields).Warn("Security event")
}

// LogAudit logs an audit event
func (l *Logger) LogAudit(action, resource, resourceID, userID, ip, userAgent, description string, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["action"] = action
	fields["resource"] = resource
	fields["resource_id"] = resourceID
	fields["user_id"] = userID
	fields["ip"] = ip
	fields["user_agent"] = userAgent
	fields["description"] = description
	l.WithFields(fields).Info("Audit event")
}