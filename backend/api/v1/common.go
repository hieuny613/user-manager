package v1

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"backend/config"
	"backend/utils"
)

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// SuccessResponse represents a success response
type SuccessResponse struct {
	Message string `json:"message"`
}

// PaginationParams represents pagination parameters
type PaginationParams struct {
	Page     int `form:"page,default=1" binding:"min=1"`
	PageSize int `form:"page_size,default=10" binding:"min=1,max=100"`
}

// UserResponse represents a user response
type UserResponse struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	Username        string    `json:"username"`
	FirstName       string    `json:"first_name"`
	LastName        string    `json:"last_name"`
	IsActive        bool      `json:"is_active"`
	IsEmailVerified bool      `json:"is_email_verified"`
	LastLoginAt     *string   `json:"last_login_at,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Groups          []string  `json:"groups,omitempty"`
	Roles           []string  `json:"roles,omitempty"`
	Permissions     []string  `json:"permissions,omitempty"`
}

// GroupResponse represents a group response
type GroupResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Users       []string  `json:"users,omitempty"`
	Roles       []string  `json:"roles,omitempty"`
}

// RoleResponse represents a role response
type RoleResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Permissions []string  `json:"permissions,omitempty"`
}

// PermissionResponse represents a permission response
type PermissionResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AuthMiddleware is a middleware for authentication
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var token string

		// Check if using cookies
		if utils.UseCookiesForTokens() {
			// Get token from cookie
			var err error
			token, err = c.Cookie("access_token")
			if err != nil || token == "" {
				c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized: missing token"})
				c.Abort()
				return
			}
		} else {
			// Get token from Authorization header
			auth := c.GetHeader("Authorization")
			if auth == "" {
				c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized: missing token"})
				c.Abort()
				return
			}

			// Check if token is in correct format
			parts := strings.SplitN(auth, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized: invalid token format"})
				c.Abort()
				return
			}

			token = parts[1]
		}

		// Validate token
		claims, err := utils.ValidateToken(token, config.GetConfig().JWT.AccessTokenSecret)
		if err != nil {
			c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized: " + err.Error()})
			c.Abort()
			return
		}

		// Extract user ID and session ID from claims
		userID, ok := claims["user_id"].(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized: invalid token"})
			c.Abort()
			return
		}

		sessionID, ok := claims["session_id"].(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized: invalid token"})
			c.Abort()
			return
		}

		// Set user ID and session ID in context
		c.Set("user_id", userID)
		c.Set("session_id", sessionID)

		// Set username in context if available
		if username, ok := claims["username"].(string); ok {
			c.Set("username", username)
		}

		// Set email in context if available
		if email, ok := claims["email"].(string); ok {
			c.Set("email", email)
		}

		c.Next()
	}
}

// RBACMiddleware is a middleware for RBAC
func RBACMiddleware(requiredPermissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from context
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized"})
			c.Abort()
			return
		}

		// Parse user ID
		userUUID, err := uuid.Parse(userID.(string))
		if err != nil {
			c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid user ID"})
			c.Abort()
			return
		}

		// Skip permission check for superadmin users
		isSuperAdmin, exists := c.Get("is_superadmin")
		if exists && isSuperAdmin.(bool) {
			c.Next()
			return
		}

		// Get user service from application context
		userService := utils.GetUserService()
		if userService == nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "User service not available"})
			c.Abort()
			return
		}

		// Check if user has required permissions
		result, err := userService.CheckUserPermissions(c.Request.Context(), userUUID, requiredPermissions)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to check permissions: " + err.Error()})
			c.Abort()
			return
		}

		// If user doesn't have all required permissions, return forbidden
		if !result.HasAllPermissions {
			c.JSON(http.StatusForbidden, ErrorResponse{Error: "Insufficient permissions"})
			c.Abort()
			return
		}

		// Add permission check to audit log
		auditService := utils.GetAuditService()
		if auditService != nil {
			go auditService.LogPermissionCheck(
				context.Background(),
				userUUID,
				requiredPermissions,
				result.HasAllPermissions,
				c.ClientIP(),
				c.Request.UserAgent(),
				c.Request.URL.Path,
			)
		}

		c.Next()
	}
}

// CORSMiddleware is a middleware for CORS
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", config.GetConfig().Security.CORSAllowOrigins)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// SecurityHeadersMiddleware is a middleware for security headers
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Content Security Policy
		c.Writer.Header().Set("Content-Security-Policy", config.GetConfig().Security.CSP)

		// Prevent MIME sniffing
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking
		c.Writer.Header().Set("X-Frame-Options", "DENY")

		// XSS protection
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")

		// Referrer policy
		c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// HSTS (only in production)
		if config.GetConfig().Environment == "production" {
			c.Writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		// Permissions policy
		c.Writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")

		c.Next()
	}
}

// RequestIDMiddleware is a middleware for request ID
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Generate request ID if not present
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Set request ID in context and header
		c.Set("request_id", requestID)
		c.Writer.Header().Set("X-Request-ID", requestID)

		c.Next()
	}
}

// LoggingMiddleware is a middleware for logging
func LoggingMiddleware(logger *utils.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(start)

		// Get request ID
		requestID, _ := c.Get("request_id")

		// Get user ID if available
		userID, exists := c.Get("user_id")
		userIDStr := "-"
		if exists {
			userIDStr = userID.(string)
		}

		// Log request
		logger.WithFields(map[string]interface{}{
			"request_id":  requestID,
			"status_code": c.Writer.Status(),
			"method":      c.Request.Method,
			"path":        c.Request.URL.Path,
			"ip":          c.ClientIP(),
			"duration":    duration.Milliseconds(),
			"user_agent":  c.Request.UserAgent(),
			"user_id":     userIDStr,
		}).Info("Request processed")
	}
}

// RateLimitMiddleware is a middleware for rate limiting
func RateLimitMiddleware() gin.HandlerFunc {
	// Create a new rate limiter store
	store := utils.NewRateLimiterStore()

	return func(c *gin.Context) {
		// Get client IP
		clientIP := c.ClientIP()

		// Get rate limit configuration
		cfg := config.GetConfig().Security.RateLimit

		// Check if this is a sensitive endpoint that needs stricter rate limiting
		path := c.Request.URL.Path
		method := c.Request.Method
		isSensitive := false

		// Authentication endpoints need stricter rate limiting
		if (strings.Contains(path, "/auth/login") ||
			strings.Contains(path, "/auth/register") ||
			strings.Contains(path, "/auth/password/reset")) &&
			method == "POST" {
			isSensitive = true
		}

		// Apply different rate limits based on endpoint sensitivity
		var limit, burst int
		var window time.Duration

		if isSensitive {
			limit = cfg.SensitiveLimit
			burst = cfg.SensitiveBurst
			window = cfg.SensitiveWindow
		} else {
			limit = cfg.StandardLimit
			burst = cfg.StandardBurst
			window = cfg.StandardWindow
		}

		// Check if rate limit is exceeded
		key := clientIP
		if isSensitive {
			// For sensitive endpoints, use a more specific key
			key = clientIP + ":" + path
		}

		allowed, remaining, reset := store.Allow(key, limit, burst, window)
		if !allowed {
			// Set rate limit headers
			c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", reset))
			c.Header("Retry-After", fmt.Sprintf("%d", reset))

			// Log rate limit exceeded
			utils.GetLogger().WithFields(map[string]interface{}{
				"ip":     clientIP,
				"path":   path,
				"method": method,
				"limit":  limit,
				"window": window,
			}).Warn("Rate limit exceeded")

			// Return 429 Too Many Requests
			c.JSON(http.StatusTooManyRequests, ErrorResponse{Error: "Rate limit exceeded. Please try again later."})
			c.Abort()
			return
		}

		// Set rate limit headers
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", reset))

		c.Next()
	}
}

// CSRFMiddleware is a middleware for CSRF protection
func CSRFMiddleware() gin.HandlerFunc {
	// TODO: Implement CSRF protection
	return func(c *gin.Context) {
		c.Next()
	}
}
