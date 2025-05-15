package middleware

import (
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"backend/config"
	"backend/utils"
)

// RateLimiter holds the rate limiter configuration
type RateLimiter struct {
	Limiter  *rate.Limiter
	LastSeen time.Time
}

// RateLimiterStore holds the rate limiters for each IP address
var RateLimiterStore = make(map[string]*RateLimiter)

// SecurityHeaders adds security headers to responses
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Set security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self';")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

		// Continue with the request
		c.Next()
	}
}

// CORS configures CORS for the application
func CORS(config *config.Config) gin.HandlerFunc {
	return cors.New(cors.Config{
		AllowOrigins:     config.CORSAllowOrigins,
		AllowMethods:     config.CORSAllowMethods,
		AllowHeaders:     config.CORSAllowHeaders,
		ExposeHeaders:    []string{"Content-Length", "Content-Type", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	})
}

// RateLimit limits the number of requests from an IP address
func RateLimit(config *config.Config, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get request logger
		reqLogger := utils.GetRequestLogger(c, logger)

		// Get client IP address
		ip := c.ClientIP()

		// Get or create rate limiter for this IP
		limiter, exists := RateLimiterStore[ip]
		if !exists {
			limiter = &RateLimiter{
				Limiter:  rate.NewLimiter(rate.Limit(float64(config.RateLimitRequests)/config.RateLimitDuration.Seconds()), config.RateLimitRequests),
				LastSeen: time.Now(),
			}
			RateLimiterStore[ip] = limiter
		}

		// Update last seen time
		limiter.LastSeen = time.Now()

		// Check if the request is allowed
		if !limiter.Limiter.Allow() {
			reqLogger.WithField("ip", ip).Warn("Rate limit exceeded")
			c.Header("Retry-After", "60")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			return
		}

		// Continue with the request
		c.Next()
	}
}

// CSRFProtection adds CSRF protection to the application
func CSRFProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip CSRF check for GET, HEAD, OPTIONS, TRACE requests
		if c.Request.Method == http.MethodGet ||
			c.Request.Method == http.MethodHead ||
			c.Request.Method == http.MethodOptions ||
			c.Request.Method == http.MethodTrace {
			c.Next()
			return
		}

		// Check CSRF token
		csrfToken := c.GetHeader("X-CSRF-Token")
		if csrfToken == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "CSRF token is required"})
			return
		}

		// Validate CSRF token (in a real application, this would check against a stored token)
		// For simplicity, we're just checking if it's not empty here
		// In a real application, you would use a library like gorilla/csrf

		// Continue with the request
		c.Next()
	}
}

// CleanupRateLimiters periodically cleans up old rate limiters
func CleanupRateLimiters() {
	for {
		time.Sleep(time.Hour)

		// Remove rate limiters that haven't been seen in the last hour
		for ip, limiter := range RateLimiterStore {
			if time.Since(limiter.LastSeen) > time.Hour {
				delete(RateLimiterStore, ip)
			}
		}
	}
}