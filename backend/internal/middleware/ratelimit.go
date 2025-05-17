package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// RateLimiter quản lý việc giới hạn tốc độ request
type RateLimiter struct {
	ipLimiters    map[string]*rate.Limiter
	userLimiters  map[string]*rate.Limiter
	ipMu          sync.RWMutex
	userMu        sync.RWMutex
	ipRate        rate.Limit
	userRate      rate.Limit
	ipBurst       int
	userBurst     int
	ipCleanupTime time.Duration
	logger        *logrus.Logger
}

// NewRateLimiter tạo một instance mới của RateLimiter
func NewRateLimiter(ipRequestsPerSecond, userRequestsPerSecond float64, ipBurst, userBurst int, logger *logrus.Logger) *RateLimiter {
	rl := &RateLimiter{
		ipLimiters:    make(map[string]*rate.Limiter),
		userLimiters:  make(map[string]*rate.Limiter),
		ipRate:        rate.Limit(ipRequestsPerSecond),
		userRate:      rate.Limit(userRequestsPerSecond),
		ipBurst:       ipBurst,
		userBurst:     userBurst,
		ipCleanupTime: 1 * time.Hour,
		logger:        logger,
	}

	// Khởi động goroutine để dọn dẹp limiters không sử dụng
	go rl.cleanupLimiters()

	return rl
}

// getIPLimiter lấy hoặc tạo một limiter cho IP
func (rl *RateLimiter) getIPLimiter(ip string) *rate.Limiter {
	rl.ipMu.RLock()
	limiter, exists := rl.ipLimiters[ip]
	rl.ipMu.RUnlock()

	if !exists {
		rl.ipMu.Lock()
		limiter = rate.NewLimiter(rl.ipRate, rl.ipBurst)
		rl.ipLimiters[ip] = limiter
		rl.ipMu.Unlock()
	}

	return limiter
}

// getUserLimiter lấy hoặc tạo một limiter cho user
func (rl *RateLimiter) getUserLimiter(userID string) *rate.Limiter {
	rl.userMu.RLock()
	limiter, exists := rl.userLimiters[userID]
	rl.userMu.RUnlock()

	if !exists {
		rl.userMu.Lock()
		limiter = rate.NewLimiter(rl.userRate, rl.userBurst)
		rl.userLimiters[userID] = limiter
		rl.userMu.Unlock()
	}

	return limiter
}

// cleanupLimiters dọn dẹp các limiters không sử dụng
func (rl *RateLimiter) cleanupLimiters() {
	ticker := time.NewTicker(rl.ipCleanupTime)
	defer ticker.Stop()

	for range ticker.C {
		rl.ipMu.Lock()
		rl.ipLimiters = make(map[string]*rate.Limiter)
		rl.ipMu.Unlock()

		rl.userMu.Lock()
		rl.userLimiters = make(map[string]*rate.Limiter)
		rl.userMu.Unlock()

		rl.logger.Info("Rate limiters cleaned up")
	}
}

// RateLimitMiddleware tạo một middleware để giới hạn tốc độ request
func (rl *RateLimiter) RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Lấy IP của client
		clientIP := c.ClientIP()
		ipLimiter := rl.getIPLimiter(clientIP)

		// Kiểm tra giới hạn IP
		if !ipLimiter.Allow() {
			rl.logger.WithFields(logrus.Fields{
				"ip":         clientIP,
				"request_id": c.GetString(RequestIDKey),
				"path":       c.Request.URL.Path,
			}).Warn("IP rate limit exceeded")

			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded. Try again later.",
			})
			return
		}

		// Nếu user đã đăng nhập, kiểm tra giới hạn user
		if userID, exists := c.Get("user_id"); exists {
			userIDStr, ok := userID.(string)
			if ok {
				userLimiter := rl.getUserLimiter(userIDStr)
				if !userLimiter.Allow() {
					rl.logger.WithFields(logrus.Fields{
						"user_id":    userIDStr,
						"ip":         clientIP,
						"request_id": c.GetString(RequestIDKey),
						"path":       c.Request.URL.Path,
					}).Warn("User rate limit exceeded")

					c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
						"error": "Rate limit exceeded. Try again later.",
					})
					return
				}
			}
		}

		c.Next()
	}
}

// SimpleRateLimitMiddleware tạo một middleware đơn giản hơn chỉ giới hạn theo IP
func SimpleRateLimitMiddleware(requestsPerSecond float64, burst int) gin.HandlerFunc {
	// Tạo map để lưu limiters
	limiters := make(map[string]*rate.Limiter)
	mu := &sync.RWMutex{}

	// Hàm để lấy limiter cho IP
	getLimiter := func(ip string) *rate.Limiter {
		mu.RLock()
		limiter, exists := limiters[ip]
		mu.RUnlock()

		if !exists {
			mu.Lock()
			limiter = rate.NewLimiter(rate.Limit(requestsPerSecond), burst)
			limiters[ip] = limiter
			mu.Unlock()
		}

		return limiter
	}

	return func(c *gin.Context) {
		limiter := getLimiter(c.ClientIP())
		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded. Try again later.",
			})
			return
		}
		c.Next()
	}
}
