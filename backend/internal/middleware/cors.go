package middleware

import (
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CORSConfig chứa cấu hình cho CORS
type CORSConfig struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           time.Duration
}

// DefaultCORSConfig trả về cấu hình CORS mặc định
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowOrigins:     []string{"http://localhost:3000", "http://localhost:8080"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With", "X-CSRF-Token"},
		ExposeHeaders:    []string{"Content-Length", "Content-Type", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
}

// CORSMiddleware tạo một middleware để xử lý CORS
func CORSMiddleware(config CORSConfig) gin.HandlerFunc {
	corsConfig := cors.Config{
		AllowOrigins:     config.AllowOrigins,
		AllowMethods:     config.AllowMethods,
		AllowHeaders:     config.AllowHeaders,
		ExposeHeaders:    config.ExposeHeaders,
		AllowCredentials: config.AllowCredentials,
		MaxAge:           int(config.MaxAge.Seconds()),
	}

	// Nếu AllowOrigins chứa "*", cho phép tất cả origins
	if len(config.AllowOrigins) == 1 && config.AllowOrigins[0] == "*" {
		corsConfig.AllowAllOrigins = true
	}

	return cors.New(corsConfig)
}

// CORSMiddlewareWithEnv tạo một middleware CORS từ chuỗi origins được phân tách bằng dấu phẩy
func CORSMiddlewareWithEnv(allowedOrigins string) gin.HandlerFunc {
	config := DefaultCORSConfig()

	// Nếu có origins được cung cấp, sử dụng chúng thay vì mặc định
	if allowedOrigins != "" {
		config.AllowOrigins = strings.Split(allowedOrigins, ",")
		// Trim whitespace
		for i := range config.AllowOrigins {
			config.AllowOrigins[i] = strings.TrimSpace(config.AllowOrigins[i])
		}
	}

	return CORSMiddleware(config)
}

// SimpleCORSMiddleware là phiên bản đơn giản hơn cho CORS
func SimpleCORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Type")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
