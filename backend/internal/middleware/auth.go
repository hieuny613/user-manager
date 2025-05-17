package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"backend/internal/utils"
)

// Các lỗi liên quan đến authentication
var (
	ErrMissingAuthHeader = errors.New("missing authorization header")
	ErrInvalidAuthFormat = errors.New("invalid authorization format")
	ErrInvalidToken      = errors.New("invalid or expired token")
	ErrTokenBlacklisted  = errors.New("token has been revoked")
	ErrInsufficientRole  = errors.New("insufficient role")
)

// AuthMiddleware tạo một middleware để xác thực JWT token
func AuthMiddleware(jwtService *utils.JWTService, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Lấy token từ header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": ErrMissingAuthHeader.Error(),
			})
			return
		}

		// Kiểm tra format "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": ErrInvalidAuthFormat.Error(),
			})
			return
		}

		tokenString := parts[1]

		// Kiểm tra token có trong blacklist không
		if jwtService.IsBlacklisted(tokenString) {
			logger.WithFields(logrus.Fields{
				"token":      tokenString[:10] + "...",
				"request_id": c.GetString(RequestIDKey),
			}).Warn("Token is blacklisted")

			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": ErrTokenBlacklisted.Error(),
			})
			return
		}

		// Xác thực token
		claims, err := jwtService.VerifyToken(tokenString)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"error":      err.Error(),
				"token":      tokenString[:10] + "...", // Chỉ log một phần của token
				"request_id": c.GetString(RequestIDKey),
			}).Warn("Invalid token")

			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": ErrInvalidToken.Error(),
			})
			return
		}

		// Lưu thông tin user vào context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("email", claims.Email)
		c.Set("session_id", claims.SessionID)
		c.Set("is_admin", claims.IsAdmin)

		// Lưu roles và permissions nếu có
		if claims.Roles != nil {
			c.Set("roles", claims.Roles)
		}
		if claims.Permissions != nil {
			c.Set("permissions", claims.Permissions)
		}

		// Log thông tin xác thực thành công
		logger.WithFields(logrus.Fields{
			"user_id":    claims.UserID,
			"username":   claims.Username,
			"session_id": claims.SessionID,
			"request_id": c.GetString(RequestIDKey),
		}).Debug("Authentication successful")

		c.Next()
	}
}

// RequireRole tạo một middleware để kiểm tra role của user
func RequireRole(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Lấy roles từ context (đã được set bởi AuthMiddleware)
		rolesInterface, exists := c.Get("roles")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "No roles found",
			})
			return
		}

		// Type assertion
		roles, ok := rolesInterface.([]string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid roles format",
			})
			return
		}

		// Kiểm tra xem user có role yêu cầu không
		hasRequiredRole := false
		for _, userRole := range roles {
			for _, requiredRole := range requiredRoles {
				if userRole == requiredRole {
					hasRequiredRole = true
					break
				}
			}
			if hasRequiredRole {
				break
			}
		}

		if !hasRequiredRole {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Insufficient role",
			})
			return
		}

		c.Next()
	}
}

// RequirePermission tạo một middleware để kiểm tra permission của user
func RequirePermission(requiredPermissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Lấy permissions từ context (đã được set bởi AuthMiddleware)
		permissionsInterface, exists := c.Get("permissions")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "No permissions found",
			})
			return
		}

		// Type assertion
		permissions, ok := permissionsInterface.([]string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Invalid permissions format",
			})
			return
		}

		// Kiểm tra xem user có permission yêu cầu không
		hasRequiredPermission := false
		for _, userPermission := range permissions {
			for _, requiredPermission := range requiredPermissions {
				if userPermission == requiredPermission {
					hasRequiredPermission = true
					break
				}
			}
			if hasRequiredPermission {
				break
			}
		}

		if !hasRequiredPermission {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permission",
			})
			return
		}

		c.Next()
	}
}
