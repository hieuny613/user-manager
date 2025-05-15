package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"backend/config"
	"backend/model"
	"backend/utils"
)

// AuthMiddleware is a middleware for JWT authentication
func AuthMiddleware(db *gorm.DB, jwtConfig *config.JWTConfig, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get request logger
		reqLogger := utils.GetRequestLogger(c, logger)

		// Get authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}

		// Check if the authorization header has the correct format
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			return
		}

		// Get the token
		tokenString := parts[1]

		// Validate the token
		token, err := jwtConfig.ValidateAccessToken(tokenString)
		if err != nil {
			reqLogger.WithError(err).Warn("Invalid access token")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		// Get claims from token
		claims, err := config.GetClaimsFromToken(token)
		if err != nil {
			reqLogger.WithError(err).Warn("Failed to get claims from token")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		// Extract user ID, email, and session ID from claims
		userIDStr, ok := claims["sub"].(string)
		if !ok {
			reqLogger.Warn("User ID not found in token claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			reqLogger.WithError(err).Warn("Invalid user ID in token claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		email, ok := claims["email"].(string)
		if !ok {
			reqLogger.Warn("Email not found in token claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		sessionIDStr, ok := claims["sid"].(string)
		if !ok {
			reqLogger.Warn("Session ID not found in token claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		sessionID, err := uuid.Parse(sessionIDStr)
		if err != nil {
			reqLogger.WithError(err).Warn("Invalid session ID in token claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		tokenJTIStr, ok := claims["jti"].(string)
		if !ok {
			reqLogger.Warn("Token JTI not found in token claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		tokenJTI, err := uuid.Parse(tokenJTIStr)
		if err != nil {
			reqLogger.WithError(err).Warn("Invalid token JTI in token claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		// Check if the user exists and is active
		var user model.User
		result := db.Where("id = ? AND is_active = true", userID).First(&user)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				reqLogger.WithField("user_id", userID).Warn("User not found or inactive")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User not found or inactive"})
				return
			}

			reqLogger.WithError(result.Error).Error("Failed to query user")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		// Check if the session exists and is active
		var session model.Session
		result = db.Where("id = ? AND user_id = ? AND token_jti = ? AND is_active = true AND expires_at > NOW()", sessionID, userID, tokenJTI).First(&session)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				reqLogger.WithFields(logrus.Fields{
					"user_id":    userID,
					"session_id": sessionID,
					"token_jti":  tokenJTI,
				}).Warn("Session not found, inactive, or expired")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Session not found, inactive, or expired"})
				return
			}

			reqLogger.WithError(result.Error).Error("Failed to query session")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		// Set user and session information in context
		c.Set("user_id", userID)
		c.Set("email", email)
		c.Set("session_id", sessionID)
		c.Set("token_jti", tokenJTI)

		// Continue with the request
		c.Next()
	}
}

// RefreshTokenMiddleware is a middleware for JWT refresh token validation
func RefreshTokenMiddleware(db *gorm.DB, jwtConfig *config.JWTConfig, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get request logger
		reqLogger := utils.GetRequestLogger(c, logger)

		// Get refresh token from request body
		var requestBody struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}

		if err := c.ShouldBindJSON(&requestBody); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Refresh token is required"})
			return
		}

		// Validate the refresh token
		token, err := jwtConfig.ValidateRefreshToken(requestBody.RefreshToken)
		if err != nil {
			reqLogger.WithError(err).Warn("Invalid refresh token")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
			return
		}

		// Get claims from token
		claims, err := config.GetClaimsFromToken(token)
		if err != nil {
			reqLogger.WithError(err).Warn("Failed to get claims from refresh token")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token claims"})
			return
		}

		// Extract user ID and session ID from claims
		userIDStr, ok := claims["sub"].(string)
		if !ok {
			reqLogger.Warn("User ID not found in refresh token claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token claims"})
			return
		}

		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			reqLogger.WithError(err).Warn("Invalid user ID in refresh token claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token claims"})
			return
		}

		sessionIDStr, ok := claims["sid"].(string)
		if !ok {
			reqLogger.Warn("Session ID not found in refresh token claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token claims"})
			return
		}

		sessionID, err := uuid.Parse(sessionIDStr)
		if err != nil {
			reqLogger.WithError(err).Warn("Invalid session ID in refresh token claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token claims"})
			return
		}

		tokenJTIStr, ok := claims["jti"].(string)
		if !ok {
			reqLogger.Warn("Token JTI not found in refresh token claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token claims"})
			return
		}

		tokenJTI, err := uuid.Parse(tokenJTIStr)
		if err != nil {
			reqLogger.WithError(err).Warn("Invalid token JTI in refresh token claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token claims"})
			return
		}

		// Check if the user exists and is active
		var user model.User
		result := db.Where("id = ? AND is_active = true", userID).First(&user)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				reqLogger.WithField("user_id", userID).Warn("User not found or inactive")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User not found or inactive"})
				return
			}

			reqLogger.WithError(result.Error).Error("Failed to query user")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		// Check if the session exists and is active
		var session model.Session
		result = db.Where("id = ? AND user_id = ? AND refresh_token_jti = ? AND is_active = true AND expires_at > NOW()", sessionID, userID, tokenJTI).First(&session)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				reqLogger.WithFields(logrus.Fields{
					"user_id":    userID,
					"session_id": sessionID,
					"token_jti":  tokenJTI,
				}).Warn("Session not found, inactive, or expired")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Session not found, inactive, or expired"})
				return
			}

			reqLogger.WithError(result.Error).Error("Failed to query session")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		// Set user and session information in context
		c.Set("user_id", userID)
		c.Set("email", user.Email)
		c.Set("session_id", sessionID)
		c.Set("refresh_token_jti", tokenJTI)

		// Continue with the request
		c.Next()
	}
}