package v1

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"backend/service"
	"backend/utils"
)

// AuthHandler handles authentication-related requests
type AuthHandler struct {
	AuthService *service.AuthService
	Logger      *logrus.Logger
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(authService *service.AuthService, logger *logrus.Logger) *AuthHandler {
	return &AuthHandler{
		AuthService: authService,
		Logger:      logger,
	}
}

// @Summary Login user
// @Description Authenticate user and return JWT tokens
// @Tags auth
// @Accept json
// @Produce json
// @Param request body service.LoginRequest true "Login credentials"
// @Success 200 {object} service.TokenResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 429 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req service.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request: " + err.Error()})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call login service
	tokenResponse, user, err := h.AuthService.Login(c.Request.Context(), req, ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
		return
	}

	// Set cookies if configured to use cookies
	if utils.UseCookiesForTokens() {
		// Set access token cookie
		c.SetCookie(
			"access_token",
			tokenResponse.AccessToken,
			int(time.Until(tokenResponse.ExpiresAt).Seconds()),
			"/",
			"",   // Domain
			true, // Secure
			true, // HttpOnly
			true, // SameSite strict
		)

		// Set refresh token cookie with longer expiry
		c.SetCookie(
			"refresh_token",
			tokenResponse.RefreshToken,
			60*60*24*30, // 30 days
			"/",
			"",   // Domain
			true, // Secure
			true, // HttpOnly
			true, // SameSite strict
		)

		// Don't include tokens in response body when using cookies
		tokenResponse.AccessToken = "[stored in cookie]"
		tokenResponse.RefreshToken = "[stored in cookie]"
	}

	// Return token response
	c.JSON(http.StatusOK, tokenResponse)
}

// @Summary Refresh token
// @Description Refresh access token using refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body service.RefreshTokenRequest true "Refresh token"
// @Success 200 {object} service.TokenResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	// Check if using cookies
	if utils.UseCookiesForTokens() {
		// Get refresh token from cookie
		refreshToken, err := c.Cookie("refresh_token")
		if err != nil || refreshToken == "" {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Refresh token not found in cookie"})
			return
		}

		// Create request with token from cookie
		req := service.RefreshTokenRequest{RefreshToken: refreshToken}

		// Get client IP and user agent
		ipAddress := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")

		// Call refresh token service
		tokenResponse, err := h.AuthService.RefreshToken(c.Request.Context(), req, ipAddress, userAgent)
		if err != nil {
			c.JSON(http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
			return
		}

		// Set new cookies
		c.SetCookie(
			"access_token",
			tokenResponse.AccessToken,
			int(time.Until(tokenResponse.ExpiresAt).Seconds()),
			"/",
			"",   // Domain
			true, // Secure
			true, // HttpOnly
			true, // SameSite strict
		)

		c.SetCookie(
			"refresh_token",
			tokenResponse.RefreshToken,
			60*60*24*30, // 30 days
			"/",
			"",   // Domain
			true, // Secure
			true, // HttpOnly
			true, // SameSite strict
		)

		// Don't include tokens in response body when using cookies
		tokenResponse.AccessToken = "[stored in cookie]"
		tokenResponse.RefreshToken = "[stored in cookie]"

		// Return token response
		c.JSON(http.StatusOK, tokenResponse)
		return
	}

	// Not using cookies, get token from request body
	var req service.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request: " + err.Error()})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call refresh token service
	tokenResponse, err := h.AuthService.RefreshToken(c.Request.Context(), req, ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
		return
	}

	// Return token response
	c.JSON(http.StatusOK, tokenResponse)
}

// @Summary Register user
// @Description Register a new user
// @Tags auth
// @Accept json
// @Produce json
// @Param request body service.RegisterRequest true "Registration details"
// @Success 201 {object} UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 429 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var req service.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request: " + err.Error()})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call register service
	user, err := h.AuthService.Register(c.Request.Context(), req, ipAddress, userAgent)
	if err != nil {
		if err.Error() == "email already exists" || err.Error() == "username already exists" {
			c.JSON(http.StatusConflict, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// Create user response
	response := UserResponse{
		ID:              user.ID.String(),
		Email:           user.Email,
		Username:        user.Username,
		FirstName:       user.FirstName,
		LastName:        user.LastName,
		IsActive:        user.IsActive,
		IsEmailVerified: user.IsEmailVerified,
		CreatedAt:       user.CreatedAt,
		UpdatedAt:       user.UpdatedAt,
	}

	c.JSON(http.StatusCreated, response)
}

// @Summary Change password
// @Description Change user password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body service.ChangePasswordRequest true "Password change details"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/auth/password/change [post]
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req service.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request: " + err.Error()})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized"})
		return
	}

	// Parse user ID
	userUUID, err := uuid.Parse(userID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid user ID"})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call change password service
	if err := h.AuthService.ChangePassword(c.Request.Context(), userUUID, req, ipAddress, userAgent); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Password changed successfully"})
}

// @Summary Request password reset
// @Description Request a password reset email
// @Tags auth
// @Accept json
// @Produce json
// @Param request body service.ResetPasswordRequest true "Email address"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 429 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/auth/password/reset [post]
func (h *AuthHandler) RequestPasswordReset(c *gin.Context) {
	var req service.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request: " + err.Error()})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call request password reset service
	if err := h.AuthService.RequestPasswordReset(c.Request.Context(), req, ipAddress, userAgent); err != nil {
		// Don't reveal specific errors to prevent user enumeration
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to process request"})
		return
	}

	// Always return success even if email doesn't exist to prevent user enumeration
	c.JSON(http.StatusOK, SuccessResponse{Message: "If your email exists in our system, you will receive a password reset link"})
}

// @Summary Confirm password reset
// @Description Reset password using token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body service.ConfirmResetPasswordRequest true "Reset details"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/auth/password/reset/confirm [post]
func (h *AuthHandler) ConfirmPasswordReset(c *gin.Context) {
	var req service.ConfirmResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request: " + err.Error()})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call confirm password reset service
	if err := h.AuthService.ConfirmPasswordReset(c.Request.Context(), req, ipAddress, userAgent); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Password reset successfully"})
}

// @Summary Logout
// @Description Logout user by invalidating current session
// @Tags auth
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized"})
		return
	}

	// Get session ID from context
	sessionID, exists := c.Get("session_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized"})
		return
	}

	// Parse UUIDs
	userUUID, err := uuid.Parse(userID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid user ID"})
		return
	}

	sessionUUID, err := uuid.Parse(sessionID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid session ID"})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call logout service
	if err := h.AuthService.Logout(c.Request.Context(), userUUID, sessionUUID, ipAddress, userAgent); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	// Clear cookies if using cookies
	if utils.UseCookiesForTokens() {
		c.SetCookie("access_token", "", -1, "/", "", true, true, true)
		c.SetCookie("refresh_token", "", -1, "/", "", true, true, true)
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Logged out successfully"})
}

// @Summary Logout all sessions
// @Description Logout user from all sessions
// @Tags auth
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/auth/logout/all [post]
func (h *AuthHandler) LogoutAllSessions(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized"})
		return
	}

	// Parse user ID
	userUUID, err := uuid.Parse(userID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid user ID"})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call logout all sessions service
	if err := h.AuthService.LogoutAllSessions(c.Request.Context(), userUUID, ipAddress, userAgent); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	// Clear cookies if using cookies
	if utils.UseCookiesForTokens() {
		c.SetCookie("access_token", "", -1, "/", "", true, true, true)
		c.SetCookie("refresh_token", "", -1, "/", "", true, true, true)
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Logged out from all sessions successfully"})
}

// @Summary Logout other sessions
// @Description Logout user from all sessions except current one
// @Tags auth
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/auth/logout/others [post]
func (h *AuthHandler) LogoutOtherSessions(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized"})
		return
	}

	// Get session ID from context
	sessionID, exists := c.Get("session_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized"})
		return
	}

	// Parse UUIDs
	userUUID, err := uuid.Parse(userID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid user ID"})
		return
	}

	sessionUUID, err := uuid.Parse(sessionID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid session ID"})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call logout other sessions service
	if err := h.AuthService.LogoutOtherSessions(c.Request.Context(), userUUID, sessionUUID, ipAddress, userAgent); err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Logged out from other sessions successfully"})
}

// @Summary Get user sessions
// @Description Get all active sessions for the current user
// @Tags auth
// @Produce json
// @Success 200 {array} service.UserSessionResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/auth/sessions [get]
func (h *AuthHandler) GetUserSessions(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized"})
		return
	}

	// Get session ID from context
	sessionID, exists := c.Get("session_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized"})
		return
	}

	// Parse UUIDs
	userUUID, err := uuid.Parse(userID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid user ID"})
		return
	}

	sessionUUID, err := uuid.Parse(sessionID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid session ID"})
		return
	}

	// Call get user sessions service
	sessions, err := h.AuthService.GetUserSessions(c.Request.Context(), userUUID, &sessionUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, sessions)
}

// @Summary Verify email
// @Description Verify user email using token
// @Tags auth
// @Produce json
// @Param token query string true "Verification token"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/auth/verify-email [get]
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	// Get token from query
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Token is required"})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call verify email service
	if err := h.AuthService.VerifyEmail(c.Request.Context(), token, ipAddress, userAgent); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Email verified successfully"})
}

// @Summary Resend verification email
// @Description Resend verification email to user
// @Tags auth
// @Accept json
// @Produce json
// @Param request body service.ResetPasswordRequest true "Email address"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 429 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/auth/resend-verification [post]
func (h *AuthHandler) ResendVerificationEmail(c *gin.Context) {
	var req service.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request: " + err.Error()})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call resend verification email service
	if err := h.AuthService.ResendVerificationEmail(c.Request.Context(), req.Email, ipAddress, userAgent); err != nil {
		// Don't reveal specific errors to prevent user enumeration
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to process request"})
		return
	}

	// Always return success even if email doesn't exist to prevent user enumeration
	c.JSON(http.StatusOK, SuccessResponse{Message: "If your email exists in our system, you will receive a verification email"})
}

// @Summary Check password strength
// @Description Check the strength of a password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body service.CheckPasswordRequest true "Password to check"
// @Success 200 {object} service.PasswordStrengthResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/v1/auth/password/check-strength [post]
func (h *AuthHandler) CheckPasswordStrength(c *gin.Context) {
	var req service.CheckPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request: " + err.Error()})
		return
	}

	// Call auth service
	result := h.AuthService.CheckPasswordStrength(c.Request.Context(), req.Password)

	c.JSON(http.StatusOK, result)
}

// RegisterRoutes registers the auth routes
func (h *AuthHandler) RegisterRoutes(router *gin.RouterGroup) {
	authGroup := router.Group("/auth")
	{
		authGroup.POST("/login", h.Login)
		authGroup.POST("/refresh", h.RefreshToken)
		authGroup.POST("/register", h.Register)
		authGroup.POST("/password/reset", h.RequestPasswordReset)
		authGroup.POST("/password/reset/confirm", h.ConfirmPasswordReset)
		authGroup.GET("/verify-email", h.VerifyEmail)
		authGroup.POST("/resend-verification", h.ResendVerificationEmail)
		authGroup.POST("/password/check-strength", h.CheckPasswordStrength)

		// Protected routes
		authGroup.Use(AuthMiddleware())
		{
			authGroup.POST("/password/change", h.ChangePassword)
			authGroup.POST("/logout", h.Logout)
			authGroup.POST("/logout/all", h.LogoutAllSessions)
			authGroup.POST("/logout/others", h.LogoutOtherSessions)
			authGroup.GET("/sessions", h.GetUserSessions)
		}
	}
}
