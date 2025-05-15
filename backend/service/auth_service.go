package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"backend/config"
	"backend/model"
	"backend/repository"
	"backend/utils"
)

// AuthService handles authentication operations
type AuthService struct {
	UserRepo   *repository.UserRepository
	AuditRepo  *repository.AuditRepository
	Config     *config.Config
	Logger     *logrus.Logger
	Validator  *utils.Validator
}

// NewAuthService creates a new authentication service
func NewAuthService(
	userRepo *repository.UserRepository,
	auditRepo *repository.AuditRepository,
	config *config.Config,
	logger *logrus.Logger,
	validator *utils.Validator,
) *AuthService {
	return &AuthService{
		UserRepo:   userRepo,
		AuditRepo:  auditRepo,
		Config:     config,
		Logger:     logger,
		Validator:  validator,
	}
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
	DeviceName string `json:"device_name" binding:"omitempty,max=255"`
	DeviceType string `json:"device_type" binding:"omitempty,max=50"`
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Username  string `json:"username" binding:"required,username,min=3,max=50"`
	Password  string `json:"password" binding:"required,password,min=12"`
	FirstName string `json:"first_name" binding:"required,nohtml,min=1,max=50"`
	LastName  string `json:"last_name" binding:"required,nohtml,min=1,max=50"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,password,min=12"`
	ConfirmPassword string `json:"confirm_password" binding:"required,eqfield=NewPassword"`
}

// ResetPasswordRequest represents a password reset request
type ResetPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ConfirmResetPasswordRequest represents a password reset confirmation request
type ConfirmResetPasswordRequest struct {
	Token           string `json:"token" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,password,min=12"`
	ConfirmPassword string `json:"confirm_password" binding:"required,eqfield=NewPassword"`
}

// RefreshTokenRequest represents a token refresh request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// TokenResponse represents a token response
type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// UserSessionResponse represents a user session response
type UserSessionResponse struct {
	ID         string    `json:"id"`
	DeviceName string    `json:"device_name,omitempty"`
	DeviceType string    `json:"device_type,omitempty"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	LastActive time.Time `json:"last_active"`
	CreatedAt  time.Time `json:"created_at"`
	IsCurrentSession bool `json:"is_current_session"`
}

// Login authenticates a user and returns tokens
func (s *AuthService) Login(ctx context.Context, req LoginRequest, ipAddress, userAgent string) (*TokenResponse, *model.User, error) {
	// Get user by email
	user, err := s.UserRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		// Record failed login attempt
		s.recordFailedLogin(ctx, req.Email, ipAddress, userAgent, "user_not_found")
		return nil, nil, errors.New("invalid email or password")
	}

	// Check if user is active
	if !user.IsActive {
		// Record failed login attempt
		s.recordFailedLogin(ctx, req.Email, ipAddress, userAgent, "account_inactive")
		return nil, nil, errors.New("account is inactive")
	}

	// Check if account is locked
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		// Record failed login attempt
		s.recordFailedLogin(ctx, req.Email, ipAddress, userAgent, "account_locked")
		return nil, nil, fmt.Errorf("account is locked until %s", user.LockedUntil.Format(time.RFC3339))
	}

	// Verify password
	valid, err := utils.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil || !valid {
		// Record failed login attempt
		s.recordFailedLogin(ctx, req.Email, ipAddress, userAgent, "invalid_password")

		// Check if we need to lock the account
		failedAttempts, err := s.UserRepo.GetRecentFailedLoginAttempts(ctx, user.ID, time.Now().Add(-24*time.Hour))
		if err == nil && len(failedAttempts) >= s.Config.Security.MaxLoginAttempts {
			// Lock account
			lockDuration := time.Duration(s.Config.Security.AccountLockDuration) * time.Minute
			lockUntil := time.Now().Add(lockDuration)
			user.LockedUntil = &lockUntil
			_ = s.UserRepo.Update(ctx, user)

			// Create security event for account lock
			securityEvent := &model.SecurityEvent{
				UserID:      &user.ID,
				EventType:   "account_locked",
				Description: fmt.Sprintf("Account locked until %s due to too many failed login attempts", lockUntil.Format(time.RFC3339)),
				IPAddress:   ipAddress,
				UserAgent:   userAgent,
				CreatedAt:   time.Now(),
			}
			_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)
		}

		return nil, nil, errors.New("invalid email or password")
	}

	// Check if password is expired
	if user.PasswordChangedAt != nil {
		passwordAge := time.Since(*user.PasswordChangedAt)
		passwordMaxAge := time.Duration(s.Config.Security.PasswordExpiryDays) * 24 * time.Hour
		if passwordAge > passwordMaxAge {
			// Record failed login attempt
			s.recordFailedLogin(ctx, req.Email, ipAddress, userAgent, "password_expired")
			return nil, nil, errors.New("password has expired, please reset your password")
		}
	}

	// Create session
	session := &model.Session{
		UserID:     user.ID,
		DeviceName: req.DeviceName,
		DeviceType: req.DeviceType,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		LastActive: time.Now(),
		ExpiresAt:  time.Now().Add(time.Duration(s.Config.JWT.RefreshTokenExpiryHours) * time.Hour),
		IsActive:   true,
	}

	// Check if we need to enforce single session
	if s.Config.Security.EnforceSingleSession {
		// Deactivate all other sessions
		if err := s.UserRepo.DeactivateAllUserSessions(ctx, user.ID); err != nil {
			s.Logger.WithError(err).Error("Failed to deactivate user sessions")
		}
	}

	// Save session
	if err := s.UserRepo.CreateSession(ctx, session); err != nil {
		return nil, nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.UserRepo.Update(ctx, user); err != nil {
		s.Logger.WithError(err).Error("Failed to update last login time")
	}

	// Generate tokens
	accessToken, refreshToken, expiresAt, err := s.generateTokens(user, session.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &user.ID,
		EventType:   "login_success",
		Description: fmt.Sprintf("User logged in: %s", user.Email),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Return tokens
	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		TokenType:    "Bearer",
	}, user, nil
}

// RefreshToken refreshes an access token using a refresh token
func (s *AuthService) RefreshToken(ctx context.Context, req RefreshTokenRequest, ipAddress, userAgent string) (*TokenResponse, error) {
	// Validate refresh token
	claims, err := utils.ValidateToken(req.RefreshToken, s.Config.JWT.RefreshTokenSecret)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Extract user ID and session ID from claims
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		return nil, errors.New("invalid refresh token")
	}

	sessionIDStr, ok := claims["session_id"].(string)
	if !ok {
		return nil, errors.New("invalid refresh token")
	}

	// Parse UUIDs
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Get user
	user, err := s.UserRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, errors.New("account is inactive")
	}

	// Get session
	session, err := s.UserRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		return nil, errors.New("session not found")
	}

	// Check if session is active
	if !session.IsActive {
		return nil, errors.New("session is inactive")
	}

	// Check if session has expired
	if session.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("session has expired")
	}

	// Update session last active time
	session.LastActive = time.Now()
	if err := s.UserRepo.UpdateSession(ctx, session); err != nil {
		s.Logger.WithError(err).Error("Failed to update session last active time")
	}

	// Generate new tokens
	accessToken, refreshToken, expiresAt, err := s.generateTokens(user, session.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &user.ID,
		EventType:   "token_refreshed",
		Description: fmt.Sprintf("Token refreshed for user: %s", user.Email),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Return tokens
	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		TokenType:    "Bearer",
	}, nil
}

// Register registers a new user
func (s *AuthService) Register(ctx context.Context, req RegisterRequest, ipAddress, userAgent string) (*model.User, error) {
	// Check if email already exists
	_, err := s.UserRepo.GetByEmail(ctx, req.Email)
	if err == nil {
		return nil, errors.New("email already exists")
	}

	// Check if username already exists
	_, err = s.UserRepo.GetByUsername(ctx, req.Username)
	if err == nil {
		return nil, errors.New("username already exists")
	}

	// Validate password strength
	valid, message := utils.ValidatePasswordStrength(req.Password, s.Config.Security.MinPasswordLength)
	if !valid {
		return nil, errors.New(message)
	}

	// Hash password
	passwordHash, err := utils.HashPassword(req.Password, utils.DefaultPasswordConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	now := time.Now()
	user := &model.User{
		Email:             req.Email,
		Username:          req.Username,
		PasswordHash:      passwordHash,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		IsActive:          true,
		IsEmailVerified:   false,
		PasswordChangedAt: &now,
	}

	// Save user
	if err := s.UserRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Add password to history
	if err := s.UserRepo.AddPasswordHistory(ctx, user.ID, passwordHash); err != nil {
		s.Logger.WithError(err).Error("Failed to add password to history")
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &user.ID,
		EventType:   "user_registered",
		Description: fmt.Sprintf("User registered: %s (%s)", user.Username, user.Email),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// TODO: Send verification email

	return user, nil
}

// ChangePassword changes a user's password
func (s *AuthService) ChangePassword(ctx context.Context, userID uuid.UUID, req ChangePasswordRequest, ipAddress, userAgent string) error {
	// Get user
	user, err := s.UserRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.New("user not found")
	}

	// Verify current password
	valid, err := utils.VerifyPassword(req.CurrentPassword, user.PasswordHash)
	if err != nil || !valid {
		// Create security event
		securityEvent := &model.SecurityEvent{
			UserID:      &user.ID,
			EventType:   "password_change_failed",
			Description: "Failed password change attempt: incorrect current password",
			IPAddress:   ipAddress,
			UserAgent:   userAgent,
			CreatedAt:   time.Now(),
		}
		_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

		return errors.New("current password is incorrect")
	}

	// Validate new password strength
	valid, message := utils.ValidatePasswordStrength(req.NewPassword, s.Config.Security.MinPasswordLength)
	if !valid {
		return errors.New(message)
	}

	// Check if new password is different from current password
	if req.CurrentPassword == req.NewPassword {
		return errors.New("new password must be different from current password")
	}

	// Check password history
	passwordHistory, err := s.UserRepo.GetPasswordHistory(ctx, user.ID, s.Config.Security.PasswordHistorySize)
	if err == nil {
		for _, history := range passwordHistory {
			valid, _ := utils.VerifyPassword(req.NewPassword, history.PasswordHash)
			if valid {
				return errors.New("new password cannot be the same as any of your recent passwords")
			}
		}
	}

	// Hash new password
	passwordHash, err := utils.HashPassword(req.NewPassword, utils.DefaultPasswordConfig())
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update user password
	now := time.Now()
	user.PasswordHash = passwordHash
	user.PasswordChangedAt = &now
	if err := s.UserRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Add password to history
	if err := s.UserRepo.AddPasswordHistory(ctx, user.ID, passwordHash); err != nil {
		s.Logger.WithError(err).Error("Failed to add password to history")
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &user.ID,
		EventType:   "password_changed",
		Description: "User changed their password",
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Optionally invalidate all sessions except current one
	if s.Config.Security.InvalidateSessionsOnPasswordChange {
		// Get current session ID from context
		sessionID, ok := ctx.Value("session_id").(uuid.UUID)
		if ok {
			// Deactivate all other sessions
			if err := s.UserRepo.DeactivateUserSessionsExcept(ctx, user.ID, sessionID); err != nil {
				s.Logger.WithError(err).Error("Failed to deactivate user sessions")
			}
		} else {
			// Deactivate all sessions
			if err := s.UserRepo.DeactivateAllUserSessions(ctx, user.ID); err != nil {
				s.Logger.WithError(err).Error("Failed to deactivate user sessions")
			}
		}
	}

	return nil
}

// RequestPasswordReset initiates a password reset
func (s *AuthService) RequestPasswordReset(ctx context.Context, req ResetPasswordRequest, ipAddress, userAgent string) error {
	// Get user by email
	user, err := s.UserRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		// Don't reveal that the email doesn't exist
		return nil
	}

	// Generate reset token
	resetToken := uuid.New().String()

	// Set expiry time
	expiresAt := time.Now().Add(time.Duration(s.Config.Security.PasswordResetExpiryMinutes) * time.Minute)

	// Save reset token
	if err := s.UserRepo.CreatePasswordReset(ctx, user.ID, resetToken, expiresAt); err != nil {
		return fmt.Errorf("failed to create password reset: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &user.ID,
		EventType:   "password_reset_requested",
		Description: fmt.Sprintf("Password reset requested for user: %s", user.Email),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// TODO: Send password reset email with token

	return nil
}

// ConfirmPasswordReset completes a password reset
func (s *AuthService) ConfirmPasswordReset(ctx context.Context, req ConfirmResetPasswordRequest, ipAddress, userAgent string) error {
	// Get password reset by token
	reset, err := s.UserRepo.GetPasswordResetByToken(ctx, req.Token)
	if err != nil {
		return errors.New("invalid or expired reset token")
	}

	// Check if token has expired
	if reset.ExpiresAt.Before(time.Now()) {
		return errors.New("reset token has expired")
	}

	// Get user
	user, err := s.UserRepo.GetByID(ctx, reset.UserID)
	if err != nil {
		return errors.New("user not found")
	}

	// Validate new password strength
	valid, message := utils.ValidatePasswordStrength(req.NewPassword, s.Config.Security.MinPasswordLength)
	if !valid {
		return errors.New(message)
	}

	// Check password history
	passwordHistory, err := s.UserRepo.GetPasswordHistory(ctx, user.ID, s.Config.Security.PasswordHistorySize)
	if err == nil {
		for _, history := range passwordHistory {
			valid, _ := utils.VerifyPassword(req.NewPassword, history.PasswordHash)
			if valid {
				return errors.New("new password cannot be the same as any of your recent passwords")
			}
		}
	}

	// Hash new password
	passwordHash, err := utils.HashPassword(req.NewPassword, utils.DefaultPasswordConfig())
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update user password
	now := time.Now()
	user.PasswordHash = passwordHash
	user.PasswordChangedAt = &now
	if err := s.UserRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Add password to history
	if err := s.UserRepo.AddPasswordHistory(ctx, user.ID, passwordHash); err != nil {
		s.Logger.WithError(err).Error("Failed to add password to history")
	}

	// Mark reset token as used
	reset.UsedAt = &now
	if err := s.UserRepo.UpdatePasswordReset(ctx, reset); err != nil {
		s.Logger.WithError(err).Error("Failed to mark reset token as used")
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &user.ID,
		EventType:   "password_reset_completed",
		Description: fmt.Sprintf("Password reset completed for user: %s", user.Email),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Deactivate all user sessions
	if err := s.UserRepo.DeactivateAllUserSessions(ctx, user.ID); err != nil {
		s.Logger.WithError(err).Error("Failed to deactivate user sessions")
	}

	return nil
}

// Logout logs out a user by deactivating their session
func (s *AuthService) Logout(ctx context.Context, userID, sessionID uuid.UUID, ipAddress, userAgent string) error {
	// Get session
	session, err := s.UserRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		return errors.New("session not found")
	}

	// Check if session belongs to user
	if session.UserID != userID {
		return errors.New("session does not belong to user")
	}

	// Deactivate session
	session.IsActive = false
	if err := s.UserRepo.UpdateSession(ctx, session); err != nil {
		return fmt.Errorf("failed to deactivate session: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &userID,
		EventType:   "logout",
		Description: "User logged out",
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	return nil
}

// LogoutAllSessions logs out a user from all sessions
func (s *AuthService) LogoutAllSessions(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) error {
	// Deactivate all user sessions
	if err := s.UserRepo.DeactivateAllUserSessions(ctx, userID); err != nil {
		return fmt.Errorf("failed to deactivate user sessions: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &userID,
		EventType:   "logout_all_sessions",
		Description: "User logged out from all sessions",
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	return nil
}

// LogoutOtherSessions logs out a user from all sessions except the current one
func (s *AuthService) LogoutOtherSessions(ctx context.Context, userID, sessionID uuid.UUID, ipAddress, userAgent string) error {
	// Deactivate all user sessions except current one
	if err := s.UserRepo.DeactivateUserSessionsExcept(ctx, userID, sessionID); err != nil {
		return fmt.Errorf("failed to deactivate user sessions: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &userID,
		EventType:   "logout_other_sessions",
		Description: "User logged out from all other sessions",
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	return nil
}

// GetUserSessions gets all sessions for a user
func (s *AuthService) GetUserSessions(ctx context.Context, userID uuid.UUID, currentSessionID *uuid.UUID) ([]UserSessionResponse, error) {
	// Get user sessions
	sessions, err := s.UserRepo.GetUserSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	// Convert to response format
	response := make([]UserSessionResponse, len(sessions))
	for i, session := range sessions {
		response[i] = UserSessionResponse{
			ID:         session.ID.String(),
			DeviceName: session.DeviceName,
			DeviceType: session.DeviceType,
			IPAddress:  session.IPAddress,
			UserAgent:  session.UserAgent,
			LastActive: session.LastActive,
			CreatedAt:  session.CreatedAt,
			IsCurrentSession: currentSessionID != nil && session.ID == *currentSessionID,
		}
	}

	return response, nil
}

// VerifyEmail verifies a user's email address
func (s *AuthService) VerifyEmail(ctx context.Context, token string, ipAddress, userAgent string) error {
	// Get email verification by token
	verification, err := s.UserRepo.GetEmailVerificationByToken(ctx, token)
	if err != nil {
		return errors.New("invalid or expired verification token")
	}

	// Check if token has expired
	if verification.ExpiresAt.Before(time.Now()) {
		return errors.New("verification token has expired")
	}

	// Get user
	user, err := s.UserRepo.GetByID(ctx, verification.UserID)
	if err != nil {
		return errors.New("user not found")
	}

	// Update user email verification status
	user.IsEmailVerified = true
	if err := s.UserRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update email verification status: %w", err)
	}

	// Mark verification token as used
	now := time.Now()
	verification.UsedAt = &now
	if err := s.UserRepo.UpdateEmailVerification(ctx, verification); err != nil {
		s.Logger.WithError(err).Error("Failed to mark verification token as used")
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &user.ID,
		EventType:   "email_verified",
		Description: fmt.Sprintf("Email verified for user: %s", user.Email),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	return nil
}

// ResendVerificationEmail resends a verification email
func (s *AuthService) ResendVerificationEmail(ctx context.Context, email string, ipAddress, userAgent string) error {
	// Get user by email
	user, err := s.UserRepo.GetByEmail(ctx, email)
	if err != nil {
		// Don't reveal that the email doesn't exist
		return nil
	}

	// Check if email is already verified
	if user.IsEmailVerified {
		return errors.New("email is already verified")
	}

	// Generate verification token
	verificationToken := uuid.New().String()

	// Set expiry time
	expiresAt := time.Now().Add(time.Duration(s.Config.Security.EmailVerificationExpiryHours) * time.Hour)

	// Save verification token
	if err := s.UserRepo.CreateEmailVerification(ctx, user.ID, verificationToken, expiresAt); err != nil {
		return fmt.Errorf("failed to create email verification: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &user.ID,
		EventType:   "verification_email_sent",
		Description: fmt.Sprintf("Verification email sent to: %s", user.Email),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// TODO: Send verification email with token

	return nil
}

// Helper function to record failed login attempts
func (s *AuthService) recordFailedLogin(ctx context.Context, email, ipAddress, userAgent, reason string) {
	// Get user by email
	user, err := s.UserRepo.GetByEmail(ctx, email)
	if err != nil {
		// User not found, still record the attempt but without user ID
		failedAttempt := &model.FailedLoginAttempt{
			Email:     email,
			IPAddress: ipAddress,
			UserAgent: userAgent,
			Reason:    reason,
			CreatedAt: time.Now(),
		}
		_ = s.UserRepo.CreateFailedLoginAttempt(ctx, failedAttempt)

		// Create security event without user ID
		securityEvent := &model.SecurityEvent{
			EventType:   "login_failed",
			Description: fmt.Sprintf("Failed login attempt for email: %s (Reason: %s)", email, reason),
			IPAddress:   ipAddress,
			UserAgent:   userAgent,
			CreatedAt:   time.Now(),
		}
		_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)
		return
	}

	// User found, record the attempt with user ID
	failedAttempt := &model.FailedLoginAttempt{
		UserID:    &user.ID,
		Email:     email,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Reason:    reason,
		CreatedAt: time.Now(),
	}
	_ = s.UserRepo.CreateFailedLoginAttempt(ctx, failedAttempt)

	// Create security event with user ID
	securityEvent := &model.SecurityEvent{
		UserID:      &user.ID,
		EventType:   "login_failed",
		Description: fmt.Sprintf("Failed login attempt for user: %s (Reason: %s)", user.Username, reason),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)
}

// Helper function to generate access and refresh tokens
func (s *AuthService) generateTokens(user *model.User, sessionID uuid.UUID) (string, string, time.Time, error) {
	// Set token expiry times
	accessTokenExpiry := time.Now().Add(time.Duration(s.Config.JWT.AccessTokenExpiryMinutes) * time.Minute)
	refreshTokenExpiry := time.Now().Add(time.Duration(s.Config.JWT.RefreshTokenExpiryHours) * time.Hour)

	// Create access token claims
	accessTokenClaims := map[string]interface{}{
		"user_id":    user.ID.String(),
		"email":      user.Email,
		"username":   user.Username,
		"session_id": sessionID.String(),
		"issued_at":  time.Now().Unix(),
		"expires_at": accessTokenExpiry.Unix(),
		"issuer":     s.Config.JWT.Issuer,
		"subject":    user.ID.String(),
	}

	// Create refresh token claims
	refreshTokenClaims := map[string]interface{}{
		"user_id":    user.ID.String(),
		"session_id": sessionID.String(),
		"issued_at":  time.Now().Unix(),
		"expires_at": refreshTokenExpiry.Unix(),
		"issuer":     s.Config.JWT.Issuer,
		"subject":    user.ID.String(),
	}

	// Generate access token
	accessToken, err := utils.GenerateToken(accessTokenClaims, s.Config.JWT.AccessTokenSecret, accessTokenExpiry)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := utils.GenerateToken(refreshTokenClaims, s.Config.JWT.RefreshTokenSecret, refreshTokenExpiry)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return accessToken, refreshToken, accessTokenExpiry, nil
}