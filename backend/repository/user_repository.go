package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"backend/model"
)

// UserRepository handles database operations for users
type UserRepository struct {
	DB *gorm.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{DB: db}
}

// Create creates a new user
func (r *UserRepository) Create(ctx context.Context, user *model.User) error {
	return r.DB.WithContext(ctx).Create(user).Error
}

// GetByID gets a user by ID
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	var user model.User
	result := r.DB.WithContext(ctx).Where("id = ?", id).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

// GetByEmail gets a user by email
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User
	result := r.DB.WithContext(ctx).Where("email = ?", email).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

// GetByUsername gets a user by username
func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*model.User, error) {
	var user model.User
	result := r.DB.WithContext(ctx).Where("username = ?", username).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

// Update updates a user
func (r *UserRepository) Update(ctx context.Context, user *model.User) error {
	user.UpdatedAt = time.Now()
	return r.DB.WithContext(ctx).Save(user).Error
}

// Delete soft deletes a user
func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.DB.WithContext(ctx).Model(&model.User{}).Where("id = ?", id).Update("deleted_at", time.Now()).Error
}

// List lists users with pagination
func (r *UserRepository) List(ctx context.Context, page, pageSize int) ([]model.User, int64, error) {
	var users []model.User
	var total int64

	// Get total count
	if err := r.DB.WithContext(ctx).Model(&model.User{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get users with pagination
	offset := (page - 1) * pageSize
	result := r.DB.WithContext(ctx).Offset(offset).Limit(pageSize).Find(&users)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return users, total, nil
}

// Search searches users by email, username, or name
func (r *UserRepository) Search(ctx context.Context, query string, page, pageSize int) ([]model.User, int64, error) {
	var users []model.User
	var total int64

	// Build search query
	searchQuery := r.DB.WithContext(ctx).Model(&model.User{}).Where(
		"email ILIKE ? OR username ILIKE ? OR first_name ILIKE ? OR last_name ILIKE ?",
		"%"+query+"%", "%"+query+"%", "%"+query+"%", "%"+query+"%",
	)

	// Get total count
	if err := searchQuery.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get users with pagination
	offset := (page - 1) * pageSize
	result := searchQuery.Offset(offset).Limit(pageSize).Find(&users)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return users, total, nil
}

// AddToGroup adds a user to a group
func (r *UserRepository) AddToGroup(ctx context.Context, userID, groupID uuid.UUID) error {
	// Check if user exists
	var user model.User
	result := r.DB.WithContext(ctx).Where("id = ?", userID).First(&user)
	if result.Error != nil {
		return result.Error
	}

	// Check if group exists
	var group model.Group
	result = r.DB.WithContext(ctx).Where("id = ?", groupID).First(&group)
	if result.Error != nil {
		return result.Error
	}

	// Check if user is already in the group
	var userGroup model.UserGroup
	result = r.DB.WithContext(ctx).Where("user_id = ? AND group_id = ?", userID, groupID).First(&userGroup)
	if result.Error == nil {
		return errors.New("user is already in the group")
	} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return result.Error
	}

	// Add user to group
	userGroup = model.UserGroup{
		UserID:  userID,
		GroupID: groupID,
	}

	return r.DB.WithContext(ctx).Create(&userGroup).Error
}

// RemoveFromGroup removes a user from a group
func (r *UserRepository) RemoveFromGroup(ctx context.Context, userID, groupID uuid.UUID) error {
	return r.DB.WithContext(ctx).Where("user_id = ? AND group_id = ?", userID, groupID).Delete(&model.UserGroup{}).Error
}

// AssignRole assigns a role to a user
func (r *UserRepository) AssignRole(ctx context.Context, userID, roleID uuid.UUID) error {
	// Check if user exists
	var user model.User
	result := r.DB.WithContext(ctx).Where("id = ?", userID).First(&user)
	if result.Error != nil {
		return result.Error
	}

	// Check if role exists
	var role model.Role
	result = r.DB.WithContext(ctx).Where("id = ?", roleID).First(&role)
	if result.Error != nil {
		return result.Error
	}

	// Check if user already has the role
	var userRole model.UserRole
	result = r.DB.WithContext(ctx).Where("user_id = ? AND role_id = ?", userID, roleID).First(&userRole)
	if result.Error == nil {
		return errors.New("user already has the role")
	} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return result.Error
	}

	// Assign role to user
	userRole = model.UserRole{
		UserID: userID,
		RoleID: roleID,
	}

	return r.DB.WithContext(ctx).Create(&userRole).Error
}

// RemoveRole removes a role from a user
func (r *UserRepository) RemoveRole(ctx context.Context, userID, roleID uuid.UUID) error {
	return r.DB.WithContext(ctx).Where("user_id = ? AND role_id = ?", userID, roleID).Delete(&model.UserRole{}).Error
}

// GetUserGroups gets all groups for a user
func (r *UserRepository) GetUserGroups(ctx context.Context, userID uuid.UUID) ([]model.Group, error) {
	var groups []model.Group

	result := r.DB.WithContext(ctx).Raw(`
		SELECT g.* FROM groups g
		JOIN user_groups ug ON g.id = ug.group_id
		WHERE ug.user_id = ? AND g.deleted_at IS NULL AND ug.deleted_at IS NULL
	`, userID).Scan(&groups)

	if result.Error != nil {
		return nil, result.Error
	}

	return groups, nil
}

// GetUserRoles gets all roles for a user
func (r *UserRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]model.Role, error) {
	var roles []model.Role

	result := r.DB.WithContext(ctx).Raw(`
		SELECT DISTINCT r.* FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = ? AND r.deleted_at IS NULL AND ur.deleted_at IS NULL
		UNION
		SELECT DISTINCT r.* FROM roles r
		JOIN group_roles gr ON r.id = gr.role_id
		JOIN groups g ON gr.group_id = g.id
		JOIN user_groups ug ON g.id = ug.group_id
		WHERE ug.user_id = ? AND r.deleted_at IS NULL AND gr.deleted_at IS NULL
		AND g.deleted_at IS NULL AND ug.deleted_at IS NULL
	`, userID, userID).Scan(&roles)

	if result.Error != nil {
		return nil, result.Error
	}

	return roles, nil
}

// GetUserPermissions gets all permissions for a user
func (r *UserRepository) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]model.Permission, error) {
	var permissions []model.Permission

	result := r.DB.WithContext(ctx).Raw(`
		SELECT DISTINCT p.* FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN roles r ON rp.role_id = r.id
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = ? AND p.deleted_at IS NULL AND r.deleted_at IS NULL AND ur.deleted_at IS NULL AND rp.deleted_at IS NULL
		UNION
		SELECT DISTINCT p.* FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN roles r ON rp.role_id = r.id
		JOIN group_roles gr ON r.id = gr.role_id
		JOIN groups g ON gr.group_id = g.id
		JOIN user_groups ug ON g.id = ug.group_id
		WHERE ug.user_id = ? AND p.deleted_at IS NULL AND r.deleted_at IS NULL AND gr.deleted_at IS NULL
		AND g.deleted_at IS NULL AND ug.deleted_at IS NULL AND rp.deleted_at IS NULL
	`, userID, userID).Scan(&permissions)

	if result.Error != nil {
		return nil, result.Error
	}

	return permissions, nil
}

// AddPasswordHistory adds a password to the user's password history
func (r *UserRepository) AddPasswordHistory(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	passwordHistory := model.PasswordHistory{
		UserID:       userID,
		PasswordHash: passwordHash,
	}

	return r.DB.WithContext(ctx).Create(&passwordHistory).Error
}

// CheckPasswordHistory checks if a password is in the user's password history
func (r *UserRepository) CheckPasswordHistory(ctx context.Context, userID uuid.UUID, passwordHash string, limit int) (bool, error) {
	var count int64

	result := r.DB.WithContext(ctx).Model(&model.PasswordHistory{}).Where(
		"user_id = ? AND password_hash = ?", userID, passwordHash,
	).Count(&count)

	if result.Error != nil {
		return false, result.Error
	}

	return count > 0, nil
}

// RecordFailedLoginAttempt records a failed login attempt
func (r *UserRepository) RecordFailedLoginAttempt(ctx context.Context, attempt *model.FailedLoginAttempt) error {
	return r.DB.WithContext(ctx).Create(attempt).Error
}

// GetFailedLoginAttempts gets the number of failed login attempts for a user or IP address
func (r *UserRepository) GetFailedLoginAttempts(ctx context.Context, userID *uuid.UUID, ipAddress string, since time.Time) (int64, error) {
	var count int64
	query := r.DB.WithContext(ctx).Model(&model.FailedLoginAttempt{}).Where("attempt_time > ?", since)

	if userID != nil {
		query = query.Where("user_id = ?", userID)
	} else if ipAddress != "" {
		query = query.Where("ip_address = ?", ipAddress)
	} else {
		return 0, errors.New("either user ID or IP address must be provided")
	}

	result := query.Count(&count)
	if result.Error != nil {
		return 0, result.Error
	}

	return count, nil
}

// ClearFailedLoginAttempts clears failed login attempts for a user or IP address
func (r *UserRepository) ClearFailedLoginAttempts(ctx context.Context, userID *uuid.UUID, ipAddress string) error {
	query := r.DB.WithContext(ctx).Model(&model.FailedLoginAttempt{})

	if userID != nil {
		query = query.Where("user_id = ?", userID)
	} else if ipAddress != "" {
		query = query.Where("ip_address = ?", ipAddress)
	} else {
		return errors.New("either user ID or IP address must be provided")
	}

	return query.Delete(&model.FailedLoginAttempt{}).Error
}

// CreateSession creates a new session for a user
func (r *UserRepository) CreateSession(ctx context.Context, session *model.Session) error {
	return r.DB.WithContext(ctx).Create(session).Error
}

// GetSessionByID gets a session by ID
func (r *UserRepository) GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*model.Session, error) {
	var session model.Session
	result := r.DB.WithContext(ctx).Where("id = ?", sessionID).First(&session)
	if result.Error != nil {
		return nil, result.Error
	}
	return &session, nil
}

// GetSessionByTokenJTI gets a session by token JTI
func (r *UserRepository) GetSessionByTokenJTI(ctx context.Context, tokenJTI uuid.UUID) (*model.Session, error) {
	var session model.Session
	result := r.DB.WithContext(ctx).Where("token_jti = ?", tokenJTI).First(&session)
	if result.Error != nil {
		return nil, result.Error
	}
	return &session, nil
}

// GetSessionByRefreshTokenJTI gets a session by refresh token JTI
func (r *UserRepository) GetSessionByRefreshTokenJTI(ctx context.Context, refreshTokenJTI uuid.UUID) (*model.Session, error) {
	var session model.Session
	result := r.DB.WithContext(ctx).Where("refresh_token_jti = ?", refreshTokenJTI).First(&session)
	if result.Error != nil {
		return nil, result.Error
	}
	return &session, nil
}

// UpdateSession updates a session
func (r *UserRepository) UpdateSession(ctx context.Context, session *model.Session) error {
	session.UpdatedAt = time.Now()
	return r.DB.WithContext(ctx).Save(session).Error
}

// DeactivateSession deactivates a session
func (r *UserRepository) DeactivateSession(ctx context.Context, sessionID uuid.UUID) error {
	return r.DB.WithContext(ctx).Model(&model.Session{}).Where("id = ?", sessionID).Update("is_active", false).Error
}

// DeactivateAllUserSessions deactivates all sessions for a user
func (r *UserRepository) DeactivateAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	return r.DB.WithContext(ctx).Model(&model.Session{}).Where("user_id = ?", userID).Update("is_active", false).Error
}

// GetUserSessions gets all sessions for a user
func (r *UserRepository) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]model.Session, error) {
	var sessions []model.Session
	result := r.DB.WithContext(ctx).Where("user_id = ?", userID).Find(&sessions)
	if result.Error != nil {
		return nil, result.Error
	}
	return sessions, nil
}

// CountActiveSessions counts the number of active sessions for a user
func (r *UserRepository) CountActiveSessions(ctx context.Context, userID uuid.UUID) (int64, error) {
	var count int64
	result := r.DB.WithContext(ctx).Model(&model.Session{}).Where("user_id = ? AND is_active = true AND expires_at > NOW()", userID).Count(&count)
	if result.Error != nil {
		return 0, result.Error
	}
	return count, nil
}

// CreateSecurityEvent creates a new security event
func (r *UserRepository) CreateSecurityEvent(ctx context.Context, event *model.SecurityEvent) error {
	return r.DB.WithContext(ctx).Create(event).Error
}

// CreateAuditLog creates a new audit log entry
func (r *UserRepository) CreateAuditLog(ctx context.Context, log *model.AuditLog) error {
	return r.DB.WithContext(ctx).Create(log).Error
}