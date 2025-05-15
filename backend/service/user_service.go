package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"backend/model"
	"backend/repository"
	"backend/utils"
)

// UserService handles user operations
type UserService struct {
	UserRepo   *repository.UserRepository
	GroupRepo  *repository.GroupRepository
	RoleRepo   *repository.RoleRepository
	AuditRepo  *repository.AuditRepository
	Logger     *logrus.Logger
	Validator  *utils.Validator
}

// NewUserService creates a new user service
func NewUserService(
	userRepo *repository.UserRepository,
	groupRepo *repository.GroupRepository,
	roleRepo *repository.RoleRepository,
	auditRepo *repository.AuditRepository,
	logger *logrus.Logger,
	validator *utils.Validator,
) *UserService {
	return &UserService{
		UserRepo:   userRepo,
		GroupRepo:  groupRepo,
		RoleRepo:   roleRepo,
		AuditRepo:  auditRepo,
		Logger:     logger,
		Validator:  validator,
	}
}

// CreateUserRequest represents a request to create a user
type CreateUserRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Username  string `json:"username" binding:"required,username,min=3,max=50"`
	Password  string `json:"password" binding:"required,password,min=12"`
	FirstName string `json:"first_name" binding:"required,nohtml,min=1,max=50"`
	LastName  string `json:"last_name" binding:"required,nohtml,min=1,max=50"`
	IsActive  bool   `json:"is_active"`
}

// UpdateUserRequest represents a request to update a user
type UpdateUserRequest struct {
	Email     string `json:"email" binding:"omitempty,email"`
	Username  string `json:"username" binding:"omitempty,username,min=3,max=50"`
	FirstName string `json:"first_name" binding:"omitempty,nohtml,min=1,max=50"`
	LastName  string `json:"last_name" binding:"omitempty,nohtml,min=1,max=50"`
	IsActive  *bool  `json:"is_active"`
}

// UserResponse represents a user response
type UserResponse struct {
	ID               string    `json:"id"`
	Email            string    `json:"email"`
	Username         string    `json:"username"`
	FirstName        string    `json:"first_name"`
	LastName         string    `json:"last_name"`
	IsActive         bool      `json:"is_active"`
	IsEmailVerified  bool      `json:"is_email_verified"`
	LastLoginAt      *string   `json:"last_login_at,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	Groups           []string  `json:"groups,omitempty"`
	Roles            []string  `json:"roles,omitempty"`
	DirectRoles      []string  `json:"direct_roles,omitempty"`
	InheritedRoles   []string  `json:"inherited_roles,omitempty"`
	Permissions      []string  `json:"permissions,omitempty"`
}

// UsersResponse represents a paginated list of users
type UsersResponse struct {
	Users      []UserResponse `json:"users"`
	Total      int64          `json:"total"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalPages int            `json:"total_pages"`
}

// GetUserByID gets a user by ID
func (s *UserService) GetUserByID(ctx context.Context, id string) (*UserResponse, error) {
	// Parse user ID
	userID, err := uuid.Parse(id)
	if err != nil {
		return nil, errors.New("invalid user ID")
	}

	// Get user
	user, err := s.UserRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Get user groups
	groups, err := s.UserRepo.GetUserGroups(ctx, user.ID)
	if err != nil {
		s.Logger.WithError(err).Error("Failed to get user groups")
		groups = []model.Group{}
	}

	// Get user roles (direct and inherited)
	roles, err := s.UserRepo.GetUserRoles(ctx, user.ID)
	if err != nil {
		s.Logger.WithError(err).Error("Failed to get user roles")
		roles = []model.Role{}
	}

	// Get direct roles
	directRoles, err := s.UserRepo.DB.Raw(`
		SELECT r.* FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = ? AND r.deleted_at IS NULL AND ur.deleted_at IS NULL
	`, user.ID).Scan(&roles).Error
	if err != nil {
		s.Logger.WithError(err).Error("Failed to get direct user roles")
		directRoles = []model.Role{}
	}

	// Get inherited roles
	inheritedRoles, err := s.UserRepo.DB.Raw(`
		SELECT DISTINCT r.* FROM roles r
		JOIN group_roles gr ON r.id = gr.role_id
		JOIN groups g ON gr.group_id = g.id
		JOIN user_groups ug ON g.id = ug.group_id
		WHERE ug.user_id = ? AND r.deleted_at IS NULL AND gr.deleted_at IS NULL
		AND g.deleted_at IS NULL AND ug.deleted_at IS NULL
	`, user.ID).Scan(&roles).Error
	if err != nil {
		s.Logger.WithError(err).Error("Failed to get inherited user roles")
		inheritedRoles = []model.Role{}
	}

	// Get user permissions
	permissions, err := s.UserRepo.GetUserPermissions(ctx, user.ID)
	if err != nil {
		s.Logger.WithError(err).Error("Failed to get user permissions")
		permissions = []model.Permission{}
	}

	// Format last login time
	var lastLoginStr *string
	if user.LastLoginAt != nil {
		tmp := user.LastLoginAt.Format(time.RFC3339)
		lastLoginStr = &tmp
	}

	// Create response
	response := &UserResponse{
		ID:              user.ID.String(),
		Email:           user.Email,
		Username:        user.Username,
		FirstName:       user.FirstName,
		LastName:        user.LastName,
		IsActive:        user.IsActive,
		IsEmailVerified: user.IsEmailVerified,
		LastLoginAt:     lastLoginStr,
		CreatedAt:       user.CreatedAt,
		UpdatedAt:       user.UpdatedAt,
		Groups:          make([]string, len(groups)),
		Roles:           make([]string, len(roles)),
		DirectRoles:     make([]string, len(directRoles)),
		InheritedRoles:  make([]string, len(inheritedRoles)),
		Permissions:     make([]string, len(permissions)),
	}

	// Add group names
	for i, group := range groups {
		response.Groups[i] = group.Name
	}

	// Add role names
	for i, role := range roles {
		response.Roles[i] = role.Name
	}

	// Add direct role names
	for i, role := range directRoles {
		response.DirectRoles[i] = role.Name
	}

	// Add inherited role names
	for i, role := range inheritedRoles {
		response.InheritedRoles[i] = role.Name
	}

	// Add permission names
	for i, permission := range permissions {
		response.Permissions[i] = permission.Name
	}

	return response, nil
}

// ListUsers lists users with pagination
func (s *UserService) ListUsers(ctx context.Context, page, pageSize int) (*UsersResponse, error) {
	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	// Get users with pagination
	users, total, err := s.UserRepo.List(ctx, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	// Calculate total pages
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	// Create response
	response := &UsersResponse{
		Users:      make([]UserResponse, len(users)),
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}

	// Convert users to response format
	for i, user := range users {
		// Format last login time
		var lastLoginStr *string
		if user.LastLoginAt != nil {
			tmp := user.LastLoginAt.Format(time.RFC3339)
			lastLoginStr = &tmp
		}

		response.Users[i] = UserResponse{
			ID:              user.ID.String(),
			Email:           user.Email,
			Username:        user.Username,
			FirstName:       user.FirstName,
			LastName:        user.LastName,
			IsActive:        user.IsActive,
			IsEmailVerified: user.IsEmailVerified,
			LastLoginAt:     lastLoginStr,
			CreatedAt:       user.CreatedAt,
			UpdatedAt:       user.UpdatedAt,
		}
	}

	return response, nil
}

// SearchUsers searches users by email, username, or name
func (s *UserService) SearchUsers(ctx context.Context, query string, page, pageSize int) (*UsersResponse, error) {
	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	// Search users with pagination
	users, total, err := s.UserRepo.Search(ctx, query, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("failed to search users: %w", err)
	}

	// Calculate total pages
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	// Create response
	response := &UsersResponse{
		Users:      make([]UserResponse, len(users)),
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}

	// Convert users to response format
	for i, user := range users {
		// Format last login time
		var lastLoginStr *string
		if user.LastLoginAt != nil {
			tmp := user.LastLoginAt.Format(time.RFC3339)
			lastLoginStr = &tmp
		}

		response.Users[i] = UserResponse{
			ID:              user.ID.String(),
			Email:           user.Email,
			Username:        user.Username,
			FirstName:       user.FirstName,
			LastName:        user.LastName,
			IsActive:        user.IsActive,
			IsEmailVerified: user.IsEmailVerified,
			LastLoginAt:     lastLoginStr,
			CreatedAt:       user.CreatedAt,
			UpdatedAt:       user.UpdatedAt,
		}
	}

	return response, nil
}

// CreateUser creates a new user
func (s *UserService) CreateUser(ctx context.Context, req CreateUserRequest, creatorID uuid.UUID, ipAddress, userAgent string) (*UserResponse, error) {
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
	valid, message := utils.ValidatePasswordStrength(req.Password, 12)
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
		IsActive:          req.IsActive,
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
		UserID:      &creatorID,
		EventType:   "user_created",
		Description: fmt.Sprintf("User created: %s (%s)", user.Username, user.Email),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	userJSON, _ := json.Marshal(user)
	auditLog := &model.AuditLog{
		UserID:       &creatorID,
		Action:       "create",
		ResourceType: "user",
		ResourceID:   &user.ID,
		NewValues:    string(userJSON),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	// Return user response
	return &UserResponse{
		ID:              user.ID.String(),
		Email:           user.Email,
		Username:        user.Username,
		FirstName:       user.FirstName,
		LastName:        user.LastName,
		IsActive:        user.IsActive,
		IsEmailVerified: user.IsEmailVerified,
		CreatedAt:       user.CreatedAt,
		UpdatedAt:       user.UpdatedAt,
	}, nil
}

// UpdateUser updates a user
func (s *UserService) UpdateUser(ctx context.Context, id string, req UpdateUserRequest, updaterID uuid.UUID, ipAddress, userAgent string) (*UserResponse, error) {
	// Parse user ID
	userID, err := uuid.Parse(id)
	if err != nil {
		return nil, errors.New("invalid user ID")
	}

	// Get user
	user, err := s.UserRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Store old values for audit log
	oldUserJSON, _ := json.Marshal(user)

	// Update email if provided
	if req.Email != "" && req.Email != user.Email {
		// Check if email already exists
		_, err := s.UserRepo.GetByEmail(ctx, req.Email)
		if err == nil {
			return nil, errors.New("email already exists")
		}

		user.Email = req.Email
		user.IsEmailVerified = false
	}

	// Update username if provided
	if req.Username != "" && req.Username != user.Username {
		// Check if username already exists
		_, err := s.UserRepo.GetByUsername(ctx, req.Username)
		if err == nil {
			return nil, errors.New("username already exists")
		}

		user.Username = req.Username
	}

	// Update first name if provided
	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}

	// Update last name if provided
	if req.LastName != "" {
		user.LastName = req.LastName
	}

	// Update active status if provided
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}

	// Save user
	if err := s.UserRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &updaterID,
		EventType:   "user_updated",
		Description: fmt.Sprintf("User updated: %s (%s)", user.Username, user.Email),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	newUserJSON, _ := json.Marshal(user)
	auditLog := &model.AuditLog{
		UserID:       &updaterID,
		Action:       "update",
		ResourceType: "user",
		ResourceID:   &user.ID,
		OldValues:    string(oldUserJSON),
		NewValues:    string(newUserJSON),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	// Return user response
	return &UserResponse{
		ID:              user.ID.String(),
		Email:           user.Email,
		Username:        user.Username,
		FirstName:       user.FirstName,
		LastName:        user.LastName,
		IsActive:        user.IsActive,
		IsEmailVerified: user.IsEmailVerified,
		CreatedAt:       user.CreatedAt,
		UpdatedAt:       user.UpdatedAt,
	}, nil
}

// DeleteUser soft deletes a user
func (s *UserService) DeleteUser(ctx context.Context, id string, deleterID uuid.UUID, ipAddress, userAgent string) error {
	// Parse user ID
	userID, err := uuid.Parse(id)
	if err != nil {
		return errors.New("invalid user ID")
	}

	// Get user
	user, err := s.UserRepo.GetByID(ctx, userID)
	if err != nil {
		return errors.New("user not found")
	}

	// Store old values for audit log
	oldUserJSON, _ := json.Marshal(user)

	// Delete user
	if err := s.UserRepo.Delete(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	// Deactivate all user sessions
	if err := s.UserRepo.DeactivateAllUserSessions(ctx, userID); err != nil {
		s.Logger.WithError(err).Error("Failed to deactivate user sessions")
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &deleterID,
		EventType:   "user_deleted",
		Description: fmt.Sprintf("User deleted: %s (%s)", user.Username, user.Email),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	auditLog := &model.AuditLog{
		UserID:       &deleterID,
		Action:       "delete",
		ResourceType: "user",
		ResourceID:   &user.ID,
		OldValues:    string(oldUserJSON),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	return nil
}

// AddUserToGroup adds a user to a group
func (s *UserService) AddUserToGroup(ctx context.Context, userID, groupID string, adminID uuid.UUID, ipAddress, userAgent string) error {
	// Parse IDs
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return errors.New("invalid user ID")
	}

	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		return errors.New("invalid group ID")
	}

	// Get user
	user, err := s.UserRepo.GetByID(ctx, userUUID)
	if err != nil {
		return errors.New("user not found")
	}

	// Get group
	group, err := s.GroupRepo.GetByID(ctx, groupUUID)
	if err != nil {
		return errors.New("group not found")
	}

	// Add user to group
	if err := s.UserRepo.AddToGroup(ctx, userUUID, groupUUID); err != nil {
		return fmt.Errorf("failed to add user to group: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &adminID,
		EventType:   "user_added_to_group",
		Description: fmt.Sprintf("User %s added to group %s", user.Username, group.Name),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	auditLog := &model.AuditLog{
		UserID:       &adminID,
		Action:       "add_to_group",
		ResourceType: "user",
		ResourceID:   &user.ID,
		NewValues:    fmt.Sprintf(`{"group_id":"%s","group_name":"%s"}`, group.ID, group.Name),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	return nil
}

// RemoveUserFromGroup removes a user from a group
func (s *UserService) RemoveUserFromGroup(ctx context.Context, userID, groupID string, adminID uuid.UUID, ipAddress, userAgent string) error {
	// Parse IDs
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return errors.New("invalid user ID")
	}

	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		return errors.New("invalid group ID")
	}

	// Get user
	user, err := s.UserRepo.GetByID(ctx, userUUID)
	if err != nil {
		return errors.New("user not found")
	}

	// Get group
	group, err := s.GroupRepo.GetByID(ctx, groupUUID)
	if err != nil {
		return errors.New("group not found")
	}

	// Remove user from group
	if err := s.UserRepo.RemoveFromGroup(ctx, userUUID, groupUUID); err != nil {
		return fmt.Errorf("failed to remove user from group: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &adminID,
		EventType:   "user_removed_from_group",
		Description: fmt.Sprintf("User %s removed from group %s", user.Username, group.Name),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	auditLog := &model.AuditLog{
		UserID:       &adminID,
		Action:       "remove_from_group",
		ResourceType: "user",
		ResourceID:   &user.ID,
		OldValues:    fmt.Sprintf(`{"group_id":"%s","group_name":"%s"}`, group.ID, group.Name),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	return nil
}

// AssignRoleToUser assigns a role to a user
func (s *UserService) AssignRoleToUser(ctx context.Context, userID, roleID string, adminID uuid.UUID, ipAddress, userAgent string) error {
	// Parse IDs
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return errors.New("invalid user ID")
	}

	roleUUID, err := uuid.Parse(roleID)
	if err != nil {
		return errors.New("invalid role ID")
	}

	// Get user
	user, err := s.UserRepo.GetByID(ctx, userUUID)
	if err != nil {
		return errors.New("user not found")
	}

	// Get role
	role, err := s.RoleRepo.GetByID(ctx, roleUUID)
	if err != nil {
		return errors.New("role not found")
	}

	// Assign role to user
	if err := s.UserRepo.AssignRole(ctx, userUUID, roleUUID); err != nil {
		return fmt.Errorf("failed to assign role to user: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &adminID,
		EventType:   "role_assigned_to_user",
		Description: fmt.Sprintf("Role %s assigned to user %s", role.Name, user.Username),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	auditLog := &model.AuditLog{
		UserID:       &adminID,
		Action:       "assign_role",
		ResourceType: "user",
		ResourceID:   &user.ID,
		NewValues:    fmt.Sprintf(`{"role_id":"%s","role_name":"%s"}`, role.ID, role.Name),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	return nil
}

// RemoveRoleFromUser removes a role from a user
func (s *UserService) RemoveRoleFromUser(ctx context.Context, userID, roleID string, adminID uuid.UUID, ipAddress, userAgent string) error {
	// Parse IDs
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return errors.New("invalid user ID")
	}

	roleUUID, err := uuid.Parse(roleID)
	if err != nil {
		return errors.New("invalid role ID")
	}

	// Get user
	user, err := s.UserRepo.GetByID(ctx, userUUID)
	if err != nil {
		return errors.New("user not found")
	}

	// Get role
	role, err := s.RoleRepo.GetByID(ctx, roleUUID)
	if err != nil {
		return errors.New("role not found")
	}

	// Remove role from user
	if err := s.UserRepo.RemoveRole(ctx, userUUID, roleUUID); err != nil {
		return fmt.Errorf("failed to remove role from user: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &adminID,
		EventType:   "role_removed_from_user",
		Description: fmt.Sprintf("Role %s removed from user %s", role.Name, user.Username),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	auditLog := &model.AuditLog{
		UserID:       &adminID,
		Action:       "remove_role",
		ResourceType: "user",
		ResourceID:   &user.ID,
		OldValues:    fmt.Sprintf(`{"role_id":"%s","role_name":"%s"}`, role.ID, role.Name),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	return nil
}

// GetUserGroups gets all groups for a user
func (s *UserService) GetUserGroups(ctx context.Context, userID string) ([]GroupResponse, error) {
	// Parse user ID
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, errors.New("invalid user ID")
	}

	// Get user
	_, err = s.UserRepo.GetByID(ctx, userUUID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Get user groups
	groups, err := s.UserRepo.GetUserGroups(ctx, userUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups: %w", err)
	}

	// Convert to response format
	response := make([]GroupResponse, len(groups))
	for i, group := range groups {
		response[i] = GroupResponse{
			ID:          group.ID.String(),
			Name:        group.Name,
			Description: group.Description,
			CreatedAt:   group.CreatedAt,
			UpdatedAt:   group.UpdatedAt,
		}
	}

	return response, nil
}

// GetUserRoles gets all roles for a user
func (s *UserService) GetUserRoles(ctx context.Context, userID string) ([]RoleResponse, error) {
	// Parse user ID
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, errors.New("invalid user ID")
	}

	// Get user
	_, err = s.UserRepo.GetByID(ctx, userUUID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Get user roles
	roles, err := s.UserRepo.GetUserRoles(ctx, userUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	// Convert to response format
	response := make([]RoleResponse, len(roles))
	for i, role := range roles {
		response[i] = RoleResponse{
			ID:          role.ID.String(),
			Name:        role.Name,
			Description: role.Description,
			CreatedAt:   role.CreatedAt,
			UpdatedAt:   role.UpdatedAt,
		}
	}

	return response, nil
}

// GetUserPermissions gets all permissions for a user
func (s *UserService) GetUserPermissions(ctx context.Context, userID string) ([]PermissionResponse, error) {
	// Parse user ID
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, errors.New("invalid user ID")
	}

	// Get user
	_, err = s.UserRepo.GetByID(ctx, userUUID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Get user permissions
	permissions, err := s.UserRepo.GetUserPermissions(ctx, userUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	// Convert to response format
	response := make([]PermissionResponse, len(permissions))
	for i, permission := range permissions {
		response[i] = PermissionResponse{
			ID:          permission.ID.String(),
			Name:        permission.Name,
			Resource:    permission.Resource,
			Action:      permission.Action,
			Description: permission.Description,
			CreatedAt:   permission.CreatedAt,
			UpdatedAt:   permission.UpdatedAt,
		}
	}

	return response, nil
}