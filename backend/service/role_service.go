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

// RoleService handles role operations
type RoleService struct {
	RoleRepo       *repository.RoleRepository
	PermissionRepo *repository.PermissionRepository
	AuditRepo      *repository.AuditRepository
	Logger         *logrus.Logger
	Validator      *utils.Validator
}

// NewRoleService creates a new role service
func NewRoleService(
	roleRepo *repository.RoleRepository,
	permissionRepo *repository.PermissionRepository,
	auditRepo *repository.AuditRepository,
	logger *logrus.Logger,
	validator *utils.Validator,
) *RoleService {
	return &RoleService{
		RoleRepo:       roleRepo,
		PermissionRepo: permissionRepo,
		AuditRepo:      auditRepo,
		Logger:         logger,
		Validator:      validator,
	}
}

// CreateRoleRequest represents a request to create a role
type CreateRoleRequest struct {
	Name        string   `json:"name" binding:"required,min=3,max=100,nohtml"`
	Description string   `json:"description" binding:"omitempty,nohtml"`
	Permissions []string `json:"permissions" binding:"omitempty"`
}

// UpdateRoleRequest represents a request to update a role
type UpdateRoleRequest struct {
	Name        string `json:"name" binding:"omitempty,min=3,max=100,nohtml"`
	Description string `json:"description" binding:"omitempty,nohtml"`
}

// RoleResponse represents a role response
type RoleResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Users       []string  `json:"users,omitempty"`
	Groups      []string  `json:"groups,omitempty"`
	Permissions []string  `json:"permissions,omitempty"`
}

// RolesResponse represents a paginated list of roles
type RolesResponse struct {
	Roles      []RoleResponse `json:"roles"`
	Total      int64          `json:"total"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalPages int            `json:"total_pages"`
}

// GetRoleByID gets a role by ID
func (s *RoleService) GetRoleByID(ctx context.Context, id string) (*RoleResponse, error) {
	// Parse role ID
	roleID, err := uuid.Parse(id)
	if err != nil {
		return nil, errors.New("invalid role ID")
	}

	// Get role
	role, err := s.RoleRepo.GetByID(ctx, roleID)
	if err != nil {
		return nil, errors.New("role not found")
	}

	// Get role users
	users, err := s.RoleRepo.GetRoleUsers(ctx, role.ID)
	if err != nil {
		s.Logger.WithError(err).Error("Failed to get role users")
		users = []model.User{}
	}

	// Get role groups
	groups, err := s.RoleRepo.GetRoleGroups(ctx, role.ID)
	if err != nil {
		s.Logger.WithError(err).Error("Failed to get role groups")
		groups = []model.Group{}
	}

	// Get role permissions
	permissions, err := s.RoleRepo.GetRolePermissions(ctx, role.ID)
	if err != nil {
		s.Logger.WithError(err).Error("Failed to get role permissions")
		permissions = []model.Permission{}
	}

	// Create response
	response := &RoleResponse{
		ID:          role.ID.String(),
		Name:        role.Name,
		Description: role.Description,
		CreatedAt:   role.CreatedAt,
		UpdatedAt:   role.UpdatedAt,
		Users:       make([]string, len(users)),
		Groups:      make([]string, len(groups)),
		Permissions: make([]string, len(permissions)),
	}

	// Add user names
	for i, user := range users {
		response.Users[i] = user.Username
	}

	// Add group names
	for i, group := range groups {
		response.Groups[i] = group.Name
	}

	// Add permission names
	for i, permission := range permissions {
		response.Permissions[i] = permission.Name
	}

	return response, nil
}

// ListRoles lists roles with pagination
func (s *RoleService) ListRoles(ctx context.Context, page, pageSize int) (*RolesResponse, error) {
	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	// Get roles with pagination
	roles, total, err := s.RoleRepo.List(ctx, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}

	// Calculate total pages
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	// Create response
	response := &RolesResponse{
		Roles:      make([]RoleResponse, len(roles)),
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}

	// Convert roles to response format
	for i, role := range roles {
		response.Roles[i] = RoleResponse{
			ID:          role.ID.String(),
			Name:        role.Name,
			Description: role.Description,
			CreatedAt:   role.CreatedAt,
			UpdatedAt:   role.UpdatedAt,
		}
	}

	return response, nil
}

// SearchRoles searches roles by name or description
func (s *RoleService) SearchRoles(ctx context.Context, query string, page, pageSize int) (*RolesResponse, error) {
	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	// Search roles with pagination
	roles, total, err := s.RoleRepo.Search(ctx, query, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("failed to search roles: %w", err)
	}

	// Calculate total pages
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	// Create response
	response := &RolesResponse{
		Roles:      make([]RoleResponse, len(roles)),
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}

	// Convert roles to response format
	for i, role := range roles {
		response.Roles[i] = RoleResponse{
			ID:          role.ID.String(),
			Name:        role.Name,
			Description: role.Description,
			CreatedAt:   role.CreatedAt,
			UpdatedAt:   role.UpdatedAt,
		}
	}

	return response, nil
}

// CreateRole creates a new role
func (s *RoleService) CreateRole(ctx context.Context, req CreateRoleRequest, creatorID uuid.UUID, ipAddress, userAgent string) (*RoleResponse, error) {
	// Check if role name already exists
	_, err := s.RoleRepo.GetByName(ctx, req.Name)
	if err == nil {
		return nil, errors.New("role name already exists")
	}

	// Create role
	role := &model.Role{
		Name:        req.Name,
		Description: req.Description,
	}

	// Save role
	if err := s.RoleRepo.Create(ctx, role); err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}

	// Add permissions if provided
	if len(req.Permissions) > 0 {
		for _, permName := range req.Permissions {
			// Get permission by name
			perm, err := s.PermissionRepo.GetByName(ctx, permName)
			if err != nil {
				s.Logger.WithError(err).WithField("permission", permName).Warn("Permission not found, skipping")
				continue
			}

			// Assign permission to role
			if err := s.RoleRepo.AssignPermission(ctx, role.ID, perm.ID); err != nil {
				s.Logger.WithError(err).WithFields(logrus.Fields{
					"role":       role.Name,
					"permission": perm.Name,
				}).Warn("Failed to assign permission to role")
			}
		}
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &creatorID,
		EventType:   "role_created",
		Description: fmt.Sprintf("Role created: %s", role.Name),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	roleJSON, _ := json.Marshal(role)
	auditLog := &model.AuditLog{
		UserID:       &creatorID,
		Action:       "create",
		ResourceType: "role",
		ResourceID:   &role.ID,
		NewValues:    string(roleJSON),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	// Return role response
	return &RoleResponse{
		ID:          role.ID.String(),
		Name:        role.Name,
		Description: role.Description,
		CreatedAt:   role.CreatedAt,
		UpdatedAt:   role.UpdatedAt,
	}, nil
}

// UpdateRole updates a role
func (s *RoleService) UpdateRole(ctx context.Context, id string, req UpdateRoleRequest, updaterID uuid.UUID, ipAddress, userAgent string) (*RoleResponse, error) {
	// Parse role ID
	roleID, err := uuid.Parse(id)
	if err != nil {
		return nil, errors.New("invalid role ID")
	}

	// Get role
	role, err := s.RoleRepo.GetByID(ctx, roleID)
	if err != nil {
		return nil, errors.New("role not found")
	}

	// Store old values for audit log
	oldRoleJSON, _ := json.Marshal(role)

	// Update name if provided
	if req.Name != "" && req.Name != role.Name {
		// Check if name already exists
		_, err := s.RoleRepo.GetByName(ctx, req.Name)
		if err == nil {
			return nil, errors.New("role name already exists")
		}

		role.Name = req.Name
	}

	// Update description if provided
	if req.Description != "" {
		role.Description = req.Description
	}

	// Save role
	if err := s.RoleRepo.Update(ctx, role); err != nil {
		return nil, fmt.Errorf("failed to update role: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &updaterID,
		EventType:   "role_updated",
		Description: fmt.Sprintf("Role updated: %s", role.Name),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	newRoleJSON, _ := json.Marshal(role)
	auditLog := &model.AuditLog{
		UserID:       &updaterID,
		Action:       "update",
		ResourceType: "role",
		ResourceID:   &role.ID,
		OldValues:    string(oldRoleJSON),
		NewValues:    string(newRoleJSON),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	// Return role response
	return &RoleResponse{
		ID:          role.ID.String(),
		Name:        role.Name,
		Description: role.Description,
		CreatedAt:   role.CreatedAt,
		UpdatedAt:   role.UpdatedAt,
	}, nil
}

// DeleteRole soft deletes a role
func (s *RoleService) DeleteRole(ctx context.Context, id string, deleterID uuid.UUID, ipAddress, userAgent string) error {
	// Parse role ID
	roleID, err := uuid.Parse(id)
	if err != nil {
		return errors.New("invalid role ID")
	}

	// Get role
	role, err := s.RoleRepo.GetByID(ctx, roleID)
	if err != nil {
		return errors.New("role not found")
	}

	// Store old values for audit log
	oldRoleJSON, _ := json.Marshal(role)

	// Delete role
	if err := s.RoleRepo.Delete(ctx, roleID); err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &deleterID,
		EventType:   "role_deleted",
		Description: fmt.Sprintf("Role deleted: %s", role.Name),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	auditLog := &model.AuditLog{
		UserID:       &deleterID,
		Action:       "delete",
		ResourceType: "role",
		ResourceID:   &role.ID,
		OldValues:    string(oldRoleJSON),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	return nil
}

// AssignPermissionToRole assigns a permission to a role
func (s *RoleService) AssignPermissionToRole(ctx context.Context, roleID, permissionID string, adminID uuid.UUID, ipAddress, userAgent string) error {
	// Parse IDs
	roleUUID, err := uuid.Parse(roleID)
	if err != nil {
		return errors.New("invalid role ID")
	}

	permissionUUID, err := uuid.Parse(permissionID)
	if err != nil {
		return errors.New("invalid permission ID")
	}

	// Get role
	role, err := s.RoleRepo.GetByID(ctx, roleUUID)
	if err != nil {
		return errors.New("role not found")
	}

	// Get permission
	permission, err := s.PermissionRepo.GetByID(ctx, permissionUUID)
	if err != nil {
		return errors.New("permission not found")
	}

	// Assign permission to role
	if err := s.RoleRepo.AssignPermission(ctx, roleUUID, permissionUUID); err != nil {
		return fmt.Errorf("failed to assign permission to role: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &adminID,
		EventType:   "permission_assigned_to_role",
		Description: fmt.Sprintf("Permission %s assigned to role %s", permission.Name, role.Name),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	auditLog := &model.AuditLog{
		UserID:       &adminID,
		Action:       "assign_permission",
		ResourceType: "role",
		ResourceID:   &role.ID,
		NewValues:    fmt.Sprintf(`{"permission_id":"%s","permission_name":"%s"}`, permission.ID, permission.Name),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	return nil
}

// RemovePermissionFromRole removes a permission from a role
func (s *RoleService) RemovePermissionFromRole(ctx context.Context, roleID, permissionID string, adminID uuid.UUID, ipAddress, userAgent string) error {
	// Parse IDs
	roleUUID, err := uuid.Parse(roleID)
	if err != nil {
		return errors.New("invalid role ID")
	}

	permissionUUID, err := uuid.Parse(permissionID)
	if err != nil {
		return errors.New("invalid permission ID")
	}

	// Get role
	role, err := s.RoleRepo.GetByID(ctx, roleUUID)
	if err != nil {
		return errors.New("role not found")
	}

	// Get permission
	permission, err := s.PermissionRepo.GetByID(ctx, permissionUUID)
	if err != nil {
		return errors.New("permission not found")
	}

	// Remove permission from role
	if err := s.RoleRepo.RemovePermission(ctx, roleUUID, permissionUUID); err != nil {
		return fmt.Errorf("failed to remove permission from role: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &adminID,
		EventType:   "permission_removed_from_role",
		Description: fmt.Sprintf("Permission %s removed from role %s", permission.Name, role.Name),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	auditLog := &model.AuditLog{
		UserID:       &adminID,
		Action:       "remove_permission",
		ResourceType: "role",
		ResourceID:   &role.ID,
		OldValues:    fmt.Sprintf(`{"permission_id":"%s","permission_name":"%s"}`, permission.ID, permission.Name),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	return nil
}

// GetRoleUsers gets all users with a role
func (s *RoleService) GetRoleUsers(ctx context.Context, roleID string) ([]UserResponse, error) {
	// Parse role ID
	roleUUID, err := uuid.Parse(roleID)
	if err != nil {
		return nil, errors.New("invalid role ID")
	}

	// Get role
	_, err = s.RoleRepo.GetByID(ctx, roleUUID)
	if err != nil {
		return nil, errors.New("role not found")
	}

	// Get role users
	users, err := s.RoleRepo.GetRoleUsers(ctx, roleUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role users: %w", err)
	}

	// Convert to response format
	response := make([]UserResponse, len(users))
	for i, user := range users {
		// Format last login time
		var lastLoginStr *string
		if user.LastLoginAt != nil {
			tmp := user.LastLoginAt.Format(time.RFC3339)
			lastLoginStr = &tmp
		}

		response[i] = UserResponse{
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

// GetRoleGroups gets all groups with a role
func (s *RoleService) GetRoleGroups(ctx context.Context, roleID string) ([]GroupResponse, error) {
	// Parse role ID
	roleUUID, err := uuid.Parse(roleID)
	if err != nil {
		return nil, errors.New("invalid role ID")
	}

	// Get role
	_, err = s.RoleRepo.GetByID(ctx, roleUUID)
	if err != nil {
		return nil, errors.New("role not found")
	}

	// Get role groups
	groups, err := s.RoleRepo.GetRoleGroups(ctx, roleUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role groups: %w", err)
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

// GetRolePermissions gets all permissions for a role
func (s *RoleService) GetRolePermissions(ctx context.Context, roleID string) ([]PermissionResponse, error) {
	// Parse role ID
	roleUUID, err := uuid.Parse(roleID)
	if err != nil {
		return nil, errors.New("invalid role ID")
	}

	// Get role
	_, err = s.RoleRepo.GetByID(ctx, roleUUID)
	if err != nil {
		return nil, errors.New("role not found")
	}

	// Get role permissions
	permissions, err := s.RoleRepo.GetRolePermissions(ctx, roleUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
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