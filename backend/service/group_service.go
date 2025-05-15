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

// GroupService handles group operations
type GroupService struct {
	GroupRepo  *repository.GroupRepository
	RoleRepo   *repository.RoleRepository
	AuditRepo  *repository.AuditRepository
	Logger     *logrus.Logger
	Validator  *utils.Validator
}

// NewGroupService creates a new group service
func NewGroupService(
	groupRepo *repository.GroupRepository,
	roleRepo *repository.RoleRepository,
	auditRepo *repository.AuditRepository,
	logger *logrus.Logger,
	validator *utils.Validator,
) *GroupService {
	return &GroupService{
		GroupRepo:  groupRepo,
		RoleRepo:   roleRepo,
		AuditRepo:  auditRepo,
		Logger:     logger,
		Validator:  validator,
	}
}

// CreateGroupRequest represents a request to create a group
type CreateGroupRequest struct {
	Name        string `json:"name" binding:"required,min=3,max=100,nohtml"`
	Description string `json:"description" binding:"omitempty,nohtml"`
}

// UpdateGroupRequest represents a request to update a group
type UpdateGroupRequest struct {
	Name        string `json:"name" binding:"omitempty,min=3,max=100,nohtml"`
	Description string `json:"description" binding:"omitempty,nohtml"`
}

// GroupResponse represents a group response
type GroupResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Users       []string  `json:"users,omitempty"`
	Roles       []string  `json:"roles,omitempty"`
	Permissions []string  `json:"permissions,omitempty"`
}

// GroupsResponse represents a paginated list of groups
type GroupsResponse struct {
	Groups     []GroupResponse `json:"groups"`
	Total      int64           `json:"total"`
	Page       int             `json:"page"`
	PageSize   int             `json:"page_size"`
	TotalPages int             `json:"total_pages"`
}

// GetGroupByID gets a group by ID
func (s *GroupService) GetGroupByID(ctx context.Context, id string) (*GroupResponse, error) {
	// Parse group ID
	groupID, err := uuid.Parse(id)
	if err != nil {
		return nil, errors.New("invalid group ID")
	}

	// Get group
	group, err := s.GroupRepo.GetByID(ctx, groupID)
	if err != nil {
		return nil, errors.New("group not found")
	}

	// Get group users
	users, err := s.GroupRepo.GetGroupUsers(ctx, group.ID)
	if err != nil {
		s.Logger.WithError(err).Error("Failed to get group users")
		users = []model.User{}
	}

	// Get group roles
	roles, err := s.GroupRepo.GetGroupRoles(ctx, group.ID)
	if err != nil {
		s.Logger.WithError(err).Error("Failed to get group roles")
		roles = []model.Role{}
	}

	// Get group permissions
	permissions, err := s.GroupRepo.GetGroupPermissions(ctx, group.ID)
	if err != nil {
		s.Logger.WithError(err).Error("Failed to get group permissions")
		permissions = []model.Permission{}
	}

	// Create response
	response := &GroupResponse{
		ID:          group.ID.String(),
		Name:        group.Name,
		Description: group.Description,
		CreatedAt:   group.CreatedAt,
		UpdatedAt:   group.UpdatedAt,
		Users:       make([]string, len(users)),
		Roles:       make([]string, len(roles)),
		Permissions: make([]string, len(permissions)),
	}

	// Add user names
	for i, user := range users {
		response.Users[i] = user.Username
	}

	// Add role names
	for i, role := range roles {
		response.Roles[i] = role.Name
	}

	// Add permission names
	for i, permission := range permissions {
		response.Permissions[i] = permission.Name
	}

	return response, nil
}

// ListGroups lists groups with pagination
func (s *GroupService) ListGroups(ctx context.Context, page, pageSize int) (*GroupsResponse, error) {
	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	// Get groups with pagination
	groups, total, err := s.GroupRepo.List(ctx, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}

	// Calculate total pages
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	// Create response
	response := &GroupsResponse{
		Groups:     make([]GroupResponse, len(groups)),
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}

	// Convert groups to response format
	for i, group := range groups {
		response.Groups[i] = GroupResponse{
			ID:          group.ID.String(),
			Name:        group.Name,
			Description: group.Description,
			CreatedAt:   group.CreatedAt,
			UpdatedAt:   group.UpdatedAt,
		}
	}

	return response, nil
}

// SearchGroups searches groups by name or description
func (s *GroupService) SearchGroups(ctx context.Context, query string, page, pageSize int) (*GroupsResponse, error) {
	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	// Search groups with pagination
	groups, total, err := s.GroupRepo.Search(ctx, query, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("failed to search groups: %w", err)
	}

	// Calculate total pages
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	// Create response
	response := &GroupsResponse{
		Groups:     make([]GroupResponse, len(groups)),
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}

	// Convert groups to response format
	for i, group := range groups {
		response.Groups[i] = GroupResponse{
			ID:          group.ID.String(),
			Name:        group.Name,
			Description: group.Description,
			CreatedAt:   group.CreatedAt,
			UpdatedAt:   group.UpdatedAt,
		}
	}

	return response, nil
}

// CreateGroup creates a new group
func (s *GroupService) CreateGroup(ctx context.Context, req CreateGroupRequest, creatorID uuid.UUID, ipAddress, userAgent string) (*GroupResponse, error) {
	// Check if group name already exists
	_, err := s.GroupRepo.GetByName(ctx, req.Name)
	if err == nil {
		return nil, errors.New("group name already exists")
	}

	// Create group
	group := &model.Group{
		Name:        req.Name,
		Description: req.Description,
	}

	// Save group
	if err := s.GroupRepo.Create(ctx, group); err != nil {
		return nil, fmt.Errorf("failed to create group: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &creatorID,
		EventType:   "group_created",
		Description: fmt.Sprintf("Group created: %s", group.Name),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	groupJSON, _ := json.Marshal(group)
	auditLog := &model.AuditLog{
		UserID:       &creatorID,
		Action:       "create",
		ResourceType: "group",
		ResourceID:   &group.ID,
		NewValues:    string(groupJSON),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	// Return group response
	return &GroupResponse{
		ID:          group.ID.String(),
		Name:        group.Name,
		Description: group.Description,
		CreatedAt:   group.CreatedAt,
		UpdatedAt:   group.UpdatedAt,
	}, nil
}

// UpdateGroup updates a group
func (s *GroupService) UpdateGroup(ctx context.Context, id string, req UpdateGroupRequest, updaterID uuid.UUID, ipAddress, userAgent string) (*GroupResponse, error) {
	// Parse group ID
	groupID, err := uuid.Parse(id)
	if err != nil {
		return nil, errors.New("invalid group ID")
	}

	// Get group
	group, err := s.GroupRepo.GetByID(ctx, groupID)
	if err != nil {
		return nil, errors.New("group not found")
	}

	// Store old values for audit log
	oldGroupJSON, _ := json.Marshal(group)

	// Update name if provided
	if req.Name != "" && req.Name != group.Name {
		// Check if name already exists
		_, err := s.GroupRepo.GetByName(ctx, req.Name)
		if err == nil {
			return nil, errors.New("group name already exists")
		}

		group.Name = req.Name
	}

	// Update description if provided
	if req.Description != "" {
		group.Description = req.Description
	}

	// Save group
	if err := s.GroupRepo.Update(ctx, group); err != nil {
		return nil, fmt.Errorf("failed to update group: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &updaterID,
		EventType:   "group_updated",
		Description: fmt.Sprintf("Group updated: %s", group.Name),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	newGroupJSON, _ := json.Marshal(group)
	auditLog := &model.AuditLog{
		UserID:       &updaterID,
		Action:       "update",
		ResourceType: "group",
		ResourceID:   &group.ID,
		OldValues:    string(oldGroupJSON),
		NewValues:    string(newGroupJSON),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	// Return group response
	return &GroupResponse{
		ID:          group.ID.String(),
		Name:        group.Name,
		Description: group.Description,
		CreatedAt:   group.CreatedAt,
		UpdatedAt:   group.UpdatedAt,
	}, nil
}

// DeleteGroup soft deletes a group
func (s *GroupService) DeleteGroup(ctx context.Context, id string, deleterID uuid.UUID, ipAddress, userAgent string) error {
	// Parse group ID
	groupID, err := uuid.Parse(id)
	if err != nil {
		return errors.New("invalid group ID")
	}

	// Get group
	group, err := s.GroupRepo.GetByID(ctx, groupID)
	if err != nil {
		return errors.New("group not found")
	}

	// Store old values for audit log
	oldGroupJSON, _ := json.Marshal(group)

	// Delete group
	if err := s.GroupRepo.Delete(ctx, groupID); err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &deleterID,
		EventType:   "group_deleted",
		Description: fmt.Sprintf("Group deleted: %s", group.Name),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	auditLog := &model.AuditLog{
		UserID:       &deleterID,
		Action:       "delete",
		ResourceType: "group",
		ResourceID:   &group.ID,
		OldValues:    string(oldGroupJSON),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	return nil
}

// AssignRoleToGroup assigns a role to a group
func (s *GroupService) AssignRoleToGroup(ctx context.Context, groupID, roleID string, adminID uuid.UUID, ipAddress, userAgent string) error {
	// Parse IDs
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		return errors.New("invalid group ID")
	}

	roleUUID, err := uuid.Parse(roleID)
	if err != nil {
		return errors.New("invalid role ID")
	}

	// Get group
	group, err := s.GroupRepo.GetByID(ctx, groupUUID)
	if err != nil {
		return errors.New("group not found")
	}

	// Get role
	role, err := s.RoleRepo.GetByID(ctx, roleUUID)
	if err != nil {
		return errors.New("role not found")
	}

	// Assign role to group
	if err := s.GroupRepo.AssignRole(ctx, groupUUID, roleUUID); err != nil {
		return fmt.Errorf("failed to assign role to group: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &adminID,
		EventType:   "role_assigned_to_group",
		Description: fmt.Sprintf("Role %s assigned to group %s", role.Name, group.Name),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	auditLog := &model.AuditLog{
		UserID:       &adminID,
		Action:       "assign_role",
		ResourceType: "group",
		ResourceID:   &group.ID,
		NewValues:    fmt.Sprintf(`{"role_id":"%s","role_name":"%s"}`, role.ID, role.Name),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	return nil
}

// RemoveRoleFromGroup removes a role from a group
func (s *GroupService) RemoveRoleFromGroup(ctx context.Context, groupID, roleID string, adminID uuid.UUID, ipAddress, userAgent string) error {
	// Parse IDs
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		return errors.New("invalid group ID")
	}

	roleUUID, err := uuid.Parse(roleID)
	if err != nil {
		return errors.New("invalid role ID")
	}

	// Get group
	group, err := s.GroupRepo.GetByID(ctx, groupUUID)
	if err != nil {
		return errors.New("group not found")
	}

	// Get role
	role, err := s.RoleRepo.GetByID(ctx, roleUUID)
	if err != nil {
		return errors.New("role not found")
	}

	// Remove role from group
	if err := s.GroupRepo.RemoveRole(ctx, groupUUID, roleUUID); err != nil {
		return fmt.Errorf("failed to remove role from group: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &adminID,
		EventType:   "role_removed_from_group",
		Description: fmt.Sprintf("Role %s removed from group %s", role.Name, group.Name),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	auditLog := &model.AuditLog{
		UserID:       &adminID,
		Action:       "remove_role",
		ResourceType: "group",
		ResourceID:   &group.ID,
		OldValues:    fmt.Sprintf(`{"role_id":"%s","role_name":"%s"}`, role.ID, role.Name),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	return nil
}

// GetGroupUsers gets all users in a group
func (s *GroupService) GetGroupUsers(ctx context.Context, groupID string) ([]UserResponse, error) {
	// Parse group ID
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		return nil, errors.New("invalid group ID")
	}

	// Get group
	_, err = s.GroupRepo.GetByID(ctx, groupUUID)
	if err != nil {
		return nil, errors.New("group not found")
	}

	// Get group users
	users, err := s.GroupRepo.GetGroupUsers(ctx, groupUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group users: %w", err)
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

// GetGroupRoles gets all roles for a group
func (s *GroupService) GetGroupRoles(ctx context.Context, groupID string) ([]RoleResponse, error) {
	// Parse group ID
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		return nil, errors.New("invalid group ID")
	}

	// Get group
	_, err = s.GroupRepo.GetByID(ctx, groupUUID)
	if err != nil {
		return nil, errors.New("group not found")
	}

	// Get group roles
	roles, err := s.GroupRepo.GetGroupRoles(ctx, groupUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group roles: %w", err)
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

// GetGroupPermissions gets all permissions for a group
func (s *GroupService) GetGroupPermissions(ctx context.Context, groupID string) ([]PermissionResponse, error) {
	// Parse group ID
	groupUUID, err := uuid.Parse(groupID)
	if err != nil {
		return nil, errors.New("invalid group ID")
	}

	// Get group
	_, err = s.GroupRepo.GetByID(ctx, groupUUID)
	if err != nil {
		return nil, errors.New("group not found")
	}

	// Get group permissions
	permissions, err := s.GroupRepo.GetGroupPermissions(ctx, groupUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group permissions: %w", err)
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