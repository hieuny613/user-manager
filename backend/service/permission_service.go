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

// PermissionService handles permission operations
type PermissionService struct {
	PermissionRepo *repository.PermissionRepository
	RoleRepo       *repository.RoleRepository
	AuditRepo      *repository.AuditRepository
	Logger         *logrus.Logger
	Validator      *utils.Validator
}

// NewPermissionService creates a new permission service
func NewPermissionService(
	permissionRepo *repository.PermissionRepository,
	roleRepo *repository.RoleRepository,
	auditRepo *repository.AuditRepository,
	logger *logrus.Logger,
	validator *utils.Validator,
) *PermissionService {
	return &PermissionService{
		PermissionRepo: permissionRepo,
		RoleRepo:       roleRepo,
		AuditRepo:      auditRepo,
		Logger:         logger,
		Validator:      validator,
	}
}

// CreatePermissionRequest represents a request to create a permission
type CreatePermissionRequest struct {
	Name        string `json:"name" binding:"required,min=3,max=100,nohtml"`
	Resource    string `json:"resource" binding:"required,min=1,max=100,nohtml"`
	Action      string `json:"action" binding:"required,min=1,max=100,nohtml"`
	Description string `json:"description" binding:"omitempty,nohtml"`
}

// UpdatePermissionRequest represents a request to update a permission
type UpdatePermissionRequest struct {
	Name        string `json:"name" binding:"omitempty,min=3,max=100,nohtml"`
	Resource    string `json:"resource" binding:"omitempty,min=1,max=100,nohtml"`
	Action      string `json:"action" binding:"omitempty,min=1,max=100,nohtml"`
	Description string `json:"description" binding:"omitempty,nohtml"`
}

// PermissionResponse represents a permission response
type PermissionResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Roles       []string  `json:"roles,omitempty"`
}

// PermissionsResponse represents a paginated list of permissions
type PermissionsResponse struct {
	Permissions []PermissionResponse `json:"permissions"`
	Total       int64                `json:"total"`
	Page        int                  `json:"page"`
	PageSize    int                  `json:"page_size"`
	TotalPages  int                  `json:"total_pages"`
}

// GetPermissionByID gets a permission by ID
func (s *PermissionService) GetPermissionByID(ctx context.Context, id string) (*PermissionResponse, error) {
	// Parse permission ID
	permissionID, err := uuid.Parse(id)
	if err != nil {
		return nil, errors.New("invalid permission ID")
	}

	// Get permission
	permission, err := s.PermissionRepo.GetByID(ctx, permissionID)
	if err != nil {
		return nil, errors.New("permission not found")
	}

	// Get permission roles
	roles, err := s.PermissionRepo.GetPermissionRoles(ctx, permission.ID)
	if err != nil {
		s.Logger.WithError(err).Error("Failed to get permission roles")
		roles = []model.Role{}
	}

	// Create response
	response := &PermissionResponse{
		ID:          permission.ID.String(),
		Name:        permission.Name,
		Resource:    permission.Resource,
		Action:      permission.Action,
		Description: permission.Description,
		CreatedAt:   permission.CreatedAt,
		UpdatedAt:   permission.UpdatedAt,
		Roles:       make([]string, len(roles)),
	}

	// Add role names
	for i, role := range roles {
		response.Roles[i] = role.Name
	}

	return response, nil
}

// ListPermissions lists permissions with pagination
func (s *PermissionService) ListPermissions(ctx context.Context, page, pageSize int) (*PermissionsResponse, error) {
	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	// Get permissions with pagination
	permissions, total, err := s.PermissionRepo.List(ctx, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("failed to list permissions: %w", err)
	}

	// Calculate total pages
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	// Create response
	response := &PermissionsResponse{
		Permissions: make([]PermissionResponse, len(permissions)),
		Total:       total,
		Page:        page,
		PageSize:    pageSize,
		TotalPages:  totalPages,
	}

	// Convert permissions to response format
	for i, permission := range permissions {
		response.Permissions[i] = PermissionResponse{
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

// SearchPermissions searches permissions by name, resource, action, or description
func (s *PermissionService) SearchPermissions(ctx context.Context, query string, page, pageSize int) (*PermissionsResponse, error) {
	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	// Search permissions with pagination
	permissions, total, err := s.PermissionRepo.Search(ctx, query, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("failed to search permissions: %w", err)
	}

	// Calculate total pages
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	// Create response
	response := &PermissionsResponse{
		Permissions: make([]PermissionResponse, len(permissions)),
		Total:       total,
		Page:        page,
		PageSize:    pageSize,
		TotalPages:  totalPages,
	}

	// Convert permissions to response format
	for i, permission := range permissions {
		response.Permissions[i] = PermissionResponse{
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

// CreatePermission creates a new permission
func (s *PermissionService) CreatePermission(ctx context.Context, req CreatePermissionRequest, creatorID uuid.UUID, ipAddress, userAgent string) (*PermissionResponse, error) {
	// Check if permission name already exists
	_, err := s.PermissionRepo.GetByName(ctx, req.Name)
	if err == nil {
		return nil, errors.New("permission name already exists")
	}

	// Check if resource+action combination already exists
	_, err = s.PermissionRepo.GetByResourceAction(ctx, req.Resource, req.Action)
	if err == nil {
		return nil, errors.New("permission with this resource and action already exists")
	}

	// Create permission
	permission := &model.Permission{
		Name:        req.Name,
		Resource:    req.Resource,
		Action:      req.Action,
		Description: req.Description,
	}

	// Save permission
	if err := s.PermissionRepo.Create(ctx, permission); err != nil {
		return nil, fmt.Errorf("failed to create permission: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &creatorID,
		EventType:   "permission_created",
		Description: fmt.Sprintf("Permission created: %s (%s:%s)", permission.Name, permission.Resource, permission.Action),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	permissionJSON, _ := json.Marshal(permission)
	auditLog := &model.AuditLog{
		UserID:       &creatorID,
		Action:       "create",
		ResourceType: "permission",
		ResourceID:   &permission.ID,
		NewValues:    string(permissionJSON),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	// Return permission response
	return &PermissionResponse{
		ID:          permission.ID.String(),
		Name:        permission.Name,
		Resource:    permission.Resource,
		Action:      permission.Action,
		Description: permission.Description,
		CreatedAt:   permission.CreatedAt,
		UpdatedAt:   permission.UpdatedAt,
	}, nil
}

// UpdatePermission updates a permission
func (s *PermissionService) UpdatePermission(ctx context.Context, id string, req UpdatePermissionRequest, updaterID uuid.UUID, ipAddress, userAgent string) (*PermissionResponse, error) {
	// Parse permission ID
	permissionID, err := uuid.Parse(id)
	if err != nil {
		return nil, errors.New("invalid permission ID")
	}

	// Get permission
	permission, err := s.PermissionRepo.GetByID(ctx, permissionID)
	if err != nil {
		return nil, errors.New("permission not found")
	}

	// Store old values for audit log
	oldPermissionJSON, _ := json.Marshal(permission)

	// Update name if provided
	if req.Name != "" && req.Name != permission.Name {
		// Check if name already exists
		_, err := s.PermissionRepo.GetByName(ctx, req.Name)
		if err == nil {
			return nil, errors.New("permission name already exists")
		}

		permission.Name = req.Name
	}

	// Update resource if provided
	resourceChanged := false
	if req.Resource != "" && req.Resource != permission.Resource {
		permission.Resource = req.Resource
		resourceChanged = true
	}

	// Update action if provided
	actionChanged := false
	if req.Action != "" && req.Action != permission.Action {
		permission.Action = req.Action
		actionChanged = true
	}

	// Check if resource+action combination already exists
	if (resourceChanged || actionChanged) && permission.Resource != "" && permission.Action != "" {
		existing, err := s.PermissionRepo.GetByResourceAction(ctx, permission.Resource, permission.Action)
		if err == nil && existing.ID != permission.ID {
			return nil, errors.New("permission with this resource and action already exists")
		}
	}

	// Update description if provided
	if req.Description != "" {
		permission.Description = req.Description
	}

	// Save permission
	if err := s.PermissionRepo.Update(ctx, permission); err != nil {
		return nil, fmt.Errorf("failed to update permission: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &updaterID,
		EventType:   "permission_updated",
		Description: fmt.Sprintf("Permission updated: %s (%s:%s)", permission.Name, permission.Resource, permission.Action),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	newPermissionJSON, _ := json.Marshal(permission)
	auditLog := &model.AuditLog{
		UserID:       &updaterID,
		Action:       "update",
		ResourceType: "permission",
		ResourceID:   &permission.ID,
		OldValues:    string(oldPermissionJSON),
		NewValues:    string(newPermissionJSON),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	// Return permission response
	return &PermissionResponse{
		ID:          permission.ID.String(),
		Name:        permission.Name,
		Resource:    permission.Resource,
		Action:      permission.Action,
		Description: permission.Description,
		CreatedAt:   permission.CreatedAt,
		UpdatedAt:   permission.UpdatedAt,
	}, nil
}

// DeletePermission soft deletes a permission
func (s *PermissionService) DeletePermission(ctx context.Context, id string, deleterID uuid.UUID, ipAddress, userAgent string) error {
	// Parse permission ID
	permissionID, err := uuid.Parse(id)
	if err != nil {
		return errors.New("invalid permission ID")
	}

	// Get permission
	permission, err := s.PermissionRepo.GetByID(ctx, permissionID)
	if err != nil {
		return errors.New("permission not found")
	}

	// Store old values for audit log
	oldPermissionJSON, _ := json.Marshal(permission)

	// Delete permission
	if err := s.PermissionRepo.Delete(ctx, permissionID); err != nil {
		return fmt.Errorf("failed to delete permission: %w", err)
	}

	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      &deleterID,
		EventType:   "permission_deleted",
		Description: fmt.Sprintf("Permission deleted: %s (%s:%s)", permission.Name, permission.Resource, permission.Action),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}
	_ = s.AuditRepo.CreateSecurityEvent(ctx, securityEvent)

	// Create audit log
	auditLog := &model.AuditLog{
		UserID:       &deleterID,
		Action:       "delete",
		ResourceType: "permission",
		ResourceID:   &permission.ID,
		OldValues:    string(oldPermissionJSON),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	_ = s.AuditRepo.CreateAuditLog(ctx, auditLog)

	return nil
}

// GetPermissionRoles gets all roles with a permission
func (s *PermissionService) GetPermissionRoles(ctx context.Context, permissionID string) ([]RoleResponse, error) {
	// Parse permission ID
	permissionUUID, err := uuid.Parse(permissionID)
	if err != nil {
		return nil, errors.New("invalid permission ID")
	}

	// Get permission
	_, err = s.PermissionRepo.GetByID(ctx, permissionUUID)
	if err != nil {
		return nil, errors.New("permission not found")
	}

	// Get permission roles
	roles, err := s.PermissionRepo.GetPermissionRoles(ctx, permissionUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get permission roles: %w", err)
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