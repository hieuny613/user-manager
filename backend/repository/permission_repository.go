package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"backend/model"
)

// PermissionRepository handles database operations for permissions
type PermissionRepository struct {
	DB *gorm.DB
}

// NewPermissionRepository creates a new permission repository
func NewPermissionRepository(db *gorm.DB) *PermissionRepository {
	return &PermissionRepository{DB: db}
}

// Create creates a new permission
func (r *PermissionRepository) Create(ctx context.Context, permission *model.Permission) error {
	return r.DB.WithContext(ctx).Create(permission).Error
}

// GetByID gets a permission by ID
func (r *PermissionRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Permission, error) {
	var permission model.Permission
	result := r.DB.WithContext(ctx).Where("id = ?", id).First(&permission)
	if result.Error != nil {
		return nil, result.Error
	}
	return &permission, nil
}

// GetByName gets a permission by name
func (r *PermissionRepository) GetByName(ctx context.Context, name string) (*model.Permission, error) {
	var permission model.Permission
	result := r.DB.WithContext(ctx).Where("name = ?", name).First(&permission)
	if result.Error != nil {
		return nil, result.Error
	}
	return &permission, nil
}

// GetByResourceAction gets a permission by resource and action
func (r *PermissionRepository) GetByResourceAction(ctx context.Context, resource, action string) (*model.Permission, error) {
	var permission model.Permission
	result := r.DB.WithContext(ctx).Where("resource = ? AND action = ?", resource, action).First(&permission)
	if result.Error != nil {
		return nil, result.Error
	}
	return &permission, nil
}

// Update updates a permission
func (r *PermissionRepository) Update(ctx context.Context, permission *model.Permission) error {
	permission.UpdatedAt = time.Now()
	return r.DB.WithContext(ctx).Save(permission).Error
}

// Delete soft deletes a permission
func (r *PermissionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.DB.WithContext(ctx).Model(&model.Permission{}).Where("id = ?", id).Update("deleted_at", time.Now()).Error
}

// List lists permissions with pagination
func (r *PermissionRepository) List(ctx context.Context, page, pageSize int) ([]model.Permission, int64, error) {
	var permissions []model.Permission
	var total int64

	// Get total count
	if err := r.DB.WithContext(ctx).Model(&model.Permission{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get permissions with pagination
	offset := (page - 1) * pageSize
	result := r.DB.WithContext(ctx).Offset(offset).Limit(pageSize).Find(&permissions)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return permissions, total, nil
}

// Search searches permissions by name, resource, action, or description
func (r *PermissionRepository) Search(ctx context.Context, query string, page, pageSize int) ([]model.Permission, int64, error) {
	var permissions []model.Permission
	var total int64

	// Build search query
	searchQuery := r.DB.WithContext(ctx).Model(&model.Permission{}).Where(
		"name ILIKE ? OR resource ILIKE ? OR action ILIKE ? OR description ILIKE ?",
		"%"+query+"%", "%"+query+"%", "%"+query+"%", "%"+query+"%",
	)

	// Get total count
	if err := searchQuery.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get permissions with pagination
	offset := (page - 1) * pageSize
	result := searchQuery.Offset(offset).Limit(pageSize).Find(&permissions)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return permissions, total, nil
}

// GetPermissionRoles gets all roles with a permission
func (r *PermissionRepository) GetPermissionRoles(ctx context.Context, permissionID uuid.UUID) ([]model.Role, error) {
	var roles []model.Role

	result := r.DB.WithContext(ctx).Raw(`
		SELECT r.* FROM roles r
		JOIN role_permissions rp ON r.id = rp.role_id
		WHERE rp.permission_id = ? AND r.deleted_at IS NULL AND rp.deleted_at IS NULL
	`, permissionID).Scan(&roles)

	if result.Error != nil {
		return nil, result.Error
	}

	return roles, nil
}

// GetPermissionUsers gets all users with a permission
func (r *PermissionRepository) GetPermissionUsers(ctx context.Context, permissionID uuid.UUID) ([]model.User, error) {
	var users []model.User

	result := r.DB.WithContext(ctx).Raw(`
		SELECT DISTINCT u.* FROM users u
		JOIN user_roles ur ON u.id = ur.user_id
		JOIN roles r ON ur.role_id = r.id
		JOIN role_permissions rp ON r.id = rp.role_id
		WHERE rp.permission_id = ? AND u.deleted_at IS NULL AND ur.deleted_at IS NULL
		AND r.deleted_at IS NULL AND rp.deleted_at IS NULL
		UNION
		SELECT DISTINCT u.* FROM users u
		JOIN user_groups ug ON u.id = ug.user_id
		JOIN groups g ON ug.group_id = g.id
		JOIN group_roles gr ON g.id = gr.group_id
		JOIN roles r ON gr.role_id = r.id
		JOIN role_permissions rp ON r.id = rp.role_id
		WHERE rp.permission_id = ? AND u.deleted_at IS NULL AND ug.deleted_at IS NULL
		AND g.deleted_at IS NULL AND gr.deleted_at IS NULL AND r.deleted_at IS NULL AND rp.deleted_at IS NULL
	`, permissionID, permissionID).Scan(&users)

	if result.Error != nil {
		return nil, result.Error
	}

	return users, nil
}

// GetPermissionGroups gets all groups with a permission
func (r *PermissionRepository) GetPermissionGroups(ctx context.Context, permissionID uuid.UUID) ([]model.Group, error) {
	var groups []model.Group

	result := r.DB.WithContext(ctx).Raw(`
		SELECT DISTINCT g.* FROM groups g
		JOIN group_roles gr ON g.id = gr.group_id
		JOIN roles r ON gr.role_id = r.id
		JOIN role_permissions rp ON r.id = rp.role_id
		WHERE rp.permission_id = ? AND g.deleted_at IS NULL AND gr.deleted_at IS NULL
		AND r.deleted_at IS NULL AND rp.deleted_at IS NULL
	`, permissionID).Scan(&groups)

	if result.Error != nil {
		return nil, result.Error
	}

	return groups, nil
}