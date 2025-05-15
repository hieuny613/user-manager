package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"backend/model"
)

// RoleRepository handles database operations for roles
type RoleRepository struct {
	DB *gorm.DB
}

// NewRoleRepository creates a new role repository
func NewRoleRepository(db *gorm.DB) *RoleRepository {
	return &RoleRepository{DB: db}
}

// Create creates a new role
func (r *RoleRepository) Create(ctx context.Context, role *model.Role) error {
	return r.DB.WithContext(ctx).Create(role).Error
}

// GetByID gets a role by ID
func (r *RoleRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Role, error) {
	var role model.Role
	result := r.DB.WithContext(ctx).Where("id = ?", id).First(&role)
	if result.Error != nil {
		return nil, result.Error
	}
	return &role, nil
}

// GetByName gets a role by name
func (r *RoleRepository) GetByName(ctx context.Context, name string) (*model.Role, error) {
	var role model.Role
	result := r.DB.WithContext(ctx).Where("name = ?", name).First(&role)
	if result.Error != nil {
		return nil, result.Error
	}
	return &role, nil
}

// Update updates a role
func (r *RoleRepository) Update(ctx context.Context, role *model.Role) error {
	role.UpdatedAt = time.Now()
	return r.DB.WithContext(ctx).Save(role).Error
}

// Delete soft deletes a role
func (r *RoleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.DB.WithContext(ctx).Model(&model.Role{}).Where("id = ?", id).Update("deleted_at", time.Now()).Error
}

// List lists roles with pagination
func (r *RoleRepository) List(ctx context.Context, page, pageSize int) ([]model.Role, int64, error) {
	var roles []model.Role
	var total int64

	// Get total count
	if err := r.DB.WithContext(ctx).Model(&model.Role{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get roles with pagination
	offset := (page - 1) * pageSize
	result := r.DB.WithContext(ctx).Offset(offset).Limit(pageSize).Find(&roles)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return roles, total, nil
}

// Search searches roles by name or description
func (r *RoleRepository) Search(ctx context.Context, query string, page, pageSize int) ([]model.Role, int64, error) {
	var roles []model.Role
	var total int64

	// Build search query
	searchQuery := r.DB.WithContext(ctx).Model(&model.Role{}).Where(
		"name ILIKE ? OR description ILIKE ?",
		"%"+query+"%", "%"+query+"%",
	)

	// Get total count
	if err := searchQuery.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get roles with pagination
	offset := (page - 1) * pageSize
	result := searchQuery.Offset(offset).Limit(pageSize).Find(&roles)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return roles, total, nil
}

// AssignPermission assigns a permission to a role
func (r *RoleRepository) AssignPermission(ctx context.Context, roleID, permissionID uuid.UUID) error {
	// Check if role exists
	var role model.Role
	result := r.DB.WithContext(ctx).Where("id = ?", roleID).First(&role)
	if result.Error != nil {
		return result.Error
	}

	// Check if permission exists
	var permission model.Permission
	result = r.DB.WithContext(ctx).Where("id = ?", permissionID).First(&permission)
	if result.Error != nil {
		return result.Error
	}

	// Check if role already has the permission
	var rolePermission model.RolePermission
	result = r.DB.WithContext(ctx).Where("role_id = ? AND permission_id = ?", roleID, permissionID).First(&rolePermission)
	if result.Error == nil {
		return errors.New("role already has the permission")
	} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return result.Error
	}

	// Assign permission to role
	rolePermission = model.RolePermission{
		RoleID:       roleID,
		PermissionID: permissionID,
	}

	return r.DB.WithContext(ctx).Create(&rolePermission).Error
}

// RemovePermission removes a permission from a role
func (r *RoleRepository) RemovePermission(ctx context.Context, roleID, permissionID uuid.UUID) error {
	return r.DB.WithContext(ctx).Where("role_id = ? AND permission_id = ?", roleID, permissionID).Delete(&model.RolePermission{}).Error
}

// GetRolePermissions gets all permissions for a role
func (r *RoleRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]model.Permission, error) {
	var permissions []model.Permission

	result := r.DB.WithContext(ctx).Raw(`
		SELECT p.* FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = ? AND p.deleted_at IS NULL AND rp.deleted_at IS NULL
	`, roleID).Scan(&permissions)

	if result.Error != nil {
		return nil, result.Error
	}

	return permissions, nil
}

// GetRoleUsers gets all users with a role
func (r *RoleRepository) GetRoleUsers(ctx context.Context, roleID uuid.UUID) ([]model.User, error) {
	var users []model.User

	result := r.DB.WithContext(ctx).Raw(`
		SELECT DISTINCT u.* FROM users u
		JOIN user_roles ur ON u.id = ur.user_id
		WHERE ur.role_id = ? AND u.deleted_at IS NULL AND ur.deleted_at IS NULL
		UNION
		SELECT DISTINCT u.* FROM users u
		JOIN user_groups ug ON u.id = ug.user_id
		JOIN groups g ON ug.group_id = g.id
		JOIN group_roles gr ON g.id = gr.group_id
		WHERE gr.role_id = ? AND u.deleted_at IS NULL AND ug.deleted_at IS NULL
		AND g.deleted_at IS NULL AND gr.deleted_at IS NULL
	`, roleID, roleID).Scan(&users)

	if result.Error != nil {
		return nil, result.Error
	}

	return users, nil
}

// GetRoleGroups gets all groups with a role
func (r *RoleRepository) GetRoleGroups(ctx context.Context, roleID uuid.UUID) ([]model.Group, error) {
	var groups []model.Group

	result := r.DB.WithContext(ctx).Raw(`
		SELECT g.* FROM groups g
		JOIN group_roles gr ON g.id = gr.group_id
		WHERE gr.role_id = ? AND g.deleted_at IS NULL AND gr.deleted_at IS NULL
	`, roleID).Scan(&groups)

	if result.Error != nil {
		return nil, result.Error
	}

	return groups, nil
}