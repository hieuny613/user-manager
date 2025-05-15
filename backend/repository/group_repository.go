package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"backend/model"
)

// GroupRepository handles database operations for groups
type GroupRepository struct {
	DB *gorm.DB
}

// NewGroupRepository creates a new group repository
func NewGroupRepository(db *gorm.DB) *GroupRepository {
	return &GroupRepository{DB: db}
}

// Create creates a new group
func (r *GroupRepository) Create(ctx context.Context, group *model.Group) error {
	return r.DB.WithContext(ctx).Create(group).Error
}

// GetByID gets a group by ID
func (r *GroupRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Group, error) {
	var group model.Group
	result := r.DB.WithContext(ctx).Where("id = ?", id).First(&group)
	if result.Error != nil {
		return nil, result.Error
	}
	return &group, nil
}

// GetByName gets a group by name
func (r *GroupRepository) GetByName(ctx context.Context, name string) (*model.Group, error) {
	var group model.Group
	result := r.DB.WithContext(ctx).Where("name = ?", name).First(&group)
	if result.Error != nil {
		return nil, result.Error
	}
	return &group, nil
}

// Update updates a group
func (r *GroupRepository) Update(ctx context.Context, group *model.Group) error {
	group.UpdatedAt = time.Now()
	return r.DB.WithContext(ctx).Save(group).Error
}

// Delete soft deletes a group
func (r *GroupRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.DB.WithContext(ctx).Model(&model.Group{}).Where("id = ?", id).Update("deleted_at", time.Now()).Error
}

// List lists groups with pagination
func (r *GroupRepository) List(ctx context.Context, page, pageSize int) ([]model.Group, int64, error) {
	var groups []model.Group
	var total int64

	// Get total count
	if err := r.DB.WithContext(ctx).Model(&model.Group{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get groups with pagination
	offset := (page - 1) * pageSize
	result := r.DB.WithContext(ctx).Offset(offset).Limit(pageSize).Find(&groups)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return groups, total, nil
}

// Search searches groups by name or description
func (r *GroupRepository) Search(ctx context.Context, query string, page, pageSize int) ([]model.Group, int64, error) {
	var groups []model.Group
	var total int64

	// Build search query
	searchQuery := r.DB.WithContext(ctx).Model(&model.Group{}).Where(
		"name ILIKE ? OR description ILIKE ?",
		"%"+query+"%", "%"+query+"%",
	)

	// Get total count
	if err := searchQuery.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get groups with pagination
	offset := (page - 1) * pageSize
	result := searchQuery.Offset(offset).Limit(pageSize).Find(&groups)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return groups, total, nil
}

// GetGroupUsers gets all users in a group
func (r *GroupRepository) GetGroupUsers(ctx context.Context, groupID uuid.UUID) ([]model.User, error) {
	var users []model.User

	result := r.DB.WithContext(ctx).Raw(`
		SELECT u.* FROM users u
		JOIN user_groups ug ON u.id = ug.user_id
		WHERE ug.group_id = ? AND u.deleted_at IS NULL AND ug.deleted_at IS NULL
	`, groupID).Scan(&users)

	if result.Error != nil {
		return nil, result.Error
	}

	return users, nil
}

// AssignRole assigns a role to a group
func (r *GroupRepository) AssignRole(ctx context.Context, groupID, roleID uuid.UUID) error {
	// Check if group exists
	var group model.Group
	result := r.DB.WithContext(ctx).Where("id = ?", groupID).First(&group)
	if result.Error != nil {
		return result.Error
	}

	// Check if role exists
	var role model.Role
	result = r.DB.WithContext(ctx).Where("id = ?", roleID).First(&role)
	if result.Error != nil {
		return result.Error
	}

	// Check if group already has the role
	var groupRole model.GroupRole
	result = r.DB.WithContext(ctx).Where("group_id = ? AND role_id = ?", groupID, roleID).First(&groupRole)
	if result.Error == nil {
		return errors.New("group already has the role")
	} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return result.Error
	}

	// Assign role to group
	groupRole = model.GroupRole{
		GroupID: groupID,
		RoleID:  roleID,
	}

	return r.DB.WithContext(ctx).Create(&groupRole).Error
}

// RemoveRole removes a role from a group
func (r *GroupRepository) RemoveRole(ctx context.Context, groupID, roleID uuid.UUID) error {
	return r.DB.WithContext(ctx).Where("group_id = ? AND role_id = ?", groupID, roleID).Delete(&model.GroupRole{}).Error
}

// GetGroupRoles gets all roles for a group
func (r *GroupRepository) GetGroupRoles(ctx context.Context, groupID uuid.UUID) ([]model.Role, error) {
	var roles []model.Role

	result := r.DB.WithContext(ctx).Raw(`
		SELECT r.* FROM roles r
		JOIN group_roles gr ON r.id = gr.role_id
		WHERE gr.group_id = ? AND r.deleted_at IS NULL AND gr.deleted_at IS NULL
	`, groupID).Scan(&roles)

	if result.Error != nil {
		return nil, result.Error
	}

	return roles, nil
}

// GetGroupPermissions gets all permissions for a group
func (r *GroupRepository) GetGroupPermissions(ctx context.Context, groupID uuid.UUID) ([]model.Permission, error) {
	var permissions []model.Permission

	result := r.DB.WithContext(ctx).Raw(`
		SELECT DISTINCT p.* FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN roles r ON rp.role_id = r.id
		JOIN group_roles gr ON r.id = gr.role_id
		WHERE gr.group_id = ? AND p.deleted_at IS NULL AND r.deleted_at IS NULL AND gr.deleted_at IS NULL AND rp.deleted_at IS NULL
	`, groupID).Scan(&permissions)

	if result.Error != nil {
		return nil, result.Error
	}

	return permissions, nil
}