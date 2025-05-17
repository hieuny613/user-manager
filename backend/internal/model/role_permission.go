package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RolePermission represents a many-to-many relationship between Role and Permission
type RolePermission struct {
	ID           uuid.UUID `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
	RoleID       uuid.UUID `gorm:"type:uuid;not null;index" json:"role_id" validate:"required"`
	PermissionID uuid.UUID `gorm:"type:uuid;not null;index" json:"permission_id" validate:"required"`
	CreatedAt    time.Time `gorm:"type:timestamp;default:now()" json:"created_at"`

	// Relationships
	Role       Role       `gorm:"foreignKey:RoleID" json:"role,omitempty"`
	Permission Permission `gorm:"foreignKey:PermissionID" json:"permission,omitempty"`
}

// TableName specifies the table name for RolePermission model
func (RolePermission) TableName() string {
	return "role_permissions"
}

// BeforeCreate hook is called before creating a new record
func (rp *RolePermission) BeforeCreate(tx *gorm.DB) error {
	if rp.ID == uuid.Nil {
		rp.ID = uuid.New()
	}
	return nil
}
