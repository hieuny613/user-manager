package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GroupRole represents a many-to-many relationship between Group and Role
type GroupRole struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
	GroupID   uuid.UUID `gorm:"type:uuid;not null;index" json:"group_id" validate:"required"`
	RoleID    uuid.UUID `gorm:"type:uuid;not null;index" json:"role_id" validate:"required"`
	CreatedAt time.Time `gorm:"type:timestamp;default:now()" json:"created_at"`

	// Relationships
	Group Group `gorm:"foreignKey:GroupID" json:"group,omitempty"`
	Role  Role  `gorm:"foreignKey:RoleID" json:"role,omitempty"`
}

// TableName specifies the table name for GroupRole model
func (GroupRole) TableName() string {
	return "group_roles"
}

// BeforeCreate hook is called before creating a new record
func (gr *GroupRole) BeforeCreate(tx *gorm.DB) error {
	if gr.ID == uuid.Nil {
		gr.ID = uuid.New()
	}
	return nil
}
