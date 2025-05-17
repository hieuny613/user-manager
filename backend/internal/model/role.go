package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Role represents a role in the system
type Role struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
	Name        string         `gorm:"type:varchar(100);unique;not null" json:"name" validate:"required,min=2,max=100"`
	Description string         `gorm:"type:text" json:"description" validate:"omitempty"`
	CreatedAt   time.Time      `gorm:"type:timestamp;default:now()" json:"created_at"`
	UpdatedAt   time.Time      `gorm:"type:timestamp;default:now()" json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"type:timestamp;index" json:"deleted_at"`

	// Relationships (not stored in database)
	Users       []User       `gorm:"many2many:user_roles;" json:"users,omitempty"`
	Groups      []Group      `gorm:"many2many:group_roles;" json:"groups,omitempty"`
	Permissions []Permission `gorm:"many2many:role_permissions;" json:"permissions,omitempty"`
}

// TableName specifies the table name for Role model
func (Role) TableName() string {
	return "roles"
}

// BeforeCreate hook is called before creating a new record
func (r *Role) BeforeCreate(tx *gorm.DB) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	return nil
}

// BeforeUpdate hook is called before updating a record
func (r *Role) BeforeUpdate(tx *gorm.DB) error {
	r.UpdatedAt = time.Now()
	return nil
}
