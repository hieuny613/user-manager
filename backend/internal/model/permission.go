package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Permission represents a permission in the system
type Permission struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
	Name        string         `gorm:"type:varchar(100);unique;not null" json:"name" validate:"required,min=2,max=100"`
	Description string         `gorm:"type:text" json:"description" validate:"omitempty"`
	CreatedAt   time.Time      `gorm:"type:timestamp;default:now()" json:"created_at"`
	UpdatedAt   time.Time      `gorm:"type:timestamp;default:now()" json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"type:timestamp;index" json:"deleted_at"`

	// Relationships (not stored in database)
	Roles []Role `gorm:"many2many:role_permissions;" json:"roles,omitempty"`
}

// TableName specifies the table name for Permission model
func (Permission) TableName() string {
	return "permissions"
}

// BeforeCreate hook is called before creating a new record
func (p *Permission) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}

// BeforeUpdate hook is called before updating a record
func (p *Permission) BeforeUpdate(tx *gorm.DB) error {
	p.UpdatedAt = time.Now()
	return nil
}
