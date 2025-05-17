package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Group represents a user group in the system
type Group struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
	Name        string         `gorm:"type:varchar(100);unique;not null" json:"name" validate:"required,min=2,max=100"`
	Description string         `gorm:"type:text" json:"description" validate:"omitempty"`
	CreatedAt   time.Time      `gorm:"type:timestamp;default:now()" json:"created_at"`
	UpdatedAt   time.Time      `gorm:"type:timestamp;default:now()" json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"type:timestamp;index" json:"deleted_at"`

	// Relationships (not stored in database)
	Users []User `gorm:"many2many:user_groups;" json:"users,omitempty"`
	Roles []Role `gorm:"many2many:group_roles;" json:"roles,omitempty"`
}

// TableName specifies the table name for Group model
func (Group) TableName() string {
	return "groups"
}

// BeforeCreate hook is called before creating a new record
func (g *Group) BeforeCreate(tx *gorm.DB) error {
	if g.ID == uuid.Nil {
		g.ID = uuid.New()
	}
	return nil
}

// BeforeUpdate hook is called before updating a record
func (g *Group) BeforeUpdate(tx *gorm.DB) error {
	g.UpdatedAt = time.Now()
	return nil
}
