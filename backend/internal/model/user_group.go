package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// UserGroup represents a many-to-many relationship between User and Group
type UserGroup struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index" json:"user_id" validate:"required"`
	GroupID   uuid.UUID `gorm:"type:uuid;not null;index" json:"group_id" validate:"required"`
	CreatedAt time.Time `gorm:"type:timestamp;default:now()" json:"created_at"`

	// Relationships
	User  User  `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Group Group `gorm:"foreignKey:GroupID" json:"group,omitempty"`
}

// TableName specifies the table name for UserGroup model
func (UserGroup) TableName() string {
	return "user_groups"
}

// BeforeCreate hook is called before creating a new record
func (ug *UserGroup) BeforeCreate(tx *gorm.DB) error {
	if ug.ID == uuid.Nil {
		ug.ID = uuid.New()
	}
	return nil
}
