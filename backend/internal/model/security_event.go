package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SecurityEvent represents a security event in the system
type SecurityEvent struct {
	ID          uuid.UUID  `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
	UserID      *uuid.UUID `gorm:"type:uuid;index" json:"user_id"` // Can be null for system events or failed login attempts
	Type        string     `gorm:"type:varchar(100);not null" json:"type" validate:"required"`
	Description string     `gorm:"type:text" json:"description" validate:"omitempty"`
	IP          string     `gorm:"type:varchar(45)" json:"ip" validate:"omitempty,ip"`
	CreatedAt   time.Time  `gorm:"type:timestamp;default:now()" json:"created_at"`

	// Relationships
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName specifies the table name for SecurityEvent model
func (SecurityEvent) TableName() string {
	return "security_events"
}

// BeforeCreate hook is called before creating a new record
func (se *SecurityEvent) BeforeCreate(tx *gorm.DB) error {
	if se.ID == uuid.Nil {
		se.ID = uuid.New()
	}
	return nil
}
