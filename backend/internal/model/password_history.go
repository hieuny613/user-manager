package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PasswordHistory represents a password history record in the system
type PasswordHistory struct {
	ID           uuid.UUID `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
	UserID       uuid.UUID `gorm:"type:uuid;not null;index" json:"user_id" validate:"required"`
	PasswordHash string    `gorm:"type:varchar(255);not null" json:"-" validate:"required"` // Argon2id hash
	CreatedAt    time.Time `gorm:"type:timestamp;default:now()" json:"created_at"`
	IsExpired    bool      `gorm:"type:boolean;default:false" json:"is_expired"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName specifies the table name for PasswordHistory model
func (PasswordHistory) TableName() string {
	return "password_history"
}

// BeforeCreate hook is called before creating a new record
func (ph *PasswordHistory) BeforeCreate(tx *gorm.DB) error {
	if ph.ID == uuid.Nil {
		ph.ID = uuid.New()
	}
	return nil
}
