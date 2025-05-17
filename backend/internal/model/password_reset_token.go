package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PasswordResetToken represents a password reset token in the system
type PasswordResetToken struct {
	ID        uuid.UUID  `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
	UserID    uuid.UUID  `gorm:"type:uuid;not null;index" json:"user_id" validate:"required"`
	Token     string     `gorm:"type:varchar(128);unique;not null" json:"token" validate:"required"`
	ExpireAt  time.Time  `gorm:"type:timestamp;not null" json:"expire_at" validate:"required"`
	UsedAt    *time.Time `gorm:"type:timestamp" json:"used_at"`
	CreatedAt time.Time  `gorm:"type:timestamp;default:now()" json:"created_at"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName specifies the table name for PasswordResetToken model
func (PasswordResetToken) TableName() string {
	return "password_reset_tokens"
}

// BeforeCreate hook is called before creating a new record
func (prt *PasswordResetToken) BeforeCreate(tx *gorm.DB) error {
	if prt.ID == uuid.Nil {
		prt.ID = uuid.New()
	}
	return nil
}

// IsExpired checks if the token is expired
func (prt *PasswordResetToken) IsExpired() bool {
	return time.Now().After(prt.ExpireAt)
}

// IsUsed checks if the token has been used
func (prt *PasswordResetToken) IsUsed() bool {
	return prt.UsedAt != nil
}

// IsValid checks if the token is valid (not expired, not used)
func (prt *PasswordResetToken) IsValid() bool {
	return !prt.IsExpired() && !prt.IsUsed()
}
