package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Session represents a user session in the system
type Session struct {
	ID          uuid.UUID  `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
	UserID      uuid.UUID  `gorm:"type:uuid;not null;index" json:"user_id" validate:"required"`
	Device      string     `gorm:"type:varchar(255)" json:"device" validate:"omitempty"`
	IP          string     `gorm:"type:varchar(45)" json:"ip" validate:"omitempty,ip"`
	Fingerprint string     `gorm:"type:varchar(255)" json:"fingerprint" validate:"omitempty"`
	IsActive    bool       `gorm:"type:boolean;default:true" json:"is_active"`
	CreatedAt   time.Time  `gorm:"type:timestamp;default:now()" json:"created_at"`
	ExpiredAt   time.Time  `gorm:"type:timestamp;not null" json:"expired_at" validate:"required"`
	RevokedAt   *time.Time `gorm:"type:timestamp" json:"revoked_at"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName specifies the table name for Session model
func (Session) TableName() string {
	return "sessions"
}

// BeforeCreate hook is called before creating a new record
func (s *Session) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}

// IsExpired checks if the session is expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiredAt)
}

// IsRevoked checks if the session is revoked
func (s *Session) IsRevoked() bool {
	return s.RevokedAt != nil
}

// IsValid checks if the session is valid (active, not expired, not revoked)
func (s *Session) IsValid() bool {
	return s.IsActive && !s.IsExpired() && !s.IsRevoked()
}
