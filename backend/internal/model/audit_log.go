package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AuditLog represents an audit log record in the system
type AuditLog struct {
	ID        uuid.UUID  `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
	ActorID   *uuid.UUID `gorm:"type:uuid;index" json:"actor_id"` // Can be null for system actions
	Entity    string     `gorm:"type:varchar(100);not null" json:"entity" validate:"required"`
	EntityID  *uuid.UUID `gorm:"type:uuid" json:"entity_id"`
	Action    string     `gorm:"type:varchar(50);not null" json:"action" validate:"required"`
	OldValue  string     `gorm:"type:text" json:"old_value"`
	NewValue  string     `gorm:"type:text" json:"new_value"`
	IP        string     `gorm:"type:varchar(45)" json:"ip" validate:"omitempty,ip"`
	UserAgent string     `gorm:"type:varchar(255)" json:"user_agent" validate:"omitempty"`
	Status    string     `gorm:"type:varchar(50);not null" json:"status" validate:"required"`
	CreatedAt time.Time  `gorm:"type:timestamp;default:now()" json:"created_at"`

	// Relationships
	Actor *User `gorm:"foreignKey:ActorID" json:"actor,omitempty"`
}

// TableName specifies the table name for AuditLog model
func (AuditLog) TableName() string {
	return "audit_logs"
}

// BeforeCreate hook is called before creating a new record
func (al *AuditLog) BeforeCreate(tx *gorm.DB) error {
	if al.ID == uuid.Nil {
		al.ID = uuid.New()
	}
	return nil
}
