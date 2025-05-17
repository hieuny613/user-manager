package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID                uuid.UUID      `gorm:"type:uuid;primary_key;default:uuid_generate_v4()" json:"id"`
	Username          string         `gorm:"type:varchar(100);unique;not null" json:"username" validate:"required,min=3,max=100"`
	Email             string         `gorm:"type:varchar(255);unique;not null" json:"email" validate:"required,email,max=255"`
	FirstName         string         `gorm:"type:varchar(100)" json:"first_name" validate:"omitempty,max=100"`
	LastName          string         `gorm:"type:varchar(100)" json:"last_name" validate:"omitempty,max=100"`
	PasswordHash      string         `gorm:"type:varchar(255);not null" json:"-" validate:"required"` // Argon2id hash
	IsActive          bool           `gorm:"type:boolean;default:true" json:"is_active"`
	IsLocked          bool           `gorm:"type:boolean;default:false" json:"is_locked"`
	LastLogin         *time.Time     `gorm:"type:timestamp" json:"last_login"`
	LastLoginIP       string         `gorm:"type:varchar(45)" json:"last_login_ip" validate:"omitempty,ip"`
	PasswordChangedAt *time.Time     `gorm:"type:timestamp" json:"password_changed_at"`
	FailedCount       int            `gorm:"type:int;default:0" json:"failed_count"`
	LockedUntil       *time.Time     `gorm:"type:timestamp" json:"locked_until"`
	CreatedAt         time.Time      `gorm:"type:timestamp;default:now()" json:"created_at"`
	UpdatedAt         time.Time      `gorm:"type:timestamp;default:now()" json:"updated_at"`
	DeletedAt         gorm.DeletedAt `gorm:"type:timestamp;index" json:"deleted_at"`

	// Relationships (not stored in database)
	Groups          []Group           `gorm:"many2many:user_groups;" json:"groups,omitempty"`
	Roles           []Role            `gorm:"many2many:user_roles;" json:"roles,omitempty"`
	Sessions        []Session         `gorm:"foreignKey:UserID" json:"sessions,omitempty"`
	PasswordHistory []PasswordHistory `gorm:"foreignKey:UserID" json:"-"`
}

// TableName specifies the table name for User model
func (User) TableName() string {
	return "users"
}

// BeforeCreate hook is called before creating a new record
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

// BeforeUpdate hook is called before updating a record
func (u *User) BeforeUpdate(tx *gorm.DB) error {
	u.UpdatedAt = time.Now()
	return nil
}

// GetFullName returns the user's full name
func (u *User) GetFullName() string {
	if u.FirstName != "" && u.LastName != "" {
		return u.FirstName + " " + u.LastName
	}
	return u.Username
}

// IsPasswordExpired checks if the user's password is expired
func (u *User) IsPasswordExpired(expiryDays int) bool {
	if u.PasswordChangedAt == nil {
		return true
	}

	expiryDate := u.PasswordChangedAt.AddDate(0, 0, expiryDays)
	return time.Now().After(expiryDate)
}
