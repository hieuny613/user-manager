package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Base model with common fields
type Base struct {
	ID        uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	CreatedAt time.Time      `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt time.Time      `json:"updated_at" gorm:"default:CURRENT_TIMESTAMP"`
	DeletedAt gorm.DeletedAt `json:"deleted_at,omitempty" gorm:"index"`
}

// User represents a user in the system
type User struct {
	Base
	Email                   string     `json:"email" gorm:"type:varchar(255);uniqueIndex;not null"`
	Username                string     `json:"username" gorm:"type:varchar(50);uniqueIndex;not null"`
	PasswordHash            string     `json:"-" gorm:"type:varchar(255);not null"`
	FirstName               string     `json:"first_name,omitempty" gorm:"type:varchar(50)"`
	LastName                string     `json:"last_name,omitempty" gorm:"type:varchar(50)"`
	IsActive                bool       `json:"is_active" gorm:"default:true"`
	IsEmailVerified         bool       `json:"is_email_verified" gorm:"default:false"`
	EmailVerificationToken  *uuid.UUID `json:"-" gorm:"type:uuid"`
	EmailVerificationSentAt *time.Time `json:"-" gorm:"type:timestamp with time zone"`
	PasswordResetToken      *uuid.UUID `json:"-" gorm:"type:uuid"`
	PasswordResetSentAt     *time.Time `json:"-" gorm:"type:timestamp with time zone"`
	PasswordChangedAt       *time.Time `json:"-" gorm:"type:timestamp with time zone"`
	LastLoginAt             *time.Time `json:"last_login_at,omitempty" gorm:"type:timestamp with time zone"`
	LastLoginIP             string     `json:"-" gorm:"type:varchar(45)"`

	// Relationships
	Groups            []Group            `json:"groups,omitempty" gorm:"many2many:user_groups;"`
	Roles             []Role             `json:"roles,omitempty" gorm:"many2many:user_roles;"`
	Sessions          []Session          `json:"sessions,omitempty" gorm:"foreignKey:UserID"`
	PasswordHistory   []PasswordHistory  `json:"-" gorm:"foreignKey:UserID"`
	FailedLoginAttempts []FailedLoginAttempt `json:"-" gorm:"foreignKey:UserID"`
}

// Group represents a user group
type Group struct {
	Base
	Name        string `json:"name" gorm:"type:varchar(100);uniqueIndex;not null"`
	Description string `json:"description,omitempty" gorm:"type:text"`

	// Relationships
	Users []User `json:"users,omitempty" gorm:"many2many:user_groups;"`
	Roles []Role `json:"roles,omitempty" gorm:"many2many:group_roles;"`
}

// Role represents a role in the system
type Role struct {
	Base
	Name        string `json:"name" gorm:"type:varchar(100);uniqueIndex;not null"`
	Description string `json:"description,omitempty" gorm:"type:text"`

	// Relationships
	Users       []User       `json:"users,omitempty" gorm:"many2many:user_roles;"`
	Groups      []Group      `json:"groups,omitempty" gorm:"many2many:group_roles;"`
	Permissions []Permission `json:"permissions,omitempty" gorm:"many2many:role_permissions;"`
}

// Permission represents a permission in the system
type Permission struct {
	Base
	Name        string `json:"name" gorm:"type:varchar(100);uniqueIndex;not null"`
	Resource    string `json:"resource" gorm:"type:varchar(100);not null"`
	Action      string `json:"action" gorm:"type:varchar(50);not null"`
	Description string `json:"description,omitempty" gorm:"type:text"`

	// Relationships
	Roles []Role `json:"roles,omitempty" gorm:"many2many:role_permissions;"`
}

// UserGroup represents the many-to-many relationship between users and groups
type UserGroup struct {
	Base
	UserID  uuid.UUID `json:"user_id" gorm:"type:uuid;not null"`
	GroupID uuid.UUID `json:"group_id" gorm:"type:uuid;not null"`

	// Relationships
	User  User  `json:"user" gorm:"foreignKey:UserID"`
	Group Group `json:"group" gorm:"foreignKey:GroupID"`
}

// UserRole represents the many-to-many relationship between users and roles
type UserRole struct {
	Base
	UserID uuid.UUID `json:"user_id" gorm:"type:uuid;not null"`
	RoleID uuid.UUID `json:"role_id" gorm:"type:uuid;not null"`

	// Relationships
	User User `json:"user" gorm:"foreignKey:UserID"`
	Role Role `json:"role" gorm:"foreignKey:RoleID"`
}

// GroupRole represents the many-to-many relationship between groups and roles
type GroupRole struct {
	Base
	GroupID uuid.UUID `json:"group_id" gorm:"type:uuid;not null"`
	RoleID  uuid.UUID `json:"role_id" gorm:"type:uuid;not null"`

	// Relationships
	Group Group `json:"group" gorm:"foreignKey:GroupID"`
	Role  Role  `json:"role" gorm:"foreignKey:RoleID"`
}

// RolePermission represents the many-to-many relationship between roles and permissions
type RolePermission struct {
	Base
	RoleID       uuid.UUID `json:"role_id" gorm:"type:uuid;not null"`
	PermissionID uuid.UUID `json:"permission_id" gorm:"type:uuid;not null"`

	// Relationships
	Role       Role       `json:"role" gorm:"foreignKey:RoleID"`
	Permission Permission `json:"permission" gorm:"foreignKey:PermissionID"`
}

// Session represents a user session
type Session struct {
	Base
	UserID         uuid.UUID  `json:"user_id" gorm:"type:uuid;not null"`
	TokenJTI       uuid.UUID  `json:"token_jti" gorm:"type:uuid;uniqueIndex;not null"`
	RefreshTokenJTI *uuid.UUID `json:"refresh_token_jti,omitempty" gorm:"type:uuid;uniqueIndex"`
	DeviceInfo     string     `json:"device_info,omitempty" gorm:"type:jsonb"`
	IPAddress      string     `json:"ip_address,omitempty" gorm:"type:varchar(45)"`
	UserAgent      string     `json:"user_agent,omitempty" gorm:"type:text"`
	ExpiresAt      time.Time  `json:"expires_at" gorm:"type:timestamp with time zone;not null"`
	IsActive       bool       `json:"is_active" gorm:"default:true"`

	// Relationships
	User User `json:"user" gorm:"foreignKey:UserID"`
}

// PasswordHistory represents a user's password history
type PasswordHistory struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	UserID       uuid.UUID `json:"user_id" gorm:"type:uuid;not null"`
	PasswordHash string    `json:"-" gorm:"type:varchar(255);not null"`
	CreatedAt    time.Time `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`

	// Relationships
	User User `json:"user" gorm:"foreignKey:UserID"`
}

// FailedLoginAttempt represents a failed login attempt
type FailedLoginAttempt struct {
	ID         uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	UserID     *uuid.UUID `json:"user_id,omitempty" gorm:"type:uuid"`
	Email      string     `json:"email,omitempty" gorm:"type:varchar(255)"`
	IPAddress  string     `json:"ip_address" gorm:"type:varchar(45);not null"`
	UserAgent  string     `json:"user_agent,omitempty" gorm:"type:text"`
	AttemptTime time.Time  `json:"attempt_time" gorm:"type:timestamp with time zone;default:CURRENT_TIMESTAMP"`

	// Relationships
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	UserID      *uuid.UUID `json:"user_id,omitempty" gorm:"type:uuid"`
	EventType   string     `json:"event_type" gorm:"type:varchar(50);not null"`
	Description string     `json:"description,omitempty" gorm:"type:text"`
	IPAddress   string     `json:"ip_address,omitempty" gorm:"type:varchar(45)"`
	UserAgent   string     `json:"user_agent,omitempty" gorm:"type:text"`
	CreatedAt   time.Time  `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`

	// Relationships
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID           uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:uuid_generate_v4()"`
	UserID       *uuid.UUID `json:"user_id,omitempty" gorm:"type:uuid"`
	Action       string     `json:"action" gorm:"type:varchar(50);not null"`
	ResourceType string     `json:"resource_type" gorm:"type:varchar(50);not null"`
	ResourceID   *uuid.UUID `json:"resource_id,omitempty" gorm:"type:uuid"`
	OldValues    string     `json:"old_values,omitempty" gorm:"type:jsonb"`
	NewValues    string     `json:"new_values,omitempty" gorm:"type:jsonb"`
	IPAddress    string     `json:"ip_address,omitempty" gorm:"type:varchar(45)"`
	UserAgent    string     `json:"user_agent,omitempty" gorm:"type:text"`
	CreatedAt    time.Time  `json:"created_at" gorm:"default:CURRENT_TIMESTAMP"`

	// Relationships
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}