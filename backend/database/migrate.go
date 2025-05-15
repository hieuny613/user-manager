package database

import (
	"backend/model"
	"fmt"
	"log"
)

// Migrate runs database migrations
func Migrate() error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	log.Println("Running database migrations...")

	// Add all models that need to be migrated here
	models := []interface{}{
		&model.User{},
		&model.Group{},
		&model.Role{},
		&model.Permission{},
		&model.UserGroup{},
		&model.UserRole{},
		&model.GroupRole{},
		&model.RolePermission{},
		&model.Session{},
		&model.PasswordHistory{},
		&model.FailedLoginAttempt{},
		&model.SecurityEvent{},
		&model.AuditLog{},
	}

	// Create UUID extension if it doesn't exist
	db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")

	for _, model := range models {
		if err := db.AutoMigrate(model); err != nil {
			return fmt.Errorf("failed to migrate model: %w", err)
		}
	}

	log.Println("Database migrations completed successfully")
	return nil
}
