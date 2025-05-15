package database

import (
	"fmt"
)

// Ping checks if the database connection is alive
func Ping() error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	return nil
}
