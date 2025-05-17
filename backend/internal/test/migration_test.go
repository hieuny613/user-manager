package test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	pgDriver "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// testContainer holds the testcontainer instance and connection details
type testContainer struct {
	container  testcontainers.Container
	host       string
	port       string
	user       string
	password   string
	dbName     string
	connection *sql.DB
	dsn        string
}

// setupTestContainer sets up a PostgreSQL test container
func setupTestContainer(t *testing.T) (*testContainer, error) {
	ctx := context.Background()

	// Define the container request
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "testuser",
			"POSTGRES_PASSWORD": "testpass",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForAll(
			wait.ForLog("database system is ready to accept connections"),
			wait.ForListeningPort("5432/tcp"),
		),
		Cmd: []string{
			"postgres",
			"-c", "fsync=off",
			"-c", "synchronous_commit=off",
			"-c", "full_page_writes=off",
		},
	}

	// Start the container
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Get host and port
	host, err := container.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get container host: %w", err)
	}

	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return nil, fmt.Errorf("failed to get container port: %w", err)
	}

	// Create a test container instance
	tc := &testContainer{
		container: container,
		host:      host,
		port:      port.Port(),
		user:      "testuser",
		password:  "testpass",
		dbName:    "testdb",
	}

	// Create DSN
	tc.dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		tc.host, tc.port, tc.user, tc.password, tc.dbName)

	// Connect to the database
	db, err := sql.Open("postgres", tc.dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Check connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	tc.connection = db
	return tc, nil
}

// teardownTestContainer cleans up the test container
func teardownTestContainer(t *testing.T, tc *testContainer) {
	if tc.connection != nil {
		if err := tc.connection.Close(); err != nil {
			t.Logf("Failed to close database connection: %v", err)
		}
	}

	if tc.container != nil {
		if err := tc.container.Terminate(context.Background()); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}
}

// runMigrations runs the migrations on the test database
func runMigrations(t *testing.T, db *sql.DB, migrationsPath string) error {
	// Create the postgres driver for migration
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create database driver: %w", err)
	}

	// Get absolute path to migrations
	absPath, err := filepath.Abs(migrationsPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path to migrations: %w", err)
	}

	// Create migrate instance
	m, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", absPath),
		"postgres", driver)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	// Run migrations
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

// TestMigrations tests that migrations can be applied successfully
func TestMigrations(t *testing.T) {
	// Set up test container
	tc, err := setupTestContainer(t)
	require.NoError(t, err, "Failed to set up test container")
	defer teardownTestContainer(t, tc)

	// Run migrations
	migrationsPath := "../../internal/migration"
	err = runMigrations(t, tc.connection, migrationsPath)
	require.NoError(t, err, "Failed to run migrations")

	// Connect using GORM
	gormDB, err := gorm.Open(pgDriver.New(pgDriver.Config{
		Conn: tc.connection,
	}), &gorm.Config{})
	require.NoError(t, err, "Failed to connect to database using GORM")

	// Test migrations by querying tables
	testTables := []string{
		"users", "groups", "roles", "permissions",
		"user_groups", "user_roles", "group_roles", "role_permissions",
		"sessions", "password_history", "password_reset_tokens",
		"audit_logs", "security_events",
	}

	for _, table := range testTables {
		var exists bool
		query := fmt.Sprintf("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '%s')", table)
		err := gormDB.Raw(query).Scan(&exists).Error
		assert.NoError(t, err, "Failed to check if table exists: %s", table)
		assert.True(t, exists, "Table does not exist: %s", table)
	}

	// Test UUID extension
	var hasUUIDExtension bool
	err = gormDB.Raw("SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'uuid-ossp')").Scan(&hasUUIDExtension).Error
	assert.NoError(t, err, "Failed to check if uuid-ossp extension exists")
	assert.True(t, hasUUIDExtension, "uuid-ossp extension is not enabled")

	// Test insert and retrieve data
	t.Run("TestInsertUser", func(t *testing.T) {
		// Insert a test user
		userID := "12345678-1234-1234-1234-123456789012"
		query := `
        INSERT INTO users (id, username, email, password_hash, is_active) 
        VALUES ($1, $2, $3, $4, $5)
        `
		_, err := tc.connection.Exec(query, userID, "testuser", "test@example.com", "argon2hash", true)
		assert.NoError(t, err, "Failed to insert test user")

		// Retrieve the user
		var count int64
		err = gormDB.Raw("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&count).Error
		assert.NoError(t, err, "Failed to retrieve test user")
		assert.Equal(t, int64(1), count, "Failed to find inserted user")
	})

	t.Run("TestRelationships", func(t *testing.T) {
		// Insert test data for relationships
		userID := "12345678-1234-1234-1234-123456789012"
		groupID := "22345678-1234-1234-1234-123456789012"
		roleID := "32345678-1234-1234-1234-123456789012"
		permissionID := "42345678-1234-1234-1234-123456789012"

		// Insert a group
		_, err := tc.connection.Exec(
			"INSERT INTO groups (id, name) VALUES ($1, $2)",
			groupID, "testgroup",
		)
		assert.NoError(t, err, "Failed to insert test group")

		// Insert a role
		_, err = tc.connection.Exec(
			"INSERT INTO roles (id, name) VALUES ($1, $2)",
			roleID, "testrole",
		)
		assert.NoError(t, err, "Failed to insert test role")

		// Insert a permission
		_, err = tc.connection.Exec(
			"INSERT INTO permissions (id, name) VALUES ($1, $2)",
			permissionID, "testpermission",
		)
		assert.NoError(t, err, "Failed to insert test permission")

		// Insert user_group relationship
		_, err = tc.connection.Exec(
			"INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)",
			userID, groupID,
		)
		assert.NoError(t, err, "Failed to insert user_group relationship")

		// Insert user_role relationship
		_, err = tc.connection.Exec(
			"INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)",
			userID, roleID,
		)
		assert.NoError(t, err, "Failed to insert user_role relationship")

		// Insert group_role relationship
		_, err = tc.connection.Exec(
			"INSERT INTO group_roles (group_id, role_id) VALUES ($1, $2)",
			groupID, roleID,
		)
		assert.NoError(t, err, "Failed to insert group_role relationship")

		// Insert role_permission relationship
		_, err = tc.connection.Exec(
			"INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
			roleID, permissionID,
		)
		assert.NoError(t, err, "Failed to insert role_permission relationship")

		// Test the relationships
		var count int64
		err = gormDB.Raw("SELECT COUNT(*) FROM user_groups WHERE user_id = ? AND group_id = ?", userID, groupID).Scan(&count).Error
		assert.NoError(t, err, "Failed to query user_groups")
		assert.Equal(t, int64(1), count, "Failed to find user_group relationship")

		err = gormDB.Raw("SELECT COUNT(*) FROM role_permissions WHERE role_id = ? AND permission_id = ?", roleID, permissionID).Scan(&count).Error
		assert.NoError(t, err, "Failed to query role_permissions")
		assert.Equal(t, int64(1), count, "Failed to find role_permission relationship")
	})

	t.Run("TestUUIDGeneration", func(t *testing.T) {
		// Test UUID generation
		var generatedID string
		err := gormDB.Raw("SELECT uuid_generate_v4()").Scan(&generatedID).Error
		assert.NoError(t, err, "Failed to generate UUID")
		assert.NotEmpty(t, generatedID, "Generated UUID is empty")
		assert.Len(t, generatedID, 36, "Generated UUID has incorrect length")
	})
}

// TestMigrationDown tests that migrations can be rolled back successfully
func TestMigrationDown(t *testing.T) {
	// Set up test container
	tc, err := setupTestContainer(t)
	require.NoError(t, err, "Failed to set up test container")
	defer teardownTestContainer(t, tc)

	// Get the database driver
	driver, err := postgres.WithInstance(tc.connection, &postgres.Config{})
	require.NoError(t, err, "Failed to create database driver")

	// Get absolute path to migrations
	migrationsPath, err := filepath.Abs("../../internal/migration")
	require.NoError(t, err, "Failed to get absolute path to migrations")

	// Create migrate instance
	m, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", migrationsPath),
		"postgres", driver)
	require.NoError(t, err, "Failed to create migrate instance")

	// Run migrations up
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		require.NoError(t, err, "Failed to run migrations up")
	}

	// Connect using GORM
	gormDB, err := gorm.Open(pgDriver.New(pgDriver.Config{
		Conn: tc.connection,
	}), &gorm.Config{})
	require.NoError(t, err, "Failed to connect to database using GORM")

	// Check tables exist
	var tableCount int64
	err = gormDB.Raw("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'").Scan(&tableCount).Error
	assert.NoError(t, err, "Failed to count tables")
	assert.Greater(t, tableCount, int64(0), "No tables found after migration up")

	// Run migrations down
	if err := m.Down(); err != nil {
		require.NoError(t, err, "Failed to run migrations down")
	}

	// Define application tables that should be dropped
	testTables := []string{
		"users", "groups", "roles", "permissions",
		"user_groups", "user_roles", "group_roles", "role_permissions",
		"sessions", "password_history", "password_reset_tokens",
		"audit_logs", "security_events",
	}

	// Check that each application table is gone
	for _, table := range testTables {
		var exists bool
		query := fmt.Sprintf("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '%s')", table)
		err := gormDB.Raw(query).Scan(&exists).Error
		assert.NoError(t, err, "Failed to check if table exists: %s", table)
		assert.False(t, exists, "Table still exists after migration down: %s", table)
	}

	// Alternative check - exclude known system/migration tables
	var appTableCount int64
	err = gormDB.Raw(`
        SELECT COUNT(*) FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name NOT IN ('schema_migrations', 'goose_db_version', 'migrations', 'schema_history') 
        AND table_name NOT LIKE 'pg_%'
        AND table_name NOT IN (?)
    `, "spatial_ref_sys").Scan(&appTableCount).Error
	assert.NoError(t, err, "Failed to count application tables after migration down")
	assert.Equal(t, int64(0), appTableCount, "Application tables still exist after migration down")
}

// TestMain is the entry point for the test package
func TestMain(m *testing.M) {
	// Initialize logger
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Run tests
	code := m.Run()
	os.Exit(code)
}
