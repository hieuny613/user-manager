# Makefile

# Variables
APP_NAME := user-management
BUILD_DIR := build
MAIN_PATH := cmd/api/main.go
MIGRATION_DIR := internal/migration
GO := go
GOOSE := goose
DOCKER := docker
COMPOSE := docker-compose
MODULE := yourproject

# Build flags
LDFLAGS := -ldflags "-s -w"

.PHONY: all clean build run test migrate migrate-up migrate-down test-migrate vet lint

# Default target
all: clean build

# Clean build artifacts
clean:
    @echo "Cleaning build artifacts..."
    @rm -rf $(BUILD_DIR)
    @mkdir -p $(BUILD_DIR)

# Build the application
build:
    @echo "Building $(APP_NAME)..."
    @$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME) $(MAIN_PATH)

# Run the application
run:
    @echo "Running $(APP_NAME)..."
    @$(GO) run $(MAIN_PATH)

# Run tests
test:
    @echo "Running tests..."
    @$(GO) test -v ./internal/... ./pkg/...

# Install migration tool (goose)
install-goose:
    @echo "Installing goose migration tool..."
    @$(GO) install github.com/pressly/goose/v3/cmd/goose@latest

# Create a new migration file
migration-create:
    @echo "Creating migration file..."
    @$(GOOSE) -dir $(MIGRATION_DIR) create $(name) sql

# Run migrations up
migrate-up:
    @echo "Running migrations up..."
    @$(GOOSE) -dir $(MIGRATION_DIR) postgres "host=$(DB_HOST) port=$(DB_PORT) user=$(DB_USER) password=$(DB_PASSWORD) dbname=$(DB_NAME) sslmode=$(DB_SSL_MODE)" up

# Run migrations down
migrate-down:
    @echo "Running migrations down..."
    @$(GOOSE) -dir $(MIGRATION_DIR) postgres "host=$(DB_HOST) port=$(DB_PORT) user=$(DB_USER) password=$(DB_PASSWORD) dbname=$(DB_NAME) sslmode=$(DB_SSL_MODE)" down

# Run specific migration
migrate-to:
    @echo "Running migration to version $(version)..."
    @$(GOOSE) -dir $(MIGRATION_DIR) postgres "host=$(DB_HOST) port=$(DB_PORT) user=$(DB_USER) password=$(DB_PASSWORD) dbname=$(DB_NAME) sslmode=$(DB_SSL_MODE)" goto $(version)

# Get current migration status
migrate-status:
    @echo "Getting migration status..."
    @$(GOOSE) -dir $(MIGRATION_DIR) postgres "host=$(DB_HOST) port=$(DB_PORT) user=$(DB_USER) password=$(DB_PASSWORD) dbname=$(DB_NAME) sslmode=$(DB_SSL_MODE)" status

# Run migration tests
test-migrate:
    @echo "Running migration tests..."
    @$(GO) test -v ./internal/test/migration_test.go

# Run vet tool
vet:
    @echo "Running go vet..."
    @$(GO) vet ./...

# Run linter
lint:
    @echo "Running linter..."
    @golangci-lint run ./...

# Run the application in docker
docker-run:
    @echo "Running in Docker..."
    @$(COMPOSE) up --build

# Stop docker containers
docker-stop:
    @echo "Stopping Docker containers..."
    @$(COMPOSE) down