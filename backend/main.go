package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"backend/api"
	"backend/config"
	"backend/database"
	"backend/utils"
)

// @title Auth Service API
// @version 1.0
// @description Secure authentication and authorization service with RBAC
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.example.com/support
// @contact.email support@example.com

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /
// @schemes http https

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and the JWT token.

func main() {
	// Load configuration
	cfg := config.GetConfig()

	// Initialize logger
	logger := utils.NewLogger()
	logger.Info("Starting application")

	// Connect to database
	db, err := database.Connect(cfg)
	if err != nil {
		logger.WithError(err).Fatal("Failed to connect to database")
	}
	// Close database connection when application exits
	defer func() {
		if err := database.Close(db); err != nil {
			logger.WithError(err).Error("Failed to close database connection")
		}
	}()

	// Run migrations
	if err := database.Migrate(db); err != nil {
		logger.WithError(err).Fatal("Failed to run database migrations")
	}

	// Setup router
	router := api.SetupRouter(cfg, logger)

	// Create server
	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		logger.Infof("Server listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Failed to start server")
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down server...")

	// Create a deadline for server shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown server
	if err := server.Shutdown(ctx); err != nil {
		logger.WithError(err).Fatal("Server forced to shutdown")
	}

	logger.Info("Server exiting")
}
