package api

import (
	"time"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"backend/config"
	"backend/service"
	"backend/utils"
)

// SetupRouter sets up the router
func SetupRouter(cfg *config.Config, logger *utils.Logger) *gin.Engine {
	// Set Gin mode
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router
	router := gin.New()

	// Add middlewares
	router.Use(gin.Recovery())
	router.Use(v1.RequestIDMiddleware())
	router.Use(v1.LoggingMiddleware(utils.NewLogger()))
	router.Use(v1.CORSMiddleware())
	router.Use(v1.SecurityHeadersMiddleware())
	router.Use(v1.RateLimitMiddleware())

	// Add health check endpoint
	router.GET("/health", func(c *gin.Context) {
		// Check database connection
		dbStatus := "ok"
		if err := database.Ping(); err != nil {
			dbStatus = "error: " + err.Error()
		}

		// Get system info
		systemInfo := map[string]string{
			"version":     cfg.Version,
			"environment": cfg.Environment,
			"timestamp":   time.Now().Format(time.RFC3339),
		}

		c.JSON(200, gin.H{
			"status":      "ok",
			"database":    dbStatus,
			"system_info": systemInfo,
		})
	})

	// Add Swagger documentation
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Create API v1 group
	v1Group := router.Group("/api/v1")

	// Create services
	authService := service.NewAuthService()
	userService := service.NewUserService()
	groupService := service.NewGroupService()
	roleService := service.NewRoleService()
	permissionService := service.NewPermissionService()
	auditService := service.NewAuditService()

	// Create handlers
	authHandler := v1.NewAuthHandler(authService, logger)
	userHandler := v1.NewUserHandler(userService, logger)
	groupHandler := v1.NewGroupHandler(groupService, logger)
	roleHandler := v1.NewRoleHandler(roleService, logger)
	permissionHandler := v1.NewPermissionHandler(permissionService, logger)
	auditHandler := v1.NewAuditHandler(auditService, logger)

	// Register routes
	authHandler.RegisterRoutes(v1Group)
	userHandler.RegisterRoutes(v1Group)
	groupHandler.RegisterRoutes(v1Group)
	roleHandler.RegisterRoutes(v1Group)
	permissionHandler.RegisterRoutes(v1Group)
	auditHandler.RegisterRoutes(v1Group)

	return router
}
