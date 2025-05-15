package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"backend/service"
)

// PermissionHandler handles permission-related requests
type PermissionHandler struct {
	PermissionService *service.PermissionService
	Logger            *logrus.Logger
}

// NewPermissionHandler creates a new permission handler
func NewPermissionHandler(permissionService *service.PermissionService, logger *logrus.Logger) *PermissionHandler {
	return &PermissionHandler{
		PermissionService: permissionService,
		Logger:            logger,
	}
}

// @Summary Get permission by ID
// @Description Get a permission by ID
// @Tags permissions
// @Produce json
// @Param id path string true "Permission ID"
// @Success 200 {object} PermissionResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/permissions/{id} [get]
func (h *PermissionHandler) GetPermissionByID(c *gin.Context) {
	// Get permission ID from path
	id := c.Param("id")

	// Call permission service
	permission, err := h.PermissionService.GetPermissionByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, permission)
}

// @Summary List permissions
// @Description List permissions with pagination
// @Tags permissions
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(10)
// @Success 200 {object} service.PermissionsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/permissions [get]
func (h *PermissionHandler) ListPermissions(c *gin.Context) {
	// Get pagination parameters
	var params PaginationParams
	if err := c.ShouldBindQuery(&params); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid pagination parameters"})
		return
	}

	// Call permission service
	permissions, err := h.PermissionService.ListPermissions(c.Request.Context(), params.Page, params.PageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, permissions)
}

// @Summary Search permissions
// @Description Search permissions by name, resource, or action
// @Tags permissions
// @Produce json
// @Param q query string true "Search query"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(10)
// @Success 200 {object} service.PermissionsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/permissions/search [get]
func (h *PermissionHandler) SearchPermissions(c *gin.Context) {
	// Get search query
	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Search query is required"})
		return
	}

	// Get pagination parameters
	var params PaginationParams
	if err := c.ShouldBindQuery(&params); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid pagination parameters"})
		return
	}

	// Call permission service
	permissions, err := h.PermissionService.SearchPermissions(c.Request.Context(), query, params.Page, params.PageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, permissions)
}

// @Summary Create permission
// @Description Create a new permission
// @Tags permissions
// @Accept json
// @Produce json
// @Param request body service.CreatePermissionRequest true "Permission details"
// @Success 201 {object} PermissionResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/permissions [post]
func (h *PermissionHandler) CreatePermission(c *gin.Context) {
	var req service.CreatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request: " + err.Error()})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized"})
		return
	}

	// Parse user ID
	creatorID, err := uuid.Parse(userID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid user ID"})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call permission service
	permission, err := h.PermissionService.CreatePermission(c.Request.Context(), req, creatorID, ipAddress, userAgent)
	if err != nil {
		if err.Error() == "permission already exists" {
			c.JSON(http.StatusConflict, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusCreated, permission)
}

// @Summary Update permission
// @Description Update a permission
// @Tags permissions
// @Accept json
// @Produce json
// @Param id path string true "Permission ID"
// @Param request body service.UpdatePermissionRequest true "Permission details"
// @Success 200 {object} PermissionResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/permissions/{id} [put]
func (h *PermissionHandler) UpdatePermission(c *gin.Context) {
	// Get permission ID from path
	id := c.Param("id")

	var req service.UpdatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request: " + err.Error()})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized"})
		return
	}

	// Parse user ID
	updaterID, err := uuid.Parse(userID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid user ID"})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call permission service
	permission, err := h.PermissionService.UpdatePermission(c.Request.Context(), id, req, updaterID, ipAddress, userAgent)
	if err != nil {
		if err.Error() == "permission not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		if err.Error() == "permission already exists" {
			c.JSON(http.StatusConflict, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, permission)
}

// @Summary Delete permission
// @Description Delete a permission
// @Tags permissions
// @Param id path string true "Permission ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/permissions/{id} [delete]
func (h *PermissionHandler) DeletePermission(c *gin.Context) {
	// Get permission ID from path
	id := c.Param("id")

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized"})
		return
	}

	// Parse user ID
	deleterID, err := uuid.Parse(userID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid user ID"})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call permission service
	if err := h.PermissionService.DeletePermission(c.Request.Context(), id, deleterID, ipAddress, userAgent); err != nil {
		if err.Error() == "permission not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Permission deleted successfully"})
}

// RegisterRoutes registers the permission routes
func (h *PermissionHandler) RegisterRoutes(router *gin.RouterGroup) {
	permissionsGroup := router.Group("/permissions")
	permissionsGroup.Use(AuthMiddleware())
	{
		permissionsGroup.GET("", h.ListPermissions)
		permissionsGroup.POST("", RBACMiddleware("permissions:create"), h.CreatePermission)
		permissionsGroup.GET("/search", h.SearchPermissions)
		permissionsGroup.GET("/:id", h.GetPermissionByID)
		permissionsGroup.PUT("/:id", RBACMiddleware("permissions:update"), h.UpdatePermission)
		permissionsGroup.DELETE("/:id", RBACMiddleware("permissions:delete"), h.DeletePermission)
	}
}