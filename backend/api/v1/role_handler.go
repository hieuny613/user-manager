package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"backend/service"
)

// RoleHandler handles role-related requests
type RoleHandler struct {
	RoleService *service.RoleService
	Logger      *logrus.Logger
}

// NewRoleHandler creates a new role handler
func NewRoleHandler(roleService *service.RoleService, logger *logrus.Logger) *RoleHandler {
	return &RoleHandler{
		RoleService: roleService,
		Logger:      logger,
	}
}

// @Summary Get role by ID
// @Description Get a role by ID
// @Tags roles
// @Produce json
// @Param id path string true "Role ID"
// @Success 200 {object} RoleResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/roles/{id} [get]
func (h *RoleHandler) GetRoleByID(c *gin.Context) {
	// Get role ID from path
	id := c.Param("id")

	// Call role service
	role, err := h.RoleService.GetRoleByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, role)
}

// @Summary List roles
// @Description List roles with pagination
// @Tags roles
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(10)
// @Success 200 {object} service.RolesResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/roles [get]
func (h *RoleHandler) ListRoles(c *gin.Context) {
	// Get pagination parameters
	var params PaginationParams
	if err := c.ShouldBindQuery(&params); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid pagination parameters"})
		return
	}

	// Call role service
	roles, err := h.RoleService.ListRoles(c.Request.Context(), params.Page, params.PageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, roles)
}

// @Summary Search roles
// @Description Search roles by name or description
// @Tags roles
// @Produce json
// @Param q query string true "Search query"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(10)
// @Success 200 {object} service.RolesResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/roles/search [get]
func (h *RoleHandler) SearchRoles(c *gin.Context) {
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

	// Call role service
	roles, err := h.RoleService.SearchRoles(c.Request.Context(), query, params.Page, params.PageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, roles)
}

// @Summary Create role
// @Description Create a new role
// @Tags roles
// @Accept json
// @Produce json
// @Param request body service.CreateRoleRequest true "Role details"
// @Success 201 {object} RoleResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/roles [post]
func (h *RoleHandler) CreateRole(c *gin.Context) {
	var req service.CreateRoleRequest
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

	// Call role service
	role, err := h.RoleService.CreateRole(c.Request.Context(), req, creatorID, ipAddress, userAgent)
	if err != nil {
		if err.Error() == "role name already exists" {
			c.JSON(http.StatusConflict, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusCreated, role)
}

// @Summary Update role
// @Description Update a role
// @Tags roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Param request body service.UpdateRoleRequest true "Role details"
// @Success 200 {object} RoleResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/roles/{id} [put]
func (h *RoleHandler) UpdateRole(c *gin.Context) {
	// Get role ID from path
	id := c.Param("id")

	var req service.UpdateRoleRequest
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

	// Call role service
	role, err := h.RoleService.UpdateRole(c.Request.Context(), id, req, updaterID, ipAddress, userAgent)
	if err != nil {
		if err.Error() == "role not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		if err.Error() == "role name already exists" {
			c.JSON(http.StatusConflict, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, role)
}

// @Summary Delete role
// @Description Delete a role
// @Tags roles
// @Param id path string true "Role ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/roles/{id} [delete]
func (h *RoleHandler) DeleteRole(c *gin.Context) {
	// Get role ID from path
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

	// Call role service
	if err := h.RoleService.DeleteRole(c.Request.Context(), id, deleterID, ipAddress, userAgent); err != nil {
		if err.Error() == "role not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Role deleted successfully"})
}

// @Summary Add permission to role
// @Description Add a permission to a role
// @Tags roles
// @Param role_id path string true "Role ID"
// @Param permission_id path string true "Permission ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/roles/{role_id}/permissions/{permission_id} [post]
func (h *RoleHandler) AddPermissionToRole(c *gin.Context) {
	// Get role ID and permission ID from path
	roleID := c.Param("role_id")
	permissionID := c.Param("permission_id")

	// Get admin ID from context
	adminID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized"})
		return
	}

	// Parse admin ID
	adminUUID, err := uuid.Parse(adminID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid user ID"})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call role service
	if err := h.RoleService.AddPermissionToRole(c.Request.Context(), roleID, permissionID, adminUUID, ipAddress, userAgent); err != nil {
		if err.Error() == "role not found" || err.Error() == "permission not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Permission added to role successfully"})
}

// @Summary Remove permission from role
// @Description Remove a permission from a role
// @Tags roles
// @Param role_id path string true "Role ID"
// @Param permission_id path string true "Permission ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/roles/{role_id}/permissions/{permission_id} [delete]
func (h *RoleHandler) RemovePermissionFromRole(c *gin.Context) {
	// Get role ID and permission ID from path
	roleID := c.Param("role_id")
	permissionID := c.Param("permission_id")

	// Get admin ID from context
	adminID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized"})
		return
	}

	// Parse admin ID
	adminUUID, err := uuid.Parse(adminID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid user ID"})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call role service
	if err := h.RoleService.RemovePermissionFromRole(c.Request.Context(), roleID, permissionID, adminUUID, ipAddress, userAgent); err != nil {
		if err.Error() == "role not found" || err.Error() == "permission not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Permission removed from role successfully"})
}

// @Summary Get role permissions
// @Description Get all permissions for a role
// @Tags roles
// @Produce json
// @Param role_id path string true "Role ID"
// @Success 200 {array} PermissionResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/roles/{role_id}/permissions [get]
func (h *RoleHandler) GetRolePermissions(c *gin.Context) {
	// Get role ID from path
	roleID := c.Param("role_id")

	// Call role service
	permissions, err := h.RoleService.GetRolePermissions(c.Request.Context(), roleID)
	if err != nil {
		if err.Error() == "role not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, permissions)
}

// RegisterRoutes registers the role routes
func (h *RoleHandler) RegisterRoutes(router *gin.RouterGroup) {
	rolesGroup := router.Group("/roles")
	rolesGroup.Use(AuthMiddleware())
	{
		rolesGroup.GET("", h.ListRoles)
		rolesGroup.POST("", RBACMiddleware("roles:create"), h.CreateRole)
		rolesGroup.GET("/search", h.SearchRoles)
		rolesGroup.GET("/:id", h.GetRoleByID)
		rolesGroup.PUT("/:id", RBACMiddleware("roles:update"), h.UpdateRole)
		rolesGroup.DELETE("/:id", RBACMiddleware("roles:delete"), h.DeleteRole)

		// Role permissions
		rolesGroup.GET("/:role_id/permissions", h.GetRolePermissions)
		rolesGroup.POST("/:role_id/permissions/:permission_id", RBACMiddleware("roles:manage_permissions"), h.AddPermissionToRole)
		rolesGroup.DELETE("/:role_id/permissions/:permission_id", RBACMiddleware("roles:manage_permissions"), h.RemovePermissionFromRole)
	}
}