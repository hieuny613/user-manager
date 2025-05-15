package v1

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"backend/service"
)

// UserHandler handles user-related requests
type UserHandler struct {
	UserService *service.UserService
	Logger      *logrus.Logger
}

// NewUserHandler creates a new user handler
func NewUserHandler(userService *service.UserService, logger *logrus.Logger) *UserHandler {
	return &UserHandler{
		UserService: userService,
		Logger:      logger,
	}
}

// @Summary Get user by ID
// @Description Get a user by ID
// @Tags users
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/users/{id} [get]
func (h *UserHandler) GetUserByID(c *gin.Context) {
	// Get user ID from path
	id := c.Param("id")

	// Call user service
	user, err := h.UserService.GetUserByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, user)
}

// @Summary List users
// @Description List users with pagination
// @Tags users
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(10)
// @Success 200 {object} service.UsersResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/users [get]
func (h *UserHandler) ListUsers(c *gin.Context) {
	// Get pagination parameters
	var params PaginationParams
	if err := c.ShouldBindQuery(&params); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid pagination parameters"})
		return
	}

	// Call user service
	users, err := h.UserService.ListUsers(c.Request.Context(), params.Page, params.PageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, users)
}

// @Summary Search users
// @Description Search users by email, username, or name
// @Tags users
// @Produce json
// @Param q query string true "Search query"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(10)
// @Success 200 {object} service.UsersResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/users/search [get]
func (h *UserHandler) SearchUsers(c *gin.Context) {
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

	// Call user service
	users, err := h.UserService.SearchUsers(c.Request.Context(), query, params.Page, params.PageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, users)
}

// @Summary Create user
// @Description Create a new user
// @Tags users
// @Accept json
// @Produce json
// @Param request body service.CreateUserRequest true "User details"
// @Success 201 {object} UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/users [post]
func (h *UserHandler) CreateUser(c *gin.Context) {
	var req service.CreateUserRequest
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

	// Call user service
	user, err := h.UserService.CreateUser(c.Request.Context(), req, creatorID, ipAddress, userAgent)
	if err != nil {
		if err.Error() == "email already exists" || err.Error() == "username already exists" {
			c.JSON(http.StatusConflict, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusCreated, user)
}

// @Summary Update user
// @Description Update a user
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param request body service.UpdateUserRequest true "User details"
// @Success 200 {object} UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/users/{id} [put]
func (h *UserHandler) UpdateUser(c *gin.Context) {
	// Get user ID from path
	id := c.Param("id")

	var req service.UpdateUserRequest
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

	// Call user service
	user, err := h.UserService.UpdateUser(c.Request.Context(), id, req, updaterID, ipAddress, userAgent)
	if err != nil {
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		if err.Error() == "email already exists" || err.Error() == "username already exists" {
			c.JSON(http.StatusConflict, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, user)
}

// @Summary Delete user
// @Description Delete a user
// @Tags users
// @Param id path string true "User ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/users/{id} [delete]
func (h *UserHandler) DeleteUser(c *gin.Context) {
	// Get user ID from path
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

	// Call user service
	if err := h.UserService.DeleteUser(c.Request.Context(), id, deleterID, ipAddress, userAgent); err != nil {
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "User deleted successfully"})
}

// @Summary Add user to group
// @Description Add a user to a group
// @Tags users
// @Param user_id path string true "User ID"
// @Param group_id path string true "Group ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/users/{user_id}/groups/{group_id} [post]
func (h *UserHandler) AddUserToGroup(c *gin.Context) {
	// Get user ID and group ID from path
	userID := c.Param("user_id")
	groupID := c.Param("group_id")

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

	// Call user service
	if err := h.UserService.AddUserToGroup(c.Request.Context(), userID, groupID, adminUUID, ipAddress, userAgent); err != nil {
		if err.Error() == "user not found" || err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "User added to group successfully"})
}

// @Summary Remove user from group
// @Description Remove a user from a group
// @Tags users
// @Param user_id path string true "User ID"
// @Param group_id path string true "Group ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/users/{user_id}/groups/{group_id} [delete]
func (h *UserHandler) RemoveUserFromGroup(c *gin.Context) {
	// Get user ID and group ID from path
	userID := c.Param("user_id")
	groupID := c.Param("group_id")

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

	// Call user service
	if err := h.UserService.RemoveUserFromGroup(c.Request.Context(), userID, groupID, adminUUID, ipAddress, userAgent); err != nil {
		if err.Error() == "user not found" || err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "User removed from group successfully"})
}

// @Summary Assign role to user
// @Description Assign a role to a user
// @Tags users
// @Param user_id path string true "User ID"
// @Param role_id path string true "Role ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/users/{user_id}/roles/{role_id} [post]
func (h *UserHandler) AssignRoleToUser(c *gin.Context) {
	// Get user ID and role ID from path
	userID := c.Param("user_id")
	roleID := c.Param("role_id")

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

	// Call user service
	if err := h.UserService.AssignRoleToUser(c.Request.Context(), userID, roleID, adminUUID, ipAddress, userAgent); err != nil {
		if err.Error() == "user not found" || err.Error() == "role not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Role assigned to user successfully"})
}

// @Summary Remove role from user
// @Description Remove a role from a user
// @Tags users
// @Param user_id path string true "User ID"
// @Param role_id path string true "Role ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/users/{user_id}/roles/{role_id} [delete]
func (h *UserHandler) RemoveRoleFromUser(c *gin.Context) {
	// Get user ID and role ID from path
	userID := c.Param("user_id")
	roleID := c.Param("role_id")

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

	// Call user service
	if err := h.UserService.RemoveRoleFromUser(c.Request.Context(), userID, roleID, adminUUID, ipAddress, userAgent); err != nil {
		if err.Error() == "user not found" || err.Error() == "role not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Role removed from user successfully"})
}

// @Summary Get user groups
// @Description Get all groups for a user
// @Tags users
// @Produce json
// @Param user_id path string true "User ID"
// @Success 200 {array} GroupResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/users/{user_id}/groups [get]
func (h *UserHandler) GetUserGroups(c *gin.Context) {
	// Get user ID from path
	userID := c.Param("user_id")

	// Call user service
	groups, err := h.UserService.GetUserGroups(c.Request.Context(), userID)
	if err != nil {
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, groups)
}

// @Summary Get user roles
// @Description Get all roles for a user
// @Tags users
// @Produce json
// @Param user_id path string true "User ID"
// @Success 200 {array} RoleResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/users/{user_id}/roles [get]
func (h *UserHandler) GetUserRoles(c *gin.Context) {
	// Get user ID from path
	userID := c.Param("user_id")

	// Call user service
	roles, err := h.UserService.GetUserRoles(c.Request.Context(), userID)
	if err != nil {
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, roles)
}

// @Summary Get user permissions
// @Description Get all permissions for a user
// @Tags users
// @Produce json
// @Param user_id path string true "User ID"
// @Success 200 {array} PermissionResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/users/{user_id}/permissions [get]
func (h *UserHandler) GetUserPermissions(c *gin.Context) {
	// Get user ID from path
	userID := c.Param("user_id")

	// Call user service
	permissions, err := h.UserService.GetUserPermissions(c.Request.Context(), userID)
	if err != nil {
		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, permissions)
}

// @Summary Get user profile
// @Description Get the current user's profile
// @Tags users
// @Produce json
// @Success 200 {object} UserResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/users/profile [get]
func (h *UserHandler) GetUserProfile(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Unauthorized"})
		return
	}

	// Call user service
	user, err := h.UserService.GetUserByID(c.Request.Context(), userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, user)
}

// @Summary Update user profile
// @Description Update the current user's profile
// @Tags users
// @Accept json
// @Produce json
// @Param request body service.UpdateProfileRequest true "Profile details"
// @Success 200 {object} UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/users/profile [put]
func (h *UserHandler) UpdateUserProfile(c *gin.Context) {
	var req service.UpdateProfileRequest
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
	userUUID, err := uuid.Parse(userID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid user ID"})
		return
	}

	// Get client IP and user agent
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Call user service
	user, err := h.UserService.UpdateUserProfile(c.Request.Context(), userUUID, req, ipAddress, userAgent)
	if err != nil {
		if err.Error() == "email already exists" || err.Error() == "username already exists" {
			c.JSON(http.StatusConflict, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, user)
}

// @Summary Check user permissions
// @Description Check if the current user has specific permissions
// @Tags users
// @Accept json
// @Produce json
// @Param request body service.CheckPermissionsRequest true "Permissions to check"
// @Success 200 {object} service.PermissionsCheckResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/users/permissions/check [post]
func (h *UserHandler) CheckUserPermissions(c *gin.Context) {
	var req service.CheckPermissionsRequest
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
	userUUID, err := uuid.Parse(userID.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid user ID"})
		return
	}

	// Call user service
	result, err := h.UserService.CheckUserPermissions(c.Request.Context(), userUUID, req.Permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// RegisterRoutes registers the user routes
func (h *UserHandler) RegisterRoutes(router *gin.RouterGroup) {
	usersGroup := router.Group("/users")
	usersGroup.Use(AuthMiddleware())
	{
		// User profile routes (no RBAC required - users can access their own profile)
		usersGroup.GET("/profile", h.GetUserProfile)
		usersGroup.PUT("/profile", h.UpdateUserProfile)
		usersGroup.POST("/permissions/check", h.CheckUserPermissions)

		// User management routes
		usersGroup.GET("", h.ListUsers)
		usersGroup.POST("", RBACMiddleware("users:create"), h.CreateUser)
		usersGroup.GET("/search", h.SearchUsers)
		usersGroup.GET("/:id", h.GetUserByID)
		usersGroup.PUT("/:id", RBACMiddleware("users:update"), h.UpdateUser)
		usersGroup.DELETE("/:id", RBACMiddleware("users:delete"), h.DeleteUser)

		// User groups
		usersGroup.GET("/:user_id/groups", h.GetUserGroups)
		usersGroup.POST("/:user_id/groups/:group_id", RBACMiddleware("users:manage_groups"), h.AddUserToGroup)
		usersGroup.DELETE("/:user_id/groups/:group_id", RBACMiddleware("users:manage_groups"), h.RemoveUserFromGroup)

		// User roles
		usersGroup.GET("/:user_id/roles", h.GetUserRoles)
		usersGroup.POST("/:user_id/roles/:role_id", RBACMiddleware("users:manage_roles"), h.AssignRoleToUser)
		usersGroup.DELETE("/:user_id/roles/:role_id", RBACMiddleware("users:manage_roles"), h.RemoveRoleFromUser)

		// User permissions
		usersGroup.GET("/:user_id/permissions", h.GetUserPermissions)
	}
}