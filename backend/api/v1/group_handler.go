package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"backend/service"
)

// GroupHandler handles group-related requests
type GroupHandler struct {
	GroupService *service.GroupService
	Logger       *logrus.Logger
}

// NewGroupHandler creates a new group handler
func NewGroupHandler(groupService *service.GroupService, logger *logrus.Logger) *GroupHandler {
	return &GroupHandler{
		GroupService: groupService,
		Logger:       logger,
	}
}

// @Summary Get group by ID
// @Description Get a group by ID
// @Tags groups
// @Produce json
// @Param id path string true "Group ID"
// @Success 200 {object} GroupResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/groups/{id} [get]
func (h *GroupHandler) GetGroupByID(c *gin.Context) {
	// Get group ID from path
	id := c.Param("id")

	// Call group service
	group, err := h.GroupService.GetGroupByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, group)
}

// @Summary List groups
// @Description List groups with pagination
// @Tags groups
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(10)
// @Success 200 {object} service.GroupsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/groups [get]
func (h *GroupHandler) ListGroups(c *gin.Context) {
	// Get pagination parameters
	var params PaginationParams
	if err := c.ShouldBindQuery(&params); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid pagination parameters"})
		return
	}

	// Call group service
	groups, err := h.GroupService.ListGroups(c.Request.Context(), params.Page, params.PageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, groups)
}

// @Summary Search groups
// @Description Search groups by name or description
// @Tags groups
// @Produce json
// @Param q query string true "Search query"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(10)
// @Success 200 {object} service.GroupsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/groups/search [get]
func (h *GroupHandler) SearchGroups(c *gin.Context) {
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

	// Call group service
	groups, err := h.GroupService.SearchGroups(c.Request.Context(), query, params.Page, params.PageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, groups)
}

// @Summary Create group
// @Description Create a new group
// @Tags groups
// @Accept json
// @Produce json
// @Param request body service.CreateGroupRequest true "Group details"
// @Success 201 {object} GroupResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/groups [post]
func (h *GroupHandler) CreateGroup(c *gin.Context) {
	var req service.CreateGroupRequest
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

	// Call group service
	group, err := h.GroupService.CreateGroup(c.Request.Context(), req, creatorID, ipAddress, userAgent)
	if err != nil {
		if err.Error() == "group name already exists" {
			c.JSON(http.StatusConflict, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusCreated, group)
}

// @Summary Update group
// @Description Update a group
// @Tags groups
// @Accept json
// @Produce json
// @Param id path string true "Group ID"
// @Param request body service.UpdateGroupRequest true "Group details"
// @Success 200 {object} GroupResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/groups/{id} [put]
func (h *GroupHandler) UpdateGroup(c *gin.Context) {
	// Get group ID from path
	id := c.Param("id")

	var req service.UpdateGroupRequest
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

	// Call group service
	group, err := h.GroupService.UpdateGroup(c.Request.Context(), id, req, updaterID, ipAddress, userAgent)
	if err != nil {
		if err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		if err.Error() == "group name already exists" {
			c.JSON(http.StatusConflict, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, group)
}

// @Summary Delete group
// @Description Delete a group
// @Tags groups
// @Param id path string true "Group ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/groups/{id} [delete]
func (h *GroupHandler) DeleteGroup(c *gin.Context) {
	// Get group ID from path
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

	// Call group service
	if err := h.GroupService.DeleteGroup(c.Request.Context(), id, deleterID, ipAddress, userAgent); err != nil {
		if err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Group deleted successfully"})
}

// @Summary Add role to group
// @Description Add a role to a group
// @Tags groups
// @Param group_id path string true "Group ID"
// @Param role_id path string true "Role ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/groups/{group_id}/roles/{role_id} [post]
func (h *GroupHandler) AddRoleToGroup(c *gin.Context) {
	// Get group ID and role ID from path
	groupID := c.Param("group_id")
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

	// Call group service
	if err := h.GroupService.AddRoleToGroup(c.Request.Context(), groupID, roleID, adminUUID, ipAddress, userAgent); err != nil {
		if err.Error() == "group not found" || err.Error() == "role not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Role added to group successfully"})
}

// @Summary Remove role from group
// @Description Remove a role from a group
// @Tags groups
// @Param group_id path string true "Group ID"
// @Param role_id path string true "Role ID"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/groups/{group_id}/roles/{role_id} [delete]
func (h *GroupHandler) RemoveRoleFromGroup(c *gin.Context) {
	// Get group ID and role ID from path
	groupID := c.Param("group_id")
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

	// Call group service
	if err := h.GroupService.RemoveRoleFromGroup(c.Request.Context(), groupID, roleID, adminUUID, ipAddress, userAgent); err != nil {
		if err.Error() == "group not found" || err.Error() == "role not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{Message: "Role removed from group successfully"})
}

// @Summary Get group users
// @Description Get all users in a group
// @Tags groups
// @Produce json
// @Param group_id path string true "Group ID"
// @Success 200 {array} UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/groups/{group_id}/users [get]
func (h *GroupHandler) GetGroupUsers(c *gin.Context) {
	// Get group ID from path
	groupID := c.Param("group_id")

	// Call group service
	users, err := h.GroupService.GetGroupUsers(c.Request.Context(), groupID)
	if err != nil {
		if err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, users)
}

// @Summary Get group roles
// @Description Get all roles in a group
// @Tags groups
// @Produce json
// @Param group_id path string true "Group ID"
// @Success 200 {array} RoleResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/groups/{group_id}/roles [get]
func (h *GroupHandler) GetGroupRoles(c *gin.Context) {
	// Get group ID from path
	groupID := c.Param("group_id")

	// Call group service
	roles, err := h.GroupService.GetGroupRoles(c.Request.Context(), groupID)
	if err != nil {
		if err.Error() == "group not found" {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, roles)
}

// RegisterRoutes registers the group routes
func (h *GroupHandler) RegisterRoutes(router *gin.RouterGroup) {
	groupsGroup := router.Group("/groups")
	groupsGroup.Use(AuthMiddleware())
	{
		groupsGroup.GET("", h.ListGroups)
		groupsGroup.POST("", RBACMiddleware("groups:create"), h.CreateGroup)
		groupsGroup.GET("/search", h.SearchGroups)
		groupsGroup.GET("/:id", h.GetGroupByID)
		groupsGroup.PUT("/:id", RBACMiddleware("groups:update"), h.UpdateGroup)
		groupsGroup.DELETE("/:id", RBACMiddleware("groups:delete"), h.DeleteGroup)

		// Group users
		groupsGroup.GET("/:group_id/users", h.GetGroupUsers)

		// Group roles
		groupsGroup.GET("/:group_id/roles", h.GetGroupRoles)
		groupsGroup.POST("/:group_id/roles/:role_id", RBACMiddleware("groups:manage_roles"), h.AddRoleToGroup)
		groupsGroup.DELETE("/:group_id/roles/:role_id", RBACMiddleware("groups:manage_roles"), h.RemoveRoleFromGroup)
	}
}