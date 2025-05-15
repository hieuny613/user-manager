package v1

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"backend/service"
)

// AuditHandler handles audit-related requests
type AuditHandler struct {
	AuditService *service.AuditService
	Logger       *logrus.Logger
}

// NewAuditHandler creates a new audit handler
func NewAuditHandler(auditService *service.AuditService, logger *logrus.Logger) *AuditHandler {
	return &AuditHandler{
		AuditService: auditService,
		Logger:       logger,
	}
}

// AuditLogResponse represents an audit log response
type AuditLogResponse struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Username    string    `json:"username,omitempty"`
	Action      string    `json:"action"`
	Resource    string    `json:"resource"`
	ResourceID  string    `json:"resource_id,omitempty"`
	Description string    `json:"description"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
	CreatedAt   time.Time `json:"created_at"`
	Metadata    string    `json:"metadata,omitempty"`
}

// AuditLogsResponse represents a paginated list of audit logs
type AuditLogsResponse struct {
	Logs       []AuditLogResponse `json:"logs"`
	Total      int                `json:"total"`
	Page       int                `json:"page"`
	PageSize   int                `json:"page_size"`
	TotalPages int                `json:"total_pages"`
}

// @Summary List audit logs
// @Description List audit logs with pagination and filtering
// @Tags audit
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(10)
// @Param user_id query string false "Filter by user ID"
// @Param action query string false "Filter by action"
// @Param resource query string false "Filter by resource"
// @Param resource_id query string false "Filter by resource ID"
// @Param start_date query string false "Filter by start date (ISO 8601 format)"
// @Param end_date query string false "Filter by end date (ISO 8601 format)"
// @Success 200 {object} AuditLogsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/audit/logs [get]
func (h *AuditHandler) ListAuditLogs(c *gin.Context) {
	// Get pagination parameters
	var params PaginationParams
	if err := c.ShouldBindQuery(&params); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid pagination parameters"})
		return
	}

	// Get filter parameters
	userID := c.Query("user_id")
	action := c.Query("action")
	resource := c.Query("resource")
	resourceID := c.Query("resource_id")
	startDateStr := c.Query("start_date")
	endDateStr := c.Query("end_date")

	// Parse dates if provided
	var startDate, endDate *time.Time
	if startDateStr != "" {
		date, err := time.Parse(time.RFC3339, startDateStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid start date format. Use ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)"})
			return
		}
		startDate = &date
	}

	if endDateStr != "" {
		date, err := time.Parse(time.RFC3339, endDateStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid end date format. Use ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)"})
			return
		}
		endDate = &date
	}

	// Call audit service
	logs, err := h.AuditService.ListAuditLogs(
		c.Request.Context(),
		params.Page,
		params.PageSize,
		userID,
		action,
		resource,
		resourceID,
		startDate,
		endDate,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, logs)
}

// @Summary Get audit log by ID
// @Description Get an audit log by ID
// @Tags audit
// @Produce json
// @Param id path string true "Audit Log ID"
// @Success 200 {object} AuditLogResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/audit/logs/{id} [get]
func (h *AuditHandler) GetAuditLogByID(c *gin.Context) {
	// Get audit log ID from path
	id := c.Param("id")

	// Call audit service
	log, err := h.AuditService.GetAuditLogByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, log)
}

// @Summary Get user audit logs
// @Description Get audit logs for a specific user
// @Tags audit
// @Produce json
// @Param user_id path string true "User ID"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(10)
// @Param action query string false "Filter by action"
// @Param resource query string false "Filter by resource"
// @Param start_date query string false "Filter by start date (ISO 8601 format)"
// @Param end_date query string false "Filter by end date (ISO 8601 format)"
// @Success 200 {object} AuditLogsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/audit/users/{user_id}/logs [get]
func (h *AuditHandler) GetUserAuditLogs(c *gin.Context) {
	// Get user ID from path
	userID := c.Param("user_id")

	// Get pagination parameters
	var params PaginationParams
	if err := c.ShouldBindQuery(&params); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid pagination parameters"})
		return
	}

	// Get filter parameters
	action := c.Query("action")
	resource := c.Query("resource")
	resourceID := c.Query("resource_id")
	startDateStr := c.Query("start_date")
	endDateStr := c.Query("end_date")

	// Parse dates if provided
	var startDate, endDate *time.Time
	if startDateStr != "" {
		date, err := time.Parse(time.RFC3339, startDateStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid start date format. Use ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)"})
			return
		}
		startDate = &date
	}

	if endDateStr != "" {
		date, err := time.Parse(time.RFC3339, endDateStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid end date format. Use ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)"})
			return
		}
		endDate = &date
	}

	// Call audit service
	logs, err := h.AuditService.ListAuditLogs(
		c.Request.Context(),
		params.Page,
		params.PageSize,
		userID,
		action,
		resource,
		resourceID,
		startDate,
		endDate,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, logs)
}

// @Summary Get resource audit logs
// @Description Get audit logs for a specific resource
// @Tags audit
// @Produce json
// @Param resource path string true "Resource type"
// @Param resource_id path string true "Resource ID"
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(10)
// @Param action query string false "Filter by action"
// @Param user_id query string false "Filter by user ID"
// @Param start_date query string false "Filter by start date (ISO 8601 format)"
// @Param end_date query string false "Filter by end date (ISO 8601 format)"
// @Success 200 {object} AuditLogsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/audit/resources/{resource}/{resource_id}/logs [get]
func (h *AuditHandler) GetResourceAuditLogs(c *gin.Context) {
	// Get resource and resource ID from path
	resource := c.Param("resource")
	resourceID := c.Param("resource_id")

	// Get pagination parameters
	var params PaginationParams
	if err := c.ShouldBindQuery(&params); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid pagination parameters"})
		return
	}

	// Get filter parameters
	userID := c.Query("user_id")
	action := c.Query("action")
	startDateStr := c.Query("start_date")
	endDateStr := c.Query("end_date")

	// Parse dates if provided
	var startDate, endDate *time.Time
	if startDateStr != "" {
		date, err := time.Parse(time.RFC3339, startDateStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid start date format. Use ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)"})
			return
		}
		startDate = &date
	}

	if endDateStr != "" {
		date, err := time.Parse(time.RFC3339, endDateStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid end date format. Use ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)"})
			return
		}
		endDate = &date
	}

	// Call audit service
	logs, err := h.AuditService.ListAuditLogs(
		c.Request.Context(),
		params.Page,
		params.PageSize,
		userID,
		action,
		resource,
		resourceID,
		startDate,
		endDate,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, logs)
}

// @Summary Get security audit logs
// @Description Get security-related audit logs
// @Tags audit
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(10)
// @Param user_id query string false "Filter by user ID"
// @Param start_date query string false "Filter by start date (ISO 8601 format)"
// @Param end_date query string false "Filter by end date (ISO 8601 format)"
// @Success 200 {object} AuditLogsResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/audit/security [get]
func (h *AuditHandler) GetSecurityAuditLogs(c *gin.Context) {
	// Get pagination parameters
	var params PaginationParams
	if err := c.ShouldBindQuery(&params); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid pagination parameters"})
		return
	}

	// Get filter parameters
	userID := c.Query("user_id")
	startDateStr := c.Query("start_date")
	endDateStr := c.Query("end_date")

	// Parse dates if provided
	var startDate, endDate *time.Time
	if startDateStr != "" {
		date, err := time.Parse(time.RFC3339, startDateStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid start date format. Use ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)"})
			return
		}
		startDate = &date
	}

	if endDateStr != "" {
		date, err := time.Parse(time.RFC3339, endDateStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid end date format. Use ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)"})
			return
		}
		endDate = &date
	}

	// Call audit service with security filter
	logs, err := h.AuditService.GetSecurityAuditLogs(
		c.Request.Context(),
		params.Page,
		params.PageSize,
		userID,
		startDate,
		endDate,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, logs)
}

// @Summary Export audit logs
// @Description Export audit logs to CSV
// @Tags audit
// @Produce text/csv
// @Param user_id query string false "Filter by user ID"
// @Param action query string false "Filter by action"
// @Param resource query string false "Filter by resource"
// @Param resource_id query string false "Filter by resource ID"
// @Param start_date query string false "Filter by start date (ISO 8601 format)"
// @Param end_date query string false "Filter by end date (ISO 8601 format)"
// @Success 200 {file} file "audit_logs.csv"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Router /api/v1/audit/export [get]
func (h *AuditHandler) ExportAuditLogs(c *gin.Context) {
	// Get filter parameters
	userID := c.Query("user_id")
	action := c.Query("action")
	resource := c.Query("resource")
	resourceID := c.Query("resource_id")
	startDateStr := c.Query("start_date")
	endDateStr := c.Query("end_date")

	// Parse dates if provided
	var startDate, endDate *time.Time
	if startDateStr != "" {
		date, err := time.Parse(time.RFC3339, startDateStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid start date format. Use ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)"})
			return
		}
		startDate = &date
	}

	if endDateStr != "" {
		date, err := time.Parse(time.RFC3339, endDateStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid end date format. Use ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)"})
			return
		}
		endDate = &date
	}

	// Call audit service to export logs
	csv, err := h.AuditService.ExportAuditLogs(
		c.Request.Context(),
		userID,
		action,
		resource,
		resourceID,
		startDate,
		endDate,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	// Set headers for CSV download
	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", "attachment; filename=audit_logs.csv")
	c.Header("Content-Type", "text/csv")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Expires", "0")
	c.Header("Cache-Control", "must-revalidate")
	c.Header("Pragma", "public")

	// Write CSV data to response
	c.String(http.StatusOK, csv)
}

// RegisterRoutes registers the audit routes
func (h *AuditHandler) RegisterRoutes(router *gin.RouterGroup) {
	auditGroup := router.Group("/audit")
	auditGroup.Use(AuthMiddleware())
	{
		// Audit logs
		logsGroup := auditGroup.Group("/logs")
		{
			logsGroup.GET("", RBACMiddleware("audit:view"), h.ListAuditLogs)
			logsGroup.GET("/:id", RBACMiddleware("audit:view"), h.GetAuditLogByID)
		}

		// User audit logs
		auditGroup.GET("/users/:user_id/logs", RBACMiddleware("audit:view"), h.GetUserAuditLogs)

		// Resource audit logs
		auditGroup.GET("/resources/:resource/:resource_id/logs", RBACMiddleware("audit:view"), h.GetResourceAuditLogs)

		// Security audit logs
		auditGroup.GET("/security", RBACMiddleware("audit:view_security"), h.GetSecurityAuditLogs)

		// Export audit logs
		auditGroup.GET("/export", RBACMiddleware("audit:export"), h.ExportAuditLogs)
	}
}