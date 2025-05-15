package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"backend/model"
	"backend/repository"
	"backend/utils"
)

// AuditService handles audit log and security event operations
type AuditService struct {
	AuditRepo *repository.AuditRepository
	Logger    *logrus.Logger
	Validator *utils.Validator
}

// NewAuditService creates a new audit service
func NewAuditService(
	auditRepo *repository.AuditRepository,
	logger *logrus.Logger,
	validator *utils.Validator,
) *AuditService {
	return &AuditService{
		AuditRepo: auditRepo,
		Logger:    logger,
		Validator: validator,
	}
}

// AuditLogResponse represents an audit log response
type AuditLogResponse struct {
	ID           string    `json:"id"`
	UserID       *string   `json:"user_id,omitempty"`
	Username     *string   `json:"username,omitempty"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   *string   `json:"resource_id,omitempty"`
	OldValues    string    `json:"old_values,omitempty"`
	NewValues    string    `json:"new_values,omitempty"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	CreatedAt    time.Time `json:"created_at"`
}

// AuditLogsResponse represents a paginated list of audit logs
type AuditLogsResponse struct {
	AuditLogs  []AuditLogResponse `json:"audit_logs"`
	Total      int64              `json:"total"`
	Page       int                `json:"page"`
	PageSize   int                `json:"page_size"`
	TotalPages int                `json:"total_pages"`
}

// SecurityEventResponse represents a security event response
type SecurityEventResponse struct {
	ID          string    `json:"id"`
	UserID      *string   `json:"user_id,omitempty"`
	Username    *string   `json:"username,omitempty"`
	EventType   string    `json:"event_type"`
	Description string    `json:"description"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
	CreatedAt   time.Time `json:"created_at"`
}

// SecurityEventsResponse represents a paginated list of security events
type SecurityEventsResponse struct {
	SecurityEvents []SecurityEventResponse `json:"security_events"`
	Total          int64                   `json:"total"`
	Page           int                     `json:"page"`
	PageSize       int                     `json:"page_size"`
	TotalPages     int                     `json:"total_pages"`
}

// GetAuditLogs gets audit logs with pagination and filtering
func (s *AuditService) GetAuditLogs(ctx context.Context, userID, resourceType, action string, startDate, endDate *time.Time, page, pageSize int) (*AuditLogsResponse, error) {
	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	// Parse user ID if provided
	var userUUID *uuid.UUID
	if userID != "" {
		id, err := uuid.Parse(userID)
		if err != nil {
			return nil, errors.New("invalid user ID")
		}
		userUUID = &id
	}

	// Get audit logs with pagination and filtering
	auditLogs, total, err := s.AuditRepo.GetAuditLogs(ctx, userUUID, resourceType, action, startDate, endDate, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs: %w", err)
	}

	// Calculate total pages
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	// Create response
	response := &AuditLogsResponse{
		AuditLogs:  make([]AuditLogResponse, len(auditLogs)),
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}

	// Convert audit logs to response format
	for i, log := range auditLogs {
		// Format user ID and username
		var userIDStr *string
		var username *string
		if log.UserID != nil {
			tmp := log.UserID.String()
			userIDStr = &tmp

			// Get username if available
			if log.User != nil {
				tmp := log.User.Username
				username = &tmp
			}
		}

		// Format resource ID
		var resourceIDStr *string
		if log.ResourceID != nil {
			tmp := log.ResourceID.String()
			resourceIDStr = &tmp
		}

		response.AuditLogs[i] = AuditLogResponse{
			ID:           log.ID.String(),
			UserID:       userIDStr,
			Username:     username,
			Action:       log.Action,
			ResourceType: log.ResourceType,
			ResourceID:   resourceIDStr,
			OldValues:    log.OldValues,
			NewValues:    log.NewValues,
			IPAddress:    log.IPAddress,
			UserAgent:    log.UserAgent,
			CreatedAt:    log.CreatedAt,
		}
	}

	return response, nil
}

// GetSecurityEvents gets security events with pagination and filtering
func (s *AuditService) GetSecurityEvents(ctx context.Context, userID, eventType string, startDate, endDate *time.Time, page, pageSize int) (*SecurityEventsResponse, error) {
	// Validate pagination parameters
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	// Parse user ID if provided
	var userUUID *uuid.UUID
	if userID != "" {
		id, err := uuid.Parse(userID)
		if err != nil {
			return nil, errors.New("invalid user ID")
		}
		userUUID = &id
	}

	// Get security events with pagination and filtering
	securityEvents, total, err := s.AuditRepo.GetSecurityEvents(ctx, userUUID, eventType, startDate, endDate, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("failed to get security events: %w", err)
	}

	// Calculate total pages
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	// Create response
	response := &SecurityEventsResponse{
		SecurityEvents: make([]SecurityEventResponse, len(securityEvents)),
		Total:          total,
		Page:           page,
		PageSize:       pageSize,
		TotalPages:     totalPages,
	}

	// Convert security events to response format
	for i, event := range securityEvents {
		// Format user ID and username
		var userIDStr *string
		var username *string
		if event.UserID != nil {
			tmp := event.UserID.String()
			userIDStr = &tmp

			// Get username if available
			if event.User != nil {
				tmp := event.User.Username
				username = &tmp
			}
		}

		response.SecurityEvents[i] = SecurityEventResponse{
			ID:          event.ID.String(),
			UserID:      userIDStr,
			Username:    username,
			EventType:   event.EventType,
			Description: event.Description,
			IPAddress:   event.IPAddress,
			UserAgent:   event.UserAgent,
			CreatedAt:   event.CreatedAt,
		}
	}

	return response, nil
}

// GetUserAuditLogs gets audit logs for a specific user
func (s *AuditService) GetUserAuditLogs(ctx context.Context, userID string, page, pageSize int) (*AuditLogsResponse, error) {
	// Parse user ID
	id, err := uuid.Parse(userID)
	if err != nil {
		return nil, errors.New("invalid user ID")
	}

	// Get audit logs for user
	return s.GetAuditLogs(ctx, userID, "", "", nil, nil, page, pageSize)
}

// GetUserSecurityEvents gets security events for a specific user
func (s *AuditService) GetUserSecurityEvents(ctx context.Context, userID string, page, pageSize int) (*SecurityEventsResponse, error) {
	// Parse user ID
	id, err := uuid.Parse(userID)
	if err != nil {
		return nil, errors.New("invalid user ID")
	}

	// Get security events for user
	return s.GetSecurityEvents(ctx, userID, "", nil, nil, page, pageSize)
}

// GetResourceAuditLogs gets audit logs for a specific resource
func (s *AuditService) GetResourceAuditLogs(ctx context.Context, resourceType, resourceID string, page, pageSize int) (*AuditLogsResponse, error) {
	// Parse resource ID
	id, err := uuid.Parse(resourceID)
	if err != nil {
		return nil, errors.New("invalid resource ID")
	}

	// Get audit logs with resource type and ID filter
	auditLogs, total, err := s.AuditRepo.GetResourceAuditLogs(ctx, resourceType, id, page, pageSize)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource audit logs: %w", err)
	}

	// Calculate total pages
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	// Create response
	response := &AuditLogsResponse{
		AuditLogs:  make([]AuditLogResponse, len(auditLogs)),
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}

	// Convert audit logs to response format
	for i, log := range auditLogs {
		// Format user ID and username
		var userIDStr *string
		var username *string
		if log.UserID != nil {
			tmp := log.UserID.String()
			userIDStr = &tmp

			// Get username if available
			if log.User != nil {
				tmp := log.User.Username
				username = &tmp
			}
		}

		// Format resource ID
		var resourceIDStr *string
		if log.ResourceID != nil {
			tmp := log.ResourceID.String()
			resourceIDStr = &tmp
		}

		response.AuditLogs[i] = AuditLogResponse{
			ID:           log.ID.String(),
			UserID:       userIDStr,
			Username:     username,
			Action:       log.Action,
			ResourceType: log.ResourceType,
			ResourceID:   resourceIDStr,
			OldValues:    log.OldValues,
			NewValues:    log.NewValues,
			IPAddress:    log.IPAddress,
			UserAgent:    log.UserAgent,
			CreatedAt:    log.CreatedAt,
		}
	}

	return response, nil
}

// CreateAuditLog creates a new audit log entry
func (s *AuditService) CreateAuditLog(ctx context.Context, userID uuid.UUID, action, resourceType string, resourceID *uuid.UUID, oldValues, newValues, ipAddress, userAgent string) error {
	// Create audit log
	auditLog := &model.AuditLog{
		UserID:       &userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		OldValues:    oldValues,
		NewValues:    newValues,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}

	// Save audit log
	if err := s.AuditRepo.CreateAuditLog(ctx, auditLog); err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

// CreateSecurityEvent creates a new security event
func (s *AuditService) CreateSecurityEvent(ctx context.Context, userID *uuid.UUID, eventType, description, ipAddress, userAgent string) error {
	// Create security event
	securityEvent := &model.SecurityEvent{
		UserID:      userID,
		EventType:   eventType,
		Description: description,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
	}

	// Save security event
	if err := s.AuditRepo.CreateSecurityEvent(ctx, securityEvent); err != nil {
		return fmt.Errorf("failed to create security event: %w", err)
	}

	return nil
}
