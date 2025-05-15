package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"backend/model"
)

// AuditRepository handles database operations for audit logs and security events
type AuditRepository struct {
	DB *gorm.DB
}

// NewAuditRepository creates a new audit repository
func NewAuditRepository(db *gorm.DB) *AuditRepository {
	return &AuditRepository{DB: db}
}

// CreateAuditLog creates a new audit log entry
func (r *AuditRepository) CreateAuditLog(ctx context.Context, log *model.AuditLog) error {
	return r.DB.WithContext(ctx).Create(log).Error
}

// GetAuditLogsByUser gets audit logs for a user
func (r *AuditRepository) GetAuditLogsByUser(ctx context.Context, userID uuid.UUID, page, pageSize int) ([]model.AuditLog, int64, error) {
	var logs []model.AuditLog
	var total int64

	// Get total count
	if err := r.DB.WithContext(ctx).Model(&model.AuditLog{}).Where("user_id = ?", userID).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get audit logs with pagination
	offset := (page - 1) * pageSize
	result := r.DB.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&logs)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return logs, total, nil
}

// GetAuditLogsByResource gets audit logs for a resource
func (r *AuditRepository) GetAuditLogsByResource(ctx context.Context, resourceType string, resourceID uuid.UUID, page, pageSize int) ([]model.AuditLog, int64, error) {
	var logs []model.AuditLog
	var total int64

	// Get total count
	if err := r.DB.WithContext(ctx).Model(&model.AuditLog{}).Where("resource_type = ? AND resource_id = ?", resourceType, resourceID).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get audit logs with pagination
	offset := (page - 1) * pageSize
	result := r.DB.WithContext(ctx).Where("resource_type = ? AND resource_id = ?", resourceType, resourceID).Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&logs)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return logs, total, nil
}

// GetAuditLogs gets all audit logs with pagination
func (r *AuditRepository) GetAuditLogs(ctx context.Context, page, pageSize int) ([]model.AuditLog, int64, error) {
	var logs []model.AuditLog
	var total int64

	// Get total count
	if err := r.DB.WithContext(ctx).Model(&model.AuditLog{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get audit logs with pagination
	offset := (page - 1) * pageSize
	result := r.DB.WithContext(ctx).Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&logs)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return logs, total, nil
}

// SearchAuditLogs searches audit logs
func (r *AuditRepository) SearchAuditLogs(ctx context.Context, query string, page, pageSize int) ([]model.AuditLog, int64, error) {
	var logs []model.AuditLog
	var total int64

	// Build search query
	searchQuery := r.DB.WithContext(ctx).Model(&model.AuditLog{}).Where(
		"action ILIKE ? OR resource_type ILIKE ?",
		"%"+query+"%", "%"+query+"%",
	)

	// Get total count
	if err := searchQuery.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get audit logs with pagination
	offset := (page - 1) * pageSize
	result := searchQuery.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&logs)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return logs, total, nil
}

// CreateSecurityEvent creates a new security event
func (r *AuditRepository) CreateSecurityEvent(ctx context.Context, event *model.SecurityEvent) error {
	return r.DB.WithContext(ctx).Create(event).Error
}

// GetSecurityEventsByUser gets security events for a user
func (r *AuditRepository) GetSecurityEventsByUser(ctx context.Context, userID uuid.UUID, page, pageSize int) ([]model.SecurityEvent, int64, error) {
	var events []model.SecurityEvent
	var total int64

	// Get total count
	if err := r.DB.WithContext(ctx).Model(&model.SecurityEvent{}).Where("user_id = ?", userID).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get security events with pagination
	offset := (page - 1) * pageSize
	result := r.DB.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return events, total, nil
}

// GetSecurityEvents gets all security events with pagination
func (r *AuditRepository) GetSecurityEvents(ctx context.Context, page, pageSize int) ([]model.SecurityEvent, int64, error) {
	var events []model.SecurityEvent
	var total int64

	// Get total count
	if err := r.DB.WithContext(ctx).Model(&model.SecurityEvent{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get security events with pagination
	offset := (page - 1) * pageSize
	result := r.DB.WithContext(ctx).Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return events, total, nil
}

// GetSecurityEventsByType gets security events by type
func (r *AuditRepository) GetSecurityEventsByType(ctx context.Context, eventType string, page, pageSize int) ([]model.SecurityEvent, int64, error) {
	var events []model.SecurityEvent
	var total int64

	// Get total count
	if err := r.DB.WithContext(ctx).Model(&model.SecurityEvent{}).Where("event_type = ?", eventType).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get security events with pagination
	offset := (page - 1) * pageSize
	result := r.DB.WithContext(ctx).Where("event_type = ?", eventType).Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return events, total, nil
}

// GetSecurityEventsByTimeRange gets security events in a time range
func (r *AuditRepository) GetSecurityEventsByTimeRange(ctx context.Context, startTime, endTime time.Time, page, pageSize int) ([]model.SecurityEvent, int64, error) {
	var events []model.SecurityEvent
	var total int64

	// Get total count
	if err := r.DB.WithContext(ctx).Model(&model.SecurityEvent{}).Where("created_at BETWEEN ? AND ?", startTime, endTime).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get security events with pagination
	offset := (page - 1) * pageSize
	result := r.DB.WithContext(ctx).Where("created_at BETWEEN ? AND ?", startTime, endTime).Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return events, total, nil
}

// SearchSecurityEvents searches security events
func (r *AuditRepository) SearchSecurityEvents(ctx context.Context, query string, page, pageSize int) ([]model.SecurityEvent, int64, error) {
	var events []model.SecurityEvent
	var total int64

	// Build search query
	searchQuery := r.DB.WithContext(ctx).Model(&model.SecurityEvent{}).Where(
		"event_type ILIKE ? OR description ILIKE ?",
		"%"+query+"%", "%"+query+"%",
	)

	// Get total count
	if err := searchQuery.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get security events with pagination
	offset := (page - 1) * pageSize
	result := searchQuery.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&events)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return events, total, nil
}