package utils

import (
	"sync"

	"backend/service"
)

var (
	userServiceInstance    *service.UserService
	userServiceMutex       sync.RWMutex
	auditServiceInstance   *service.AuditService
	auditServiceMutex      sync.RWMutex
	metricsServiceInstance *service.MetricsService
	metricsServiceMutex    sync.RWMutex
)

// SetUserService sets the global user service instance
func SetUserService(service *service.UserService) {
	userServiceMutex.Lock()
	defer userServiceMutex.Unlock()
	userServiceInstance = service
}

// GetUserService returns the global user service instance
func GetUserService() *service.UserService {
	userServiceMutex.RLock()
	defer userServiceMutex.RUnlock()
	return userServiceInstance
}

// SetAuditService sets the global audit service instance
func SetAuditService(service *service.AuditService) {
	auditServiceMutex.Lock()
	defer auditServiceMutex.Unlock()
	auditServiceInstance = service
}

// GetAuditService returns the global audit service instance
func GetAuditService() *service.AuditService {
	auditServiceMutex.RLock()
	defer auditServiceMutex.RUnlock()
	return auditServiceInstance
}

// SetMetricsService sets the global metrics service instance
func SetMetricsService(service *service.MetricsService) {
	metricsServiceMutex.Lock()
	defer metricsServiceMutex.Unlock()
	metricsServiceInstance = service
}

// GetMetricsService returns the global metrics service instance
func GetMetricsService() *service.MetricsService {
	metricsServiceMutex.RLock()
	defer metricsServiceMutex.RUnlock()
	return metricsServiceInstance
}
