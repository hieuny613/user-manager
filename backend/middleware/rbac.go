package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"backend/model"
	"backend/utils"
)

// RequirePermission is a middleware for checking if a user has a specific permission
func RequirePermission(db *gorm.DB, resource, action string, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get request logger
		reqLogger := utils.GetRequestLogger(c, logger)

		// Get user ID from context
		userID, exists := c.Get("user_id")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		// Check if the user has the required permission
		hasPermission, err := hasPermission(db, userID.(uuid.UUID), resource, action)
		if err != nil {
			reqLogger.WithError(err).Error("Failed to check user permissions")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		if !hasPermission {
			reqLogger.WithFields(logrus.Fields{
				"user_id":  userID,
				"resource": resource,
				"action":   action,
			}).Warn("Permission denied")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
			return
		}

		// Continue with the request
		c.Next()
	}
}

// RequireRole is a middleware for checking if a user has a specific role
func RequireRole(db *gorm.DB, roleName string, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get request logger
		reqLogger := utils.GetRequestLogger(c, logger)

		// Get user ID from context
		userID, exists := c.Get("user_id")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		// Check if the user has the required role
		hasRole, err := hasRole(db, userID.(uuid.UUID), roleName)
		if err != nil {
			reqLogger.WithError(err).Error("Failed to check user roles")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		if !hasRole {
			reqLogger.WithFields(logrus.Fields{
				"user_id": userID,
				"role":    roleName,
			}).Warn("Role required")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Role required"})
			return
		}

		// Continue with the request
		c.Next()
	}
}

// hasPermission checks if a user has a specific permission
func hasPermission(db *gorm.DB, userID uuid.UUID, resource, action string) (bool, error) {
	// Check if the user has the permission directly through roles
	var count int64
	err := db.Raw(`
		SELECT COUNT(*) FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN roles r ON rp.role_id = r.id
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = ? AND p.resource = ? AND p.action = ?
		AND p.deleted_at IS NULL AND r.deleted_at IS NULL AND ur.deleted_at IS NULL AND rp.deleted_at IS NULL
	`, userID, resource, action).Count(&count).Error

	if err != nil {
		return false, err
	}

	if count > 0 {
		return true, nil
	}

	// Check if the user has the permission through groups
	err = db.Raw(`
		SELECT COUNT(*) FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN roles r ON rp.role_id = r.id
		JOIN group_roles gr ON r.id = gr.role_id
		JOIN groups g ON gr.group_id = g.id
		JOIN user_groups ug ON g.id = ug.group_id
		WHERE ug.user_id = ? AND p.resource = ? AND p.action = ?
		AND p.deleted_at IS NULL AND r.deleted_at IS NULL AND gr.deleted_at IS NULL
		AND g.deleted_at IS NULL AND ug.deleted_at IS NULL AND rp.deleted_at IS NULL
	`, userID, resource, action).Count(&count).Error

	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// hasRole checks if a user has a specific role
func hasRole(db *gorm.DB, userID uuid.UUID, roleName string) (bool, error) {
	// Check if the user has the role directly
	var count int64
	err := db.Raw(`
		SELECT COUNT(*) FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = ? AND r.name = ?
		AND r.deleted_at IS NULL AND ur.deleted_at IS NULL
	`, userID, roleName).Count(&count).Error

	if err != nil {
		return false, err
	}

	if count > 0 {
		return true, nil
	}

	// Check if the user has the role through groups
	err = db.Raw(`
		SELECT COUNT(*) FROM roles r
		JOIN group_roles gr ON r.id = gr.role_id
		JOIN groups g ON gr.group_id = g.id
		JOIN user_groups ug ON g.id = ug.group_id
		WHERE ug.user_id = ? AND r.name = ?
		AND r.deleted_at IS NULL AND gr.deleted_at IS NULL
		AND g.deleted_at IS NULL AND ug.deleted_at IS NULL
	`, userID, roleName).Count(&count).Error

	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// GetUserPermissions gets all permissions for a user
func GetUserPermissions(db *gorm.DB, userID uuid.UUID) ([]model.Permission, error) {
	var permissions []model.Permission

	// Get permissions from user roles
	err := db.Raw(`
		SELECT DISTINCT p.* FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN roles r ON rp.role_id = r.id
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = ?
		AND p.deleted_at IS NULL AND r.deleted_at IS NULL AND ur.deleted_at IS NULL AND rp.deleted_at IS NULL
		UNION
		SELECT DISTINCT p.* FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN roles r ON rp.role_id = r.id
		JOIN group_roles gr ON r.id = gr.role_id
		JOIN groups g ON gr.group_id = g.id
		JOIN user_groups ug ON g.id = ug.group_id
		WHERE ug.user_id = ?
		AND p.deleted_at IS NULL AND r.deleted_at IS NULL AND gr.deleted_at IS NULL
		AND g.deleted_at IS NULL AND ug.deleted_at IS NULL AND rp.deleted_at IS NULL
	`, userID, userID).Scan(&permissions).Error

	if err != nil {
		return nil, err
	}

	return permissions, nil
}

// GetUserRoles gets all roles for a user
func GetUserRoles(db *gorm.DB, userID uuid.UUID) ([]model.Role, error) {
	var roles []model.Role

	// Get roles from user roles and group roles
	err := db.Raw(`
		SELECT DISTINCT r.* FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = ?
		AND r.deleted_at IS NULL AND ur.deleted_at IS NULL
		UNION
		SELECT DISTINCT r.* FROM roles r
		JOIN group_roles gr ON r.id = gr.role_id
		JOIN groups g ON gr.group_id = g.id
		JOIN user_groups ug ON g.id = ug.group_id
		WHERE ug.user_id = ?
		AND r.deleted_at IS NULL AND gr.deleted_at IS NULL
		AND g.deleted_at IS NULL AND ug.deleted_at IS NULL
	`, userID, userID).Scan(&roles).Error

	if err != nil {
		return nil, err
	}

	return roles, nil
}