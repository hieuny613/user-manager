package middleware

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// SecurityConfig chứa cấu hình cho security headers
type SecurityConfig struct {
	CSPEnabled            bool
	CSPDefaultSrc         []string
	CSPScriptSrc          []string
	CSPStyleSrc           []string
	CSPImgSrc             []string
	CSPConnectSrc         []string
	CSPFontSrc            []string
	CSPObjectSrc          []string
	CSPMediaSrc           []string
	CSPFrameSrc           []string
	HSTSEnabled           bool
	HSTSMaxAge            int
	HSTSIncludeSubDomains bool
	HSTSPreload           bool
	XFrameOptions         string
	XContentTypeOptions   string
	ReferrerPolicy        string
	PermissionsPolicy     string
}

// DefaultSecurityConfig trả về cấu hình security mặc định
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		CSPEnabled:            true,
		CSPDefaultSrc:         []string{"'self'"},
		CSPScriptSrc:          []string{"'self'", "'unsafe-inline'", "'unsafe-eval'"},
		CSPStyleSrc:           []string{"'self'", "'unsafe-inline'"},
		CSPImgSrc:             []string{"'self'", "data:"},
		CSPConnectSrc:         []string{"'self'"},
		CSPFontSrc:            []string{"'self'"},
		CSPObjectSrc:          []string{"'none'"},
		CSPMediaSrc:           []string{"'self'"},
		CSPFrameSrc:           []string{"'self'"},
		HSTSEnabled:           true,
		HSTSMaxAge:            31536000, // 1 năm
		HSTSIncludeSubDomains: true,
		HSTSPreload:           false,
		XFrameOptions:         "SAMEORIGIN",
		XContentTypeOptions:   "nosniff",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		PermissionsPolicy:     "camera=(), microphone=(), geolocation=()",
	}
}

// SecurityHeadersMiddleware thêm các security headers vào response
func SecurityHeadersMiddleware(config SecurityConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Content-Security-Policy
		if config.CSPEnabled {
			csp := buildCSP(config)
			c.Header("Content-Security-Policy", csp)
		}

		// Strict-Transport-Security (HSTS)
		if config.HSTSEnabled {
			hsts := buildHSTS(config)
			c.Header("Strict-Transport-Security", hsts)
		}

		// X-Frame-Options
		if config.XFrameOptions != "" {
			c.Header("X-Frame-Options", config.XFrameOptions)
		}

		// X-Content-Type-Options
		if config.XContentTypeOptions != "" {
			c.Header("X-Content-Type-Options", config.XContentTypeOptions)
		}

		// X-XSS-Protection
		c.Header("X-XSS-Protection", "1; mode=block")

		// Referrer-Policy
		if config.ReferrerPolicy != "" {
			c.Header("Referrer-Policy", config.ReferrerPolicy)
		}

		// Permissions-Policy
		if config.PermissionsPolicy != "" {
			c.Header("Permissions-Policy", config.PermissionsPolicy)
		}

		// Cache-Control
		c.Header("Cache-Control", "no-store, max-age=0")

		c.Next()
	}
}

// buildCSP tạo chuỗi Content-Security-Policy từ cấu hình
func buildCSP(config SecurityConfig) string {
	csp := ""

	// Default-Src
	if len(config.CSPDefaultSrc) > 0 {
		csp += "default-src " + joinSources(config.CSPDefaultSrc) + "; "
	}

	// Script-Src
	if len(config.CSPScriptSrc) > 0 {
		csp += "script-src " + joinSources(config.CSPScriptSrc) + "; "
	}

	// Style-Src
	if len(config.CSPStyleSrc) > 0 {
		csp += "style-src " + joinSources(config.CSPStyleSrc) + "; "
	}

	// Img-Src
	if len(config.CSPImgSrc) > 0 {
		csp += "img-src " + joinSources(config.CSPImgSrc) + "; "
	}

	// Connect-Src
	if len(config.CSPConnectSrc) > 0 {
		csp += "connect-src " + joinSources(config.CSPConnectSrc) + "; "
	}

	// Font-Src
	if len(config.CSPFontSrc) > 0 {
		csp += "font-src " + joinSources(config.CSPFontSrc) + "; "
	}

	// Object-Src
	if len(config.CSPObjectSrc) > 0 {
		csp += "object-src " + joinSources(config.CSPObjectSrc) + "; "
	}

	// Media-Src
	if len(config.CSPMediaSrc) > 0 {
		csp += "media-src " + joinSources(config.CSPMediaSrc) + "; "
	}

	// Frame-Src
	if len(config.CSPFrameSrc) > 0 {
		csp += "frame-src " + joinSources(config.CSPFrameSrc) + "; "
	}

	return csp
}

// buildHSTS tạo chuỗi Strict-Transport-Security từ cấu hình
func buildHSTS(config SecurityConfig) string {
	hsts := "max-age=" + strconv.Itoa(config.HSTSMaxAge)

	if config.HSTSIncludeSubDomains {
		hsts += "; includeSubDomains"
	}

	if config.HSTSPreload {
		hsts += "; preload"
	}

	return hsts
}

// joinSources nối các sources thành một chuỗi
func joinSources(sources []string) string {
	return strings.Join(sources, " ")
}

// BasicSecurityHeadersMiddleware là phiên bản đơn giản hơn với các headers cơ bản
func BasicSecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// X-Frame-Options
		c.Header("X-Frame-Options", "SAMEORIGIN")

		// X-Content-Type-Options
		c.Header("X-Content-Type-Options", "nosniff")

		// X-XSS-Protection
		c.Header("X-XSS-Protection", "1; mode=block")

		// Referrer-Policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Content-Security-Policy
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")

		c.Next()
	}
}
