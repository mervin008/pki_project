package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// UserClaims represents the claims inside a Supabase JWT token.
type UserClaims struct {
	Sub         string                 `json:"sub"`
	Email       string                 `json:"email"`
	Role        string                 `json:"role"` // postgres role e.g. authenticated
	AppMetadata map[string]interface{} `json:"app_metadata"`
	jwt.RegisteredClaims
}

// GetCertPilotRole returns the RBAC role assigned in app_metadata (defaults to "viewer").
func (c *UserClaims) GetCertPilotRole() string {
	if c.AppMetadata != nil {
		if role, ok := c.AppMetadata["certpilot_role"].(string); ok && role != "" {
			return role
		}
	}
	return "viewer"
}

// AuthMiddleware creates a Gin middleware that validates Supabase JWTs.
// If devMode is true and no token is provided, a default dev admin context is used.
func AuthMiddleware(jwtSecret string, devMode bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		if authHeader == "" {
			if devMode {
				// In development mode, allow anonymous requests with admin role for ease of testing
				c.Set("user_id", "00000000-0000-0000-0000-000000000001")
				c.Set("user_email", "dev@certpilot.local")
				c.Set("user_role", "admin")
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Bearer token required"})
			return
		}

		// Parse token
		claims := &UserClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			// If validation with secret fails, check if we're in dev mode
			if devMode {
				c.Set("user_id", "00000000-0000-0000-0000-000000000001")
				c.Set("user_email", "dev@certpilot.local")
				c.Set("user_role", "admin")
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		c.Set("user_id", claims.Sub)
		c.Set("user_email", claims.Email)
		c.Set("user_role", claims.GetCertPilotRole())
		c.Next()
	}
}

// RequireRole enforces that the authenticated user has one of the allowed roles.
func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleVal, exists := c.Get("user_role")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Role not found in context"})
			return
		}

		role := roleVal.(string)
		for _, allowed := range allowedRoles {
			if role == allowed || role == "admin" { // admin has superuser permissions
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": fmt.Sprintf("Role '%s' does not have permission for this operation", role),
		})
	}
}

// CORS creates a standard CORS middleware.
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, PATCH, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
