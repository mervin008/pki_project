// Package middleware provides authentication, authorization, and request
// hygiene for the CertPilot HTTP API.
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/certpilot/certpilot/pkg/config"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// RBAC roles, in ascending order of privilege for write operations.
const (
	RoleViewer   = "viewer"
	RoleAuditor  = "auditor"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// Context keys set by AuthMiddleware.
const (
	ContextUserID    = "user_id"
	ContextUserEmail = "user_email"
	ContextUserRole  = "user_role"
	// ContextAuthMethod records how the caller proved who they are. It is what
	// lets a later middleware tell "already authenticated" from "not yet
	// looked at", and it is worth recording in its own right: an audit entry
	// attributed to a corridor screen means something different from one
	// attributed to a person.
	ContextAuthMethod = "auth_method"
)

// Authentication methods recorded in ContextAuthMethod.
const (
	AuthMethodBearer       = "bearer"
	AuthMethodAnonymous    = "anonymous"
	AuthMethodDisplayToken = "display_token"
)

// UserClaims represents the claims inside an identity provider's JWT.
type UserClaims struct {
	Email       string         `json:"email"`
	AppMetadata map[string]any `json:"app_metadata"`
	jwt.RegisteredClaims
}

// Role returns the RBAC role from app_metadata, defaulting to viewer.
//
// The role is read from app_metadata rather than user_metadata deliberately:
// user_metadata is writable by the user the token belongs to, so trusting it
// would let any account promote itself to admin.
func (c *UserClaims) Role(claimName string) string {
	if claimName == "" {
		claimName = "certpilot_role"
	}
	if c.AppMetadata != nil {
		if role, ok := c.AppMetadata[claimName].(string); ok {
			switch role {
			case RoleAdmin, RoleOperator, RoleAuditor, RoleViewer:
				return role
			}
		}
	}
	return RoleViewer
}

// Authenticator verifies bearer tokens.
type Authenticator struct {
	cfg   config.AuthConfig
	cache *jwk.Cache

	// anonymousWarn ensures the anonymous-access warning is logged once per
	// process rather than once per request.
	anonymousWarn sync.Once
}

// NewAuthenticator builds an Authenticator. When a JWKS URL is configured, its
// keys are fetched and refreshed in the background.
func NewAuthenticator(ctx context.Context, cfg config.AuthConfig) (*Authenticator, error) {
	a := &Authenticator{cfg: cfg}

	if cfg.JWKSURL != "" {
		cache, err := jwk.NewCache(ctx, httprc.NewClient())
		if err != nil {
			return nil, fmt.Errorf("auth: failed to create JWKS cache: %w", err)
		}
		if err := cache.Register(ctx, cfg.JWKSURL, jwk.WithMinInterval(15*time.Minute)); err != nil {
			return nil, fmt.Errorf("auth: failed to register JWKS endpoint %s: %w", cfg.JWKSURL, err)
		}
		a.cache = cache
	}

	if a.cache == nil && cfg.JWTSecret == "" && !cfg.AllowAnonymous {
		return nil, fmt.Errorf("auth: no verification method configured; set auth.jwks_url, auth.jwt_secret, or auth.allow_anonymous")
	}

	return a, nil
}

// Middleware returns the Gin handler that authenticates each request.
func (a *Authenticator) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// An earlier middleware may already have established an identity — in
		// practice, a display token. That path grants nothing but read-only
		// viewer access and enforces its own restrictions, so there is nothing
		// left to check here.
		if c.GetString(ContextAuthMethod) != "" {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")

		if authHeader == "" {
			// Anonymous access is a first-run convenience, gated at config
			// load to development mode on a loopback address. Crucially it
			// applies only when no token was presented at all — an invalid
			// token is always a rejection, never a fallback to admin.
			if a.cfg.AllowAnonymous {
				a.anonymousWarn.Do(func() {
					gin.DefaultWriter.Write([]byte(
						"WARNING: anonymous API access is enabled; every request is treated as admin\n"))
				})
				c.Set(ContextUserID, "00000000-0000-0000-0000-000000000001")
				c.Set(ContextUserEmail, "anonymous@certpilot.local")
				c.Set(ContextUserRole, RoleAdmin)
				c.Set(ContextAuthMethod, AuthMethodAnonymous)
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
			return
		}

		tokenString, ok := strings.CutPrefix(authHeader, "Bearer ")
		if !ok || strings.TrimSpace(tokenString) == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header must be of the form 'Bearer <token>'",
			})
			return
		}

		claims, err := a.Verify(c.Request.Context(), tokenString)
		if err != nil {
			// The reason is deliberately not echoed back: it tells an attacker
			// which part of their forgery to fix.
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
			})
			return
		}

		c.Set(ContextUserID, claims.Subject)
		c.Set(ContextUserEmail, claims.Email)
		c.Set(ContextUserRole, claims.Role(a.cfg.RoleClaim))
		c.Set(ContextAuthMethod, AuthMethodBearer)
		c.Next()
	}
}

// Verify validates a token and returns its claims.
func (a *Authenticator) Verify(ctx context.Context, tokenString string) (*UserClaims, error) {
	claims := &UserClaims{}

	opts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30 * time.Second),
	}
	if a.cfg.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(a.cfg.Issuer))
	}
	if a.cfg.Audience != "" {
		opts = append(opts, jwt.WithAudience(a.cfg.Audience))
	}

	// Pinning the accepted algorithms is what stops an attacker swapping the
	// header to "none", or to HS256 signed with the public key of an RS256
	// keypair.
	var allowed []string
	if a.cache != nil {
		allowed = append(allowed, "RS256", "RS512", "ES256", "ES384", "ES512", "EdDSA")
	}
	if a.cfg.JWTSecret != "" {
		allowed = append(allowed, "HS256")
	}
	opts = append(opts, jwt.WithValidMethods(allowed))

	token, err := jwt.ParseWithClaims(tokenString, claims, a.keyFunc(ctx), opts...)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("auth: token is not valid")
	}

	return claims, nil
}

func (a *Authenticator) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if _, isHMAC := token.Method.(*jwt.SigningMethodHMAC); isHMAC {
			if a.cfg.JWTSecret == "" {
				return nil, fmt.Errorf("auth: HMAC-signed token presented but no shared secret is configured")
			}
			return []byte(a.cfg.JWTSecret), nil
		}

		if a.cache == nil {
			return nil, fmt.Errorf("auth: asymmetrically signed token presented but no JWKS endpoint is configured")
		}

		set, err := a.cache.Lookup(ctx, a.cfg.JWKSURL)
		if err != nil {
			return nil, fmt.Errorf("auth: failed to fetch JWKS: %w", err)
		}

		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("auth: token header has no key ID")
		}

		key, found := set.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("auth: no key in the JWKS matches key ID %q", kid)
		}

		var pubKey any
		if err := jwk.Export(key, &pubKey); err != nil {
			return nil, fmt.Errorf("auth: failed to export signing key: %w", err)
		}
		return pubKey, nil
	}
}

// RequireRole enforces that the authenticated user holds one of the allowed
// roles. Admin passes every check.
func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetString(ContextUserRole)
		if role == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "No role in request context"})
			return
		}

		if role == RoleAdmin {
			c.Next()
			return
		}
		for _, allowed := range allowedRoles {
			if role == allowed {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": fmt.Sprintf("Role %q is not permitted to perform this operation", role),
		})
	}
}

// CORS restricts browser access to the configured origins.
//
// The previous implementation paired a wildcard origin with credentials, a
// combination the Fetch specification rejects outright — so it did not work in
// any browser while looking permissive enough to discourage anyone from
// checking.
func CORS(allowedOrigins []string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[strings.TrimSuffix(strings.TrimSpace(o), "/")] = true
	}

	return func(c *gin.Context) {
		origin := strings.TrimSuffix(c.GetHeader("Origin"), "/")

		if origin != "" && allowed[origin] {
			h := c.Writer.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Allow-Headers",
				"Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Accept, Origin, Cache-Control, X-Requested-With")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			h.Set("Access-Control-Max-Age", "600")
			// Responses vary by origin, so caches must not share them.
			h.Add("Vary", "Origin")
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// SecurityHeaders sets conservative response headers for an API that serves
// certificate material.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// Nothing this API returns should ever be stored by an intermediary.
		h.Set("Cache-Control", "no-store")
		c.Next()
	}
}
