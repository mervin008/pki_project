package api

import (
	"net/http"

	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/config"
	"github.com/gin-gonic/gin"
)

// SessionHandler serves what a browser needs in order to sign in, and who it
// is once it has.
type SessionHandler struct {
	store store.Store
	auth  config.AuthConfig
}

func NewSessionHandler(s store.Store, auth config.AuthConfig) *SessionHandler {
	return &SessionHandler{store: s, auth: auth}
}

// AuthConfigResponse tells the frontend how to authenticate against this
// instance.
//
// Served rather than compiled in, so that one deployment is described by one
// configuration file. A frontend carrying its own build-time copy of the issuer
// and client id can disagree with the core it is talking to, and the way that
// disagreement presents is a login that appears to succeed followed by 401 on
// every subsequent request — which reads as a broken API rather than as a
// mismatched setting.
//
// Everything here is public by construction. In authorization code with PKCE
// there is no client secret: the issuer and client id are sent to the provider
// in a URL the user can read.
type AuthConfigResponse struct {
	// Mode is "oidc", "anonymous", or "unconfigured".
	Mode     string   `json:"mode"`
	Issuer   string   `json:"issuer,omitempty"`
	ClientID string   `json:"client_id,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	Audience string   `json:"audience,omitempty"`
}

// Config handles GET /api/v1/auth/config.
//
// Deliberately unauthenticated: it is what a browser reads before it has any
// credential at all.
func (h *SessionHandler) Config(c *gin.Context) {
	switch {
	case h.auth.AllowAnonymous:
		// Development. Saying so explicitly is what lets the frontend skip its
		// login screen rather than presenting one that cannot work.
		c.JSON(http.StatusOK, AuthConfigResponse{Mode: "anonymous"})

	case h.auth.Issuer != "" && h.auth.ClientID != "":
		c.JSON(http.StatusOK, AuthConfigResponse{
			Mode:     "oidc",
			Issuer:   h.auth.Issuer,
			ClientID: h.auth.ClientID,
			Scopes:   h.auth.Scopes,
			Audience: h.auth.Audience,
		})

	default:
		// Tokens are still verified, but nothing here can start a sign-in. An
		// API-only deployment is a legitimate configuration; a browser being
		// told plainly that it cannot log in is better than a login button
		// that fails at the provider with an unreadable error.
		c.JSON(http.StatusOK, AuthConfigResponse{Mode: "unconfigured"})
	}
}

// MeResponse is the caller's own identity and role.
type MeResponse struct {
	Subject     string `json:"subject"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role"`
	// AuthMethod distinguishes a person from a wall display from local
	// development, which the UI needs in order to decide what to offer.
	AuthMethod string `json:"auth_method"`
	// UserID is CertPilot's own identifier, absent for display tokens and
	// anonymous development where no user row exists.
	UserID     string `json:"user_id,omitempty"`
	RoleSource string `json:"role_source,omitempty"`
}

// Me handles GET /api/v1/me.
//
// The frontend must not decide a role by reading the token itself. The role
// that governs a request is the one in CertPilot's users table, and this is the
// only endpoint that reports it — a UI that decoded the JWT would show controls
// matching a claim the API stopped honouring the moment somebody was demoted.
func (h *SessionHandler) Me(c *gin.Context) {
	resp := MeResponse{
		Subject:     c.GetString(middleware.ContextUserID),
		Email:       c.GetString(middleware.ContextUserEmail),
		Role:        c.GetString(middleware.ContextUserRole),
		AuthMethod:  c.GetString(middleware.ContextAuthMethod),
		UserID:      c.GetString(middleware.ContextUserDBID),
		DisplayName: "",
	}

	if resp.UserID != "" {
		if u, err := h.store.GetUser(c.Request.Context(), resp.UserID); err == nil && u != nil {
			resp.DisplayName = u.DisplayName
			resp.RoleSource = u.RoleSource
		}
	}

	c.JSON(http.StatusOK, resp)
}
