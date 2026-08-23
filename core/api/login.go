package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/passwords"
	"github.com/gin-gonic/gin"
)

// LoginInput is an email and a password. Nothing else — no "remember me",
// because a longer session on a console that can export private keys is not a
// convenience worth offering.
type LoginInput struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// Login handles POST /api/v1/auth/login.
//
// Every failure returns the same message and the same status. Distinguishing
// "no such account" from "wrong password" turns the endpoint into an address
// oracle, and distinguishing "locked out" tells an attacker their guessing is
// working. The real reason is logged and audited, where the operator can read
// it and the person guessing cannot.
func (h *SessionHandler) Login(c *gin.Context) {
	var input LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "an email address and a password are required"})
		return
	}

	// Bounded before any work is done. Argon2id allocates 64 MiB per attempt,
	// so an unbounded password field is a cheap way to make the core do
	// expensive things.
	if len([]rune(input.Password)) > passwords.MaxLength {
		c.JSON(http.StatusBadRequest, gin.H{"error": "that password is too long to be one of ours"})
		return
	}

	user, outcome, err := h.store.AuthenticatePassword(c.Request.Context(), input.Email, input.Password)
	if err != nil {
		slog.Error("sign-in failed unexpectedly", "error", err, "email", input.Email)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "sign-in could not be completed; the API log has the reason",
		})
		return
	}

	if outcome != store.LoginOK {
		slog.Warn("sign-in refused",
			"reason", loginReason(outcome), "email", input.Email, "client_ip", c.ClientIP())

		if user != nil {
			h.audit(c, user.Subject, "auth.login_failed", map[string]any{
				"reason": loginReason(outcome), "email": input.Email,
			})
		}

		status := http.StatusUnauthorized
		if outcome == store.LoginLockedOut {
			// The one distinction worth making, because it is the one a
			// legitimate user needs in order to stop trying. It reveals only
			// that this address is throttled — which an attacker who caused the
			// lock already knows.
			status = http.StatusTooManyRequests
		}
		c.JSON(status, gin.H{"error": loginMessage(outcome)})
		return
	}

	raw, hash, err := middleware.NewSessionToken()
	if err != nil {
		slog.Error("could not generate a session token", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sign-in could not be completed"})
		return
	}

	expires := time.Now().Add(middleware.SessionLifetime)
	if _, err := h.store.CreateSession(c.Request.Context(), user.ID, hash, expires,
		c.Request.UserAgent(), c.ClientIP()); err != nil {
		slog.Error("could not create a session", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sign-in could not be completed"})
		return
	}

	middleware.SetSessionCookie(c, raw, expires)
	h.audit(c, user.Subject, "auth.login", map[string]any{"email": user.Email})

	c.JSON(http.StatusOK, MeResponse{
		Subject:     user.Subject,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Role:        user.Role,
		AuthMethod:  middleware.AuthMethodSession,
		UserID:      user.ID,
		RoleSource:  user.RoleSource,
	})
}

func loginReason(outcome store.LoginOutcome) string {
	switch outcome {
	case store.LoginNoSuchAccount:
		return "no such account"
	case store.LoginWrongPassword:
		return "wrong password"
	case store.LoginLockedOut:
		return "locked out"
	case store.LoginSuspended:
		return "account suspended"
	case store.LoginNoPasswordSet:
		return "no password set"
	default:
		return "unknown"
	}
}

func loginMessage(outcome store.LoginOutcome) string {
	if outcome == store.LoginLockedOut {
		return "too many failed attempts for this account; try again shortly"
	}
	return "that email address and password do not match an account"
}

// Logout handles POST /api/v1/auth/logout.
func (h *SessionHandler) Logout(c *gin.Context) {
	// Revoked by the cookie's own hash rather than by session id, so that a
	// request can only ever end its own session.
	if cookie, err := c.Cookie(middleware.SessionCookieName); err == nil && cookie != "" {
		if err := h.store.RevokeSession(c.Request.Context(), middleware.HashSessionToken(cookie)); err != nil {
			slog.Warn("could not revoke a session on sign-out", "error", err)
		}
	}

	// Cleared whatever happened above. Signing out must never leave somebody
	// signed in because a database write failed.
	middleware.ClearSessionCookie(c)
	h.audit(c, c.GetString(middleware.ContextUserID), "auth.logout", nil)

	c.JSON(http.StatusOK, gin.H{"message": "signed out"})
}

// ChangePasswordInput carries the current password as well as the new one.
type ChangePasswordInput struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
}

// ChangePassword handles POST /api/v1/auth/password.
//
// The current password is required even though the caller is already
// authenticated. A session left open on an unattended machine should not be
// enough to lock its owner out of their own account.
func (h *SessionHandler) ChangePassword(c *gin.Context) {
	var input ChangePasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "both the current password and a new one are required",
		})
		return
	}

	userID := c.GetString(middleware.ContextUserDBID)
	if userID == "" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "only an account with a password can change one",
		})
		return
	}

	user, err := h.store.GetUser(c.Request.Context(), userID)
	if err != nil || user == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "your account could not be read"})
		return
	}

	if _, outcome, err := h.store.AuthenticatePassword(
		c.Request.Context(), user.Email, input.CurrentPassword); err != nil || outcome != store.LoginOK {
		c.JSON(http.StatusForbidden, gin.H{"error": "the current password is not correct"})
		return
	}

	// The requirement is stated, not merely enforced: somebody choosing a
	// password needs to know what would satisfy it.
	if err := passwords.Validate(input.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if input.NewPassword == input.CurrentPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "the new password is the same as the current one"})
		return
	}

	if err := h.store.SetUserPassword(c.Request.Context(), userID, input.NewPassword, false); err != nil {
		slog.Error("could not set a password", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "the password could not be changed"})
		return
	}

	// Every other session is ended. A password change is usually a response to
	// believing somebody else has the old one, and leaving their session alive
	// makes the change theatre.
	if _, err := h.store.RevokeSessionsForUser(c.Request.Context(), userID); err != nil {
		slog.Warn("could not end other sessions after a password change", "error", err)
	}

	// This one is re-established, so the person changing their password is not
	// signed out by their own action.
	raw, hash, err := middleware.NewSessionToken()
	if err == nil {
		expires := time.Now().Add(middleware.SessionLifetime)
		if _, err := h.store.CreateSession(c.Request.Context(), userID, hash, expires,
			c.Request.UserAgent(), c.ClientIP()); err == nil {
			middleware.SetSessionCookie(c, raw, expires)
		}
	}

	h.audit(c, user.Subject, "auth.password_changed", nil)
	c.JSON(http.StatusOK, gin.H{"message": "password changed; other sessions have been signed out"})
}
