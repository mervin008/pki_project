package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// SessionCookieName is the cookie a signed-in browser presents.
const SessionCookieName = "certpilot_session"

// SessionLifetime is how long a browser session lasts before it must be
// established again.
//
// Twelve hours rather than thirty days: this console can export private keys
// and delete certificate authorities, and a laptop left open in an office is
// the ordinary case, not the exotic one. It comfortably outlasts a shift, which
// is the length that actually matters here.
const SessionLifetime = 12 * time.Hour

// SessionStore is the slice of the store session authentication needs.
type SessionStore interface {
	SessionByHash(ctx context.Context, tokenHash string) (*store.Session, *store.User, error)
	TouchSession(ctx context.Context, id string, seenAt time.Time, ip string) error
	RevokeSession(ctx context.Context, tokenHash string) error
}

// NewSessionToken returns a raw session token and the hash to store.
//
// The raw value exists only in the cookie. What is stored is its SHA-256, so a
// stolen database yields nothing that can be presented as a session — the same
// property display tokens have.
func NewSessionToken() (raw, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	raw = "cps_" + base64.RawURLEncoding.EncodeToString(buf)
	return raw, HashSessionToken(raw), nil
}

// HashSessionToken hashes a raw token for storage and lookup.
func HashSessionToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// SetSessionCookie writes the session cookie.
//
// httpOnly is the point of the whole design: script on this origin cannot read
// the value, so a cross-site scripting flaw cannot walk away with a credential
// that outlives the page. SameSite=Strict is what makes it safe to authenticate
// state-changing requests with a cookie at all — without it, any site could
// cause the browser to send it.
//
// Secure is set unless the request arrived over plain HTTP on a loopback
// address, because a Secure cookie is silently discarded over http://localhost
// in some browsers and the resulting symptom — signing in appears to work, then
// every request is anonymous — is genuinely hard to diagnose.
func SetSessionCookie(c *gin.Context, raw string, expires time.Time) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     SessionCookieName,
		Value:    raw,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   !isPlainLoopback(c),
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearSessionCookie removes the session cookie.
//
// The attributes must match the ones it was set with, or the browser treats it
// as a different cookie and quietly keeps the original.
func ClearSessionCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !isPlainLoopback(c),
		SameSite: http.SameSiteStrictMode,
	})
}

func isPlainLoopback(c *gin.Context) bool {
	if c.Request.TLS != nil {
		return false
	}
	host := c.Request.Host
	if i := strings.LastIndex(host, ":"); i != -1 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// SessionAuth authenticates a browser session cookie.
//
// Runs ahead of bearer authentication and takes effect only when no
// Authorization header was sent, matching the precedence display tokens
// already follow: an explicit credential always wins over an ambient one, so a
// cookie left in a browser cannot mask the identity of a request that presented
// a token.
func SessionAuth(st SessionStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("Authorization") != "" {
			c.Next()
			return
		}

		cookie, err := c.Cookie(SessionCookieName)
		if err != nil || strings.TrimSpace(cookie) == "" {
			c.Next()
			return
		}

		hash := HashSessionToken(cookie)
		sess, user, err := st.SessionByHash(c.Request.Context(), hash)
		if err != nil {
			slog.Error("could not look up a session", "error", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "your session could not be checked, so this request was refused rather than allowed",
			})
			return
		}

		// A cookie that does not resolve is cleared rather than ignored.
		// Leaving it in place means every subsequent request repeats the same
		// failed lookup, and the browser keeps presenting a credential that
		// will never work again.
		if sess == nil || user == nil {
			ClearSessionCookie(c)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "this session is not recognised; sign in again",
			})
			return
		}

		// Belt and braces over the store's own lookup, and the real comparison
		// for any implementation that resolves sessions by scanning.
		if subtle.ConstantTimeCompare([]byte(sess.TokenHash), []byte(hash)) != 1 {
			ClearSessionCookie(c)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "this session is not recognised"})
			return
		}

		now := time.Now()
		if !sess.IsUsable(now) {
			ClearSessionCookie(c)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "this session has expired or been ended; sign in again",
			})
			return
		}

		// Checked on every request, not only at sign-in. Suspending somebody
		// has to take effect while they are looking at the screen, not the next
		// time they happen to log in.
		if !user.IsActive() {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "this account is suspended in CertPilot",
			})
			return
		}

		c.Set(ContextUserID, user.Subject)
		c.Set(ContextUserEmail, user.Email)
		c.Set(ContextUserRole, user.Role)
		c.Set(ContextUserDBID, user.ID)
		c.Set(ContextAuthMethod, AuthMethodSession)
		c.Set(ContextSessionID, sess.ID)

		if err := st.TouchSession(c.Request.Context(), sess.ID, now, c.ClientIP()); err != nil {
			slog.Warn("could not record session activity", "error", err, "session_id", sess.ID)
		}

		c.Next()
	}
}
