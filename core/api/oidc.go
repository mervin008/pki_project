package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/gin-gonic/gin"
)

// The core redeems the authorization code, not the browser.
//
// This is a backend-for-frontend, and it exists to answer one question: where
// does the credential that survives a page reload live? A single-page
// application that redeems the code itself gets a refresh token it has nowhere
// safe to put — every storage a page can reach is readable by script on that
// origin — so CertPilot kept it in localStorage and documented the trade-off.
//
// Once browser sessions became rows with an httpOnly cookie, that trade-off
// stopped being necessary. The browser now sends the code here, gets a session
// cookie back, and never handles a token at all. The refresh token is not
// stored anywhere: CertPilot's own session is the durable credential, and
// keeping a second one would mean holding a provider secret at rest to
// duplicate something the sessions table already does.
//
// What that costs, stated plainly: a federated session outlives revocation at
// the identity provider until it expires. CertPilot's answer to "this person
// should no longer have access" is suspending the account, which is checked on
// every request and ends every session immediately — the provider says who you
// are, CertPilot says what you may do.

// oidcExchangeTimeout bounds the call to the provider.
//
// A sign-in that hangs is a sign-in that fails; leaving the request open longer
// than this just holds a connection while somebody stares at a spinner.
const oidcExchangeTimeout = 15 * time.Second

// discoveryTTL is how long a provider's metadata is reused.
//
// Endpoints move about once in the lifetime of a deployment, so this is long.
// It is cached at all because the alternative is a well-known fetch on every
// sign-in, which turns the provider's availability into a hard dependency of
// each individual login rather than of the first one after a restart.
const discoveryTTL = time.Hour

type providerMetadata struct {
	TokenEndpoint string `json:"token_endpoint"`
	Issuer        string `json:"issuer"`
}

type discoveryCache struct {
	mu        sync.Mutex
	metadata  providerMetadata
	fetchedAt time.Time
}

var oidcDiscovery discoveryCache

// CallbackInput is what the browser brings back from the identity provider.
type CallbackInput struct {
	Code         string `json:"code" binding:"required"`
	CodeVerifier string `json:"code_verifier" binding:"required"`
	RedirectURI  string `json:"redirect_uri" binding:"required"`
	// Nonce is the value the browser put in the authorization request. It is
	// sent back so the core can check the ID token carries the same one — the
	// browser cannot be trusted to check it itself, because the whole point of
	// moving this here is that the browser is the untrusted half.
	Nonce string `json:"nonce" binding:"required"`
}

// Callback handles POST /api/v1/auth/callback.
//
// Public, because a sign-in cannot require being signed in. Every failure
// returns the same shape of message: the reasons are useful to an operator
// reading the log and useful to somebody probing the endpoint, so only the
// former gets them.
func (h *SessionHandler) Callback(c *gin.Context) {
	if h.auth.Issuer == "" || h.auth.ClientID == "" {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "this instance is not configured for single sign-on; sign in with an account instead",
		})
		return
	}

	var input CallbackInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "this sign-in response was incomplete; begin again from the sign-in page",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), oidcExchangeTimeout)
	defer cancel()

	metadata, err := h.providerMetadata(ctx)
	if err != nil {
		slog.Error("could not read the identity provider's metadata", "error", err, "issuer", h.auth.Issuer)
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "CertPilot could not reach the identity provider to complete this sign-in",
		})
		return
	}

	idToken, err := h.exchangeCode(ctx, metadata.TokenEndpoint, input)
	if err != nil {
		slog.Warn("the authorization code exchange failed", "error", err, "client_ip", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "the identity provider refused this sign-in; begin again from the sign-in page",
		})
		return
	}

	claims, err := h.authenticator.VerifyIDToken(ctx, idToken, h.auth.ClientID, input.Nonce)
	if err != nil {
		// Logged in full and reported in outline. The reason names which part
		// of a forgery to correct.
		slog.Warn("an ID token was refused", "error", err, "client_ip", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "the identity provider's response could not be verified, so it was refused",
		})
		return
	}

	user, err := h.authenticator.ResolveIdentity(ctx, claims)
	if err != nil {
		// Fail closed, exactly as the request path does. A role that cannot be
		// established is not a role.
		slog.Error("could not resolve a federated identity", "error", err, "subject", claims.Subject)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "your identity could not be resolved against CertPilot's user directory, " +
				"so no role could be established",
		})
		return
	}

	if !user.IsActive() {
		h.audit(c, user.Subject, "auth.login_failed", map[string]any{
			"reason": "account suspended", "email": user.Email, "method": "oidc",
		})
		c.JSON(http.StatusForbidden, gin.H{
			"error": "this account is suspended in CertPilot; the identity provider still accepts it",
		})
		return
	}

	raw, hash, err := middleware.NewSessionToken()
	if err != nil {
		slog.Error("could not generate a session token", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sign-in could not be completed"})
		return
	}

	expires := time.Now().Add(middleware.SessionLifetime)
	if _, err := h.store.CreateSession(ctx, user.ID, hash, expires,
		c.Request.UserAgent(), c.ClientIP()); err != nil {
		slog.Error("could not create a session", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sign-in could not be completed"})
		return
	}

	middleware.SetSessionCookie(c, raw, expires)
	h.audit(c, user.Subject, "auth.login", map[string]any{"email": user.Email, "method": "oidc"})

	c.JSON(http.StatusOK, MeResponse{
		Subject:     user.Subject,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Role:        user.Role,
		AuthMethod:  middleware.AuthMethodSession,
		UserID:      user.ID,
		RoleSource:  user.RoleSource,
		// A federated account has no CertPilot password to change, but the
		// field is carried rather than omitted so that one response shape means
		// one thing everywhere.
		MustChangePassword: user.MustChangePassword,
	})
}

// exchangeCode redeems the authorization code and returns the ID token.
//
// No client secret is sent, and none is configured: this is a public client and
// PKCE is what proves the code belongs to the browser that asked for it. The
// access and refresh tokens in the response are deliberately dropped on the
// floor — see the note at the top of this file.
func (h *SessionHandler) exchangeCode(ctx context.Context, tokenEndpoint string, input CallbackInput) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {input.Code},
		"redirect_uri":  {input.RedirectURI},
		"client_id":     {h.auth.ClientID},
		"code_verifier": {input.CodeVerifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Bounded: the response is a small JSON document, and an endpoint that
	// streams gigabytes at the core should not be able to.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokens); err != nil {
		return "", fmt.Errorf("token endpoint returned something that is not JSON: %w", err)
	}
	if tokens.IDToken == "" {
		return "", fmt.Errorf("token endpoint returned no id_token; check that the openid scope is requested")
	}
	return tokens.IDToken, nil
}

// providerMetadata reads and caches the provider's discovery document.
func (h *SessionHandler) providerMetadata(ctx context.Context) (providerMetadata, error) {
	oidcDiscovery.mu.Lock()
	defer oidcDiscovery.mu.Unlock()

	if oidcDiscovery.metadata.TokenEndpoint != "" &&
		oidcDiscovery.metadata.Issuer == h.auth.Issuer &&
		time.Since(oidcDiscovery.fetchedAt) < discoveryTTL {
		return oidcDiscovery.metadata, nil
	}

	endpoint := strings.TrimSuffix(h.auth.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return providerMetadata{}, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return providerMetadata{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return providerMetadata{}, fmt.Errorf("%s returned HTTP %d", endpoint, resp.StatusCode)
	}

	var metadata providerMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&metadata); err != nil {
		return providerMetadata{}, err
	}
	if metadata.TokenEndpoint == "" {
		return providerMetadata{}, fmt.Errorf("%s names no token_endpoint", endpoint)
	}

	// The issuer in the document must be the one that was asked, or the
	// discovery has been redirected somewhere else — which is how a
	// misconfigured proxy turns into an authentication bypass.
	if metadata.Issuer != "" && metadata.Issuer != h.auth.Issuer {
		return providerMetadata{}, fmt.Errorf(
			"discovery at %s describes issuer %q, not the configured %q",
			endpoint, metadata.Issuer, h.auth.Issuer)
	}
	metadata.Issuer = h.auth.Issuer

	oidcDiscovery.metadata = metadata
	oidcDiscovery.fetchedAt = time.Now()
	return metadata, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
