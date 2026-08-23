package vault

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// authInfo is the auth block Vault returns from a login.
type authInfo struct {
	ClientToken   string   `json:"client_token"`
	Accessor      string   `json:"accessor"`
	LeaseDuration int      `json:"lease_duration"`
	Renewable     bool     `json:"renewable"`
	TokenPolicies []string `json:"token_policies"`
}

// tokenInfo is what auth/token/lookup-self reports about a token.
type tokenInfo struct {
	DisplayName string   `json:"display_name"`
	Policies    []string `json:"policies"`
	TTL         int      `json:"ttl"`
	Renewable   bool     `json:"renewable"`
	Period      int      `json:"period"`
	ExpireTime  string   `json:"expire_time"`
}

// cachedToken is a live Vault token and when it stops being one.
type cachedToken struct {
	token string
	// expires is zero for a token that does not expire — a root token, or one
	// created with no TTL. Nothing is renewed on its behalf.
	expires   time.Time
	renewable bool
}

// tokenCache holds one token per distinct set of Vault credentials.
//
// The alternative — logging in per request — is what makes a gateway hostile to
// the Vault it depends on: a fleet renewal of two thousand certificates would
// create two thousand tokens, each with its own lease, and Vault's token store
// grows until somebody notices the storage.
type tokenCache struct {
	mu      sync.Mutex
	entries map[string]*cachedToken
}

func newTokenCache() *tokenCache {
	return &tokenCache{entries: map[string]*cachedToken{}}
}

func (c *tokenCache) get(identity string) (*cachedToken, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[identity]
	return entry, ok
}

func (c *tokenCache) put(identity string, entry *cachedToken) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[identity] = entry
}

func (c *tokenCache) forget(identity string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, identity)
}

// token returns a usable Vault token for this configuration.
//
// The second value reports whether it was just obtained, which is how the
// caller knows a 403 cannot be explained by a stale cache entry.
func (p *Provider) token(ctx context.Context, cfg *Config) (token string, fresh bool, err error) {
	if cfg.AuthMethod == AuthToken {
		if strings.TrimSpace(cfg.Token) == "" {
			return "", false, fmt.Errorf("no Vault token in this configuration")
		}
		return cfg.Token, true, nil
	}

	identity := cfg.identity()
	if entry, ok := p.tokens.get(identity); ok {
		switch {
		case entry.expires.IsZero(), time.Now().Before(renewAt(entry.expires)):
			return entry.token, false, nil
		case entry.renewable:
			if renewed, err := p.renewSelf(ctx, cfg, entry); err == nil {
				p.tokens.put(identity, renewed)
				return renewed.token, false, nil
			}
			// Renewal can fail because the token hit its maximum TTL, which is
			// ordinary and expected — a fresh login is the answer, not an
			// error. Falling through is the whole handling.
		}
	}

	entry, err := p.login(ctx, cfg)
	if err != nil {
		return "", false, err
	}
	p.tokens.put(identity, entry)
	return entry.token, true, nil
}

// renewAt is when a token should be refreshed rather than used.
//
// Early enough that a renewal has room to fail and be retried as a login,
// late enough that a short-lived token is not renewed on every call.
func renewAt(expires time.Time) time.Time {
	margin := time.Minute
	if remaining := time.Until(expires); remaining > 10*time.Minute {
		margin = remaining / 10
	}
	return expires.Add(-margin)
}

// login obtains a new token by the configured method.
func (p *Provider) login(ctx context.Context, cfg *Config) (*cachedToken, error) {
	switch cfg.AuthMethod {
	case AuthAppRole:
		return p.loginAppRole(ctx, cfg)
	case AuthKubernetes:
		return p.loginKubernetes(ctx, cfg)
	default:
		return nil, fmt.Errorf("cannot log in with auth_method %q", cfg.AuthMethod)
	}
}

func (p *Provider) loginAppRole(ctx context.Context, cfg *Config) (*cachedToken, error) {
	var auth authInfo
	_, err := p.request(ctx, cfg, http.MethodPost,
		"/v1/auth/"+cfg.AppRoleMount+"/login", "",
		map[string]any{"role_id": cfg.RoleID, "secret_id": cfg.SecretID}, &auth)
	if err != nil {
		return nil, describeLoginFailure(err, "approle", cfg)
	}
	return fromAuth(&auth, "approle")
}

func (p *Provider) loginKubernetes(ctx context.Context, cfg *Config) (*cachedToken, error) {
	// Read at every login rather than once at startup. The kubelet rotates a
	// projected service account token roughly hourly, so a copy taken when the
	// process started stops working while the file beside it is perfectly
	// valid.
	jwt, err := os.ReadFile(cfg.KubernetesJWTPath)
	if err != nil {
		return nil, fmt.Errorf(
			"could not read the service account token at %s: %w. Kubernetes auth expects this gateway to be running in a pod with a projected token", cfg.KubernetesJWTPath, err)
	}

	var auth authInfo
	_, err = p.request(ctx, cfg, http.MethodPost,
		"/v1/auth/"+cfg.KubernetesMount+"/login", "",
		map[string]any{"role": cfg.KubernetesRole, "jwt": strings.TrimSpace(string(jwt))}, &auth)
	if err != nil {
		return nil, describeLoginFailure(err, "kubernetes", cfg)
	}
	return fromAuth(&auth, "kubernetes")
}

// renewSelf extends the life of a token that is nearing expiry.
func (p *Provider) renewSelf(ctx context.Context, cfg *Config, entry *cachedToken) (*cachedToken, error) {
	var auth authInfo
	_, err := p.request(ctx, cfg, http.MethodPost,
		"/v1/auth/token/renew-self", entry.token, map[string]any{}, &auth)
	if err != nil {
		return nil, err
	}
	renewed, err := fromAuth(&auth, "renew-self")
	if err != nil {
		return nil, err
	}
	if renewed.token == "" {
		// renew-self echoes the same token; an empty one means Vault answered
		// in a shape this gateway does not understand rather than that the
		// token is gone.
		renewed.token = entry.token
	}
	return renewed, nil
}

// lookupSelf reports what a token is, used at configuration time to say
// out loud when a credential will outlive its usefulness.
func (p *Provider) lookupSelf(ctx context.Context, cfg *Config, token string) (*tokenInfo, error) {
	var info tokenInfo
	if _, err := p.request(ctx, cfg, http.MethodGet, "/v1/auth/token/lookup-self", token, nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func fromAuth(auth *authInfo, method string) (*cachedToken, error) {
	if auth.ClientToken == "" && method != "renew-self" {
		return nil, fmt.Errorf("the %s login succeeded and returned no token", method)
	}
	entry := &cachedToken{token: auth.ClientToken, renewable: auth.Renewable}
	if auth.LeaseDuration > 0 {
		entry.expires = time.Now().Add(time.Duration(auth.LeaseDuration) * time.Second)
	}
	return entry, nil
}

// describeLoginFailure turns Vault's login refusals into the sentence that
// names the actual cause. All three arrive as a bare 400 "invalid role or
// secret id", which is true and does not say which.
func describeLoginFailure(err error, method string, cfg *Config) error {
	ve, ok := asAPIError(err)
	if !ok {
		return fmt.Errorf("%s login to Vault failed: %w", method, err)
	}

	switch {
	case ve.Status == http.StatusBadRequest && strings.Contains(ve.message(), "secret id"):
		return fmt.Errorf(
			"the AppRole login was refused: %s. A SecretID that has reached its use limit or its TTL fails exactly like a wrong one — check secret_id_num_uses and secret_id_ttl on the role", strings.Join(ve.Messages, "; "))
	case ve.Status == http.StatusNotFound || strings.Contains(ve.message(), "unsupported path"):
		mount := cfg.AppRoleMount
		if method == "kubernetes" {
			mount = cfg.KubernetesMount
		}
		return fmt.Errorf(
			"Vault has no %s auth method mounted at %q. Check the mount path — it is the path, not the type, that has to match", method, mount)
	default:
		return fmt.Errorf("%s login to Vault failed: %w", method, err)
	}
}
