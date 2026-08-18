package cloudsync

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// KeyVault reads Azure Key Vault certificates.
//
// The renewal trap here is subtler than ACM's, and it lives in one word. Every
// Key Vault certificate has a policy, and every policy has an issuer name. When
// that name is `Unknown`, the certificate was imported — somebody uploaded a
// PFX — and Key Vault has no issuer to go back to, so it cannot renew it. It
// will still happily hold a lifetime action against it, which on the portal
// looks like automation, and which can only ever send an email.
type KeyVault struct {
	vaultURL string
	client   *http.Client
	now      func() time.Time

	tenantID     string
	clientID     string
	clientSecret string
	// managedIdentity reads a token from the instance metadata service instead
	// of holding a client secret at all — the shape worth deploying, because
	// there is then no secret to leak.
	managedIdentity bool
	loginURL        string
	imdsURL         string

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

// keyVaultAPIVersion is pinned. An unpinned version is a sync whose behaviour
// changes without anybody deploying anything.
const keyVaultAPIVersion = "7.4"

func newKeyVault(config map[string]any) (*KeyVault, error) {
	k := &KeyVault{
		vaultURL:        strings.TrimRight(configString(config, "vault_url"), "/"),
		client:          defaultClient(),
		now:             time.Now,
		tenantID:        configString(config, "tenant_id"),
		clientID:        configString(config, "client_id"),
		clientSecret:    configString(config, "client_secret"),
		managedIdentity: configBool(config, "managed_identity"),
		loginURL:        "https://login.microsoftonline.com",
		imdsURL:         "http://169.254.169.254/metadata/identity/oauth2/token",
	}
	if override := configString(config, "login_url"); override != "" {
		k.loginURL = strings.TrimRight(override, "/")
	}
	if override := configString(config, "imds_url"); override != "" {
		k.imdsURL = override
	}

	if k.vaultURL == "" {
		return nil, missingField("azure_key_vault", "vault_url",
			"the vault's DNS name, e.g. https://contoso.vault.azure.net")
	}
	if !strings.HasPrefix(k.vaultURL, "http") {
		return nil, fmt.Errorf("vault_url must be a URL, e.g. https://contoso.vault.azure.net")
	}

	if !k.managedIdentity {
		switch {
		case k.tenantID == "":
			return nil, missingField("azure_key_vault", "tenant_id",
				"the directory the app registration lives in — or set managed_identity when CertPilot runs in Azure")
		case k.clientID == "":
			return nil, missingField("azure_key_vault", "client_id", "the app registration's application id")
		case k.clientSecret == "":
			return nil, missingField("azure_key_vault", "client_secret",
				"a client secret for that app registration; the certificates/get and certificates/list permissions are enough")
		}
	}
	return k, nil
}

// Type identifies the provider.
func (k *KeyVault) Type() string { return "azure_key_vault" }

// Describe names the vault.
func (k *KeyVault) Describe() string { return k.vaultURL }

// Scopes says what will be enumerated.
func (k *KeyVault) Scopes() []string {
	return []string{
		fmt.Sprintf("certificates in %s only — one connection reads one vault", k.vaultURL),
		"each certificate's issuance policy, to see whether the vault can renew it at all",
		"nothing about deployment: a vault does not know what is serving its certificates",
	}
}

type keyVaultListItem struct {
	ID         string            `json:"id"`
	X5T        string            `json:"x5t"`
	Tags       map[string]string `json:"tags"`
	Attributes struct {
		Enabled bool  `json:"enabled"`
		NotedAt int64 `json:"created"`
		Expires int64 `json:"exp"`
	} `json:"attributes"`
}

type keyVaultCertificate struct {
	ID         string `json:"id"`
	CER        string `json:"cer"`
	Attributes struct {
		Enabled bool `json:"enabled"`
	} `json:"attributes"`
	Policy struct {
		Issuer struct {
			Name string `json:"name"`
		} `json:"issuer"`
		LifetimeActions []struct {
			Action struct {
				ActionType string `json:"action_type"`
			} `json:"action"`
		} `json:"lifetime_actions"`
	} `json:"policy"`
}

// Inventory lists every certificate in the vault, with its policy.
func (k *KeyVault) Inventory(ctx context.Context) ([]Asset, error) {
	items, err := k.list(ctx)
	if err != nil {
		return nil, err
	}

	assets := make([]Asset, 0, len(items))
	for _, item := range items {
		name := certificateNameFromID(item.ID)
		if name == "" {
			continue
		}

		asset := Asset{
			ResourceID: item.ID,
			Name:       name,
			Location:   k.vaultURL,
			// A vault has no notion of what is serving its certificates, so
			// Attached stays nil. That is the honest answer, and it is not the
			// same as "nothing is using this".
		}

		detail, err := k.get(ctx, name)
		if err != nil {
			// One certificate that could not be read does not invalidate the
			// rest of the vault, but the gap is recorded on the record itself
			// rather than dropped.
			asset.RenewalMode = "unknown: " + err.Error()
			assets = append(assets, asset)
			continue
		}

		asset.CertificatePEM = derToPEM(detail.CER)
		asset.Disabled = !detail.Attributes.Enabled

		issuer := strings.TrimSpace(detail.Policy.Issuer.Name)
		autoRenew := false
		for _, action := range detail.Policy.LifetimeActions {
			if strings.EqualFold(action.Action.ActionType, "AutoRenew") {
				autoRenew = true
			}
		}

		switch {
		case strings.EqualFold(issuer, "Unknown"):
			// The whole point of this provider. An imported certificate has no
			// issuer to go back to, so the vault cannot renew it whatever its
			// policy appears to say.
			no := false
			asset.WillRenew = &no
			asset.RenewalMode = "imported (policy issuer: Unknown)"
		case autoRenew:
			yes := true
			asset.WillRenew = &yes
			asset.RenewalMode = fmt.Sprintf("AutoRenew via issuer %s", issuerOrUnnamed(issuer))
		default:
			no := false
			asset.WillRenew = &no
			asset.RenewalMode = fmt.Sprintf("issuer %s, no AutoRenew action in the policy", issuerOrUnnamed(issuer))
		}

		assets = append(assets, asset)
	}
	return assets, nil
}

func (k *KeyVault) list(ctx context.Context) ([]keyVaultListItem, error) {
	next := fmt.Sprintf("%s/certificates?api-version=%s&maxresults=25", k.vaultURL, keyVaultAPIVersion)
	out := []keyVaultListItem{}

	for next != "" {
		var page struct {
			Value    []keyVaultListItem `json:"value"`
			NextLink string             `json:"nextLink"`
		}
		if err := k.get2(ctx, next, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
		next = page.NextLink
		if len(out) > 5000 {
			return out, nil
		}
	}
	return out, nil
}

func (k *KeyVault) get(ctx context.Context, name string) (*keyVaultCertificate, error) {
	endpoint := fmt.Sprintf("%s/certificates/%s?api-version=%s",
		k.vaultURL, url.PathEscape(name), keyVaultAPIVersion)
	var out keyVaultCertificate
	if err := k.get2(ctx, endpoint, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (k *KeyVault) get2(ctx context.Context, endpoint string, out any) error {
	token, err := k.accessToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	return doJSON(k.client, req, out)
}

// accessToken returns a bearer token for the vault, minting a new one when the
// held one is within a minute of expiry.
func (k *KeyVault) accessToken(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.token != "" && k.now().Add(time.Minute).Before(k.tokenExpiry) {
		return k.token, nil
	}

	var (
		token   string
		expires time.Time
		err     error
	)
	if k.managedIdentity {
		token, expires, err = k.tokenFromIMDS(ctx)
	} else {
		token, expires, err = k.tokenFromClientSecret(ctx)
	}
	if err != nil {
		return "", err
	}

	k.token, k.tokenExpiry = token, expires
	return token, nil
}

func (k *KeyVault) tokenFromClientSecret(ctx context.Context) (string, time.Time, error) {
	form := url.Values{
		"client_id":     {k.clientID},
		"client_secret": {k.clientSecret},
		"grant_type":    {"client_credentials"},
		"scope":         {"https://vault.azure.net/.default"},
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", k.loginURL, url.PathEscape(k.tenantID))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := doJSON(k.client, req, &resp); err != nil {
		return "", time.Time{}, fmt.Errorf("Entra ID would not issue a token for this app registration: %w", err)
	}
	if resp.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("Entra ID answered without a token")
	}
	return resp.AccessToken, k.now().Add(time.Duration(resp.ExpiresIn) * time.Second), nil
}

func (k *KeyVault) tokenFromIMDS(ctx context.Context) (string, time.Time, error) {
	endpoint := k.imdsURL + "?api-version=2018-02-01&resource=" + url.QueryEscape("https://vault.azure.net")
	if k.clientID != "" {
		// A host with several assigned identities needs to be told which one.
		endpoint += "&client_id=" + url.QueryEscape(k.clientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Metadata", "true")

	var resp struct {
		AccessToken string `json:"access_token"`
		ExpiresOn   string `json:"expires_on"`
	}
	if err := doJSON(k.client, req, &resp); err != nil {
		return "", time.Time{}, fmt.Errorf("the instance metadata service would not issue a token; is a managed identity assigned to this host? %w", err)
	}
	if resp.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("the instance metadata service answered without a token")
	}

	// expires_on is a unix timestamp as a string. An unparseable one falls back
	// to a short life rather than to forever: re-minting a token needlessly
	// costs one request, and holding a dead one costs the sync.
	expires := k.now().Add(10 * time.Minute)
	if resp.ExpiresOn != "" {
		var epoch int64
		if _, err := fmt.Sscanf(resp.ExpiresOn, "%d", &epoch); err == nil && epoch > 0 {
			expires = time.Unix(epoch, 0)
		}
	}
	return resp.AccessToken, expires, nil
}

// certificateNameFromID pulls the certificate name out of a vault id such as
// https://contoso.vault.azure.net/certificates/web/<version>.
func certificateNameFromID(id string) string {
	parts := strings.Split(strings.TrimRight(id, "/"), "/")
	for i, part := range parts {
		if part == "certificates" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// derToPEM wraps a base64 DER certificate, which is how Key Vault returns one.
func derToPEM(b64 string) string {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(der) == 0 {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func issuerOrUnnamed(issuer string) string {
	if issuer == "" {
		return "(none set)"
	}
	return issuer
}
