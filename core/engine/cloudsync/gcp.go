package cloudsync

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// GCP reads SSL certificates from Google Cloud load balancing.
//
// The distinction that matters is in a single field. A `MANAGED` certificate is
// renewed by Google. A `SELF_MANAGED` one was uploaded, once, by somebody who
// may no longer work there, and is renewed by nobody. Both sit in the same
// list, both show as ACTIVE, and only one of them is somebody's problem.
type GCP struct {
	projectID string
	client    *http.Client
	now       func() time.Time

	// Service account key, or the metadata server when running on GCP — which
	// is the shape worth deploying, because no key material exists to leak.
	clientEmail   string
	privateKey    *rsa.PrivateKey
	tokenURI      string
	useMetadata   bool
	metadataURL   string
	computeAPIURL string

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

const gcpScope = "https://www.googleapis.com/auth/cloud-platform.read-only"

func newGCP(config map[string]any) (*GCP, error) {
	g := &GCP{
		projectID:     configString(config, "project_id"),
		client:        defaultClient(),
		now:           time.Now,
		tokenURI:      "https://oauth2.googleapis.com/token",
		useMetadata:   configBool(config, "use_metadata_server"),
		metadataURL:   "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		computeAPIURL: "https://compute.googleapis.com/compute/v1",
	}
	if override := configString(config, "compute_api_url"); override != "" {
		g.computeAPIURL = strings.TrimRight(override, "/")
	}
	if override := configString(config, "token_uri"); override != "" {
		g.tokenURI = override
	}
	if override := configString(config, "metadata_url"); override != "" {
		g.metadataURL = override
	}

	if g.projectID == "" {
		return nil, missingField("gcp", "project_id", "the project whose load balancer certificates should be read")
	}

	if !g.useMetadata {
		raw := configString(config, "service_account_json")
		if raw == "" {
			return nil, missingField("gcp", "service_account_json",
				"the JSON key for a service account with compute.sslCertificates.list — or set use_metadata_server when CertPilot runs on GCP")
		}
		var key struct {
			ClientEmail string `json:"client_email"`
			PrivateKey  string `json:"private_key"`
			TokenURI    string `json:"token_uri"`
			ProjectID   string `json:"project_id"`
		}
		if err := json.Unmarshal([]byte(raw), &key); err != nil {
			return nil, fmt.Errorf("service_account_json is not the JSON key file Google issues: %w", err)
		}
		if key.ClientEmail == "" || key.PrivateKey == "" {
			return nil, fmt.Errorf("service_account_json has no client_email or private_key; paste the whole key file")
		}
		parsed, err := parseRSAPrivateKey(key.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("the private key in service_account_json could not be read: %w", err)
		}
		g.clientEmail, g.privateKey = key.ClientEmail, parsed
		if key.TokenURI != "" {
			g.tokenURI = key.TokenURI
		}
	}
	return g, nil
}

// Type identifies the provider.
func (g *GCP) Type() string { return "gcp" }

// Describe names the project.
func (g *GCP) Describe() string { return "GCP project " + g.projectID }

// Scopes says what will be enumerated — and, just as importantly, what will not.
func (g *GCP) Scopes() []string {
	return []string{
		fmt.Sprintf("compute sslCertificates in project %s, global and every region", g.projectID),
		"target HTTPS and SSL proxies, to see which certificates are actually in front of something",
		"NOT Certificate Manager (certificatemanager.googleapis.com): certificates held only there are not visible to this connection",
	}
}

type gcpSSLCertificate struct {
	Name              string `json:"name"`
	Description       string `json:"description"`
	Certificate       string `json:"certificate"`
	SelfLink          string `json:"selfLink"`
	Type              string `json:"type"`
	Region            string `json:"region"`
	ExpireTime        string `json:"expireTime"`
	CreationTimestamp string `json:"creationTimestamp"`
	Managed           struct {
		Status  string            `json:"status"`
		Domains map[string]string `json:"domainStatus"`
	} `json:"managed"`
}

// Inventory lists every load balancer certificate in the project.
func (g *GCP) Inventory(ctx context.Context) ([]Asset, error) {
	certificates, err := g.listSSLCertificates(ctx)
	if err != nil {
		return nil, err
	}

	// Which certificates are in front of something. A failure leaves Attached
	// nil rather than false: "no proxy uses this" and "we could not find out"
	// are different answers and only one of them is a finding.
	used, usedKnown := g.proxyReferences(ctx)

	assets := make([]Asset, 0, len(certificates))
	for _, cert := range certificates {
		location := "global"
		if cert.Region != "" {
			location = shortName(cert.Region)
		}

		asset := Asset{
			ResourceID:     cert.SelfLink,
			Name:           cert.Name,
			Location:       location,
			CertificatePEM: cert.Certificate,
			RenewalMode:    cert.Type,
		}
		switch strings.ToUpper(cert.Type) {
		case "MANAGED":
			yes := true
			asset.WillRenew = &yes
			if cert.Managed.Status != "" {
				asset.RenewalMode = "MANAGED (" + cert.Managed.Status + ")"
			}
		case "SELF_MANAGED", "":
			// The default is the dangerous one. A certificate uploaded through
			// the console with no type set behaves as self-managed, and Google
			// will not touch it again.
			no := false
			asset.WillRenew = &no
			asset.RenewalMode = "SELF_MANAGED"
		}

		if usedKnown {
			refs := used[cert.SelfLink]
			attached := len(refs) > 0
			asset.Attached = &attached
			asset.AttachedTo = refs
		}

		assets = append(assets, asset)
	}
	return assets, nil
}

// gcpAggregatedList is the shape every compute aggregated listing takes: a map
// of scope name to a per-scope payload.
type gcpAggregatedList struct {
	Items         map[string]json.RawMessage `json:"items"`
	NextPageToken string                     `json:"nextPageToken"`
}

func (g *GCP) listSSLCertificates(ctx context.Context) ([]gcpSSLCertificate, error) {
	out := []gcpSSLCertificate{}
	err := g.eachAggregatedPage(ctx, "sslCertificates", func(scope json.RawMessage) error {
		var payload struct {
			SSLCertificates []gcpSSLCertificate `json:"sslCertificates"`
		}
		if err := json.Unmarshal(scope, &payload); err != nil {
			return err
		}
		out = append(out, payload.SSLCertificates...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// proxyReferences maps certificate self-links to the proxies serving them.
func (g *GCP) proxyReferences(ctx context.Context) (map[string][]string, bool) {
	refs := map[string][]string{}

	collect := func(resource, field string) error {
		return g.eachAggregatedPage(ctx, resource, func(scope json.RawMessage) error {
			var payload map[string][]struct {
				Name            string   `json:"name"`
				SSLCertificates []string `json:"sslCertificates"`
			}
			if err := json.Unmarshal(scope, &payload); err != nil {
				return err
			}
			for _, proxy := range payload[field] {
				for _, link := range proxy.SSLCertificates {
					refs[link] = append(refs[link], resource+" "+proxy.Name)
				}
			}
			return nil
		})
	}

	if err := collect("targetHttpsProxies", "targetHttpsProxies"); err != nil {
		return nil, false
	}
	if err := collect("targetSslProxies", "targetSslProxies"); err != nil {
		return nil, false
	}
	return refs, true
}

func (g *GCP) eachAggregatedPage(ctx context.Context, resource string, fn func(json.RawMessage) error) error {
	pageToken := ""
	for pages := 0; pages < 50; pages++ {
		query := url.Values{"maxResults": {"500"}, "returnPartialSuccess": {"true"}}
		if pageToken != "" {
			query.Set("pageToken", pageToken)
		}
		endpoint := fmt.Sprintf("%s/projects/%s/aggregated/%s?%s",
			g.computeAPIURL, url.PathEscape(g.projectID), resource, query.Encode())

		var page gcpAggregatedList
		if err := g.get(ctx, endpoint, &page); err != nil {
			return err
		}
		for _, scope := range page.Items {
			if err := fn(scope); err != nil {
				return err
			}
		}
		pageToken = page.NextPageToken
		if pageToken == "" {
			return nil
		}
	}
	return nil
}

func (g *GCP) get(ctx context.Context, endpoint string, out any) error {
	token, err := g.accessToken(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	return doJSON(g.client, req, out)
}

func (g *GCP) accessToken(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.token != "" && g.now().Add(time.Minute).Before(g.tokenExpiry) {
		return g.token, nil
	}

	var (
		token   string
		expires time.Time
		err     error
	)
	if g.useMetadata {
		token, expires, err = g.tokenFromMetadata(ctx)
	} else {
		token, expires, err = g.tokenFromServiceAccount(ctx)
	}
	if err != nil {
		return "", err
	}

	g.token, g.tokenExpiry = token, expires
	return token, nil
}

// tokenFromServiceAccount performs the JWT bearer exchange: sign a short-lived
// assertion with the service account key, trade it for an access token.
func (g *GCP) tokenFromServiceAccount(ctx context.Context) (string, time.Time, error) {
	now := g.now().UTC()
	claims := map[string]any{
		"iss":   g.clientEmail,
		"scope": gcpScope,
		"aud":   g.tokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	assertion, err := signRS256JWT(claims, g.privateKey)
	if err != nil {
		return "", time.Time{}, err
	}

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := doJSON(g.client, req, &resp); err != nil {
		return "", time.Time{}, fmt.Errorf("Google would not issue a token for this service account: %w", err)
	}
	if resp.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("Google answered without a token")
	}
	return resp.AccessToken, now.Add(time.Duration(resp.ExpiresIn) * time.Second), nil
}

func (g *GCP) tokenFromMetadata(ctx context.Context) (string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.metadataURL, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	var resp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := doJSON(g.client, req, &resp); err != nil {
		return "", time.Time{}, fmt.Errorf("the metadata server would not issue a token; is a service account attached to this instance? %w", err)
	}
	if resp.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("the metadata server answered without a token")
	}
	return resp.AccessToken, g.now().Add(time.Duration(resp.ExpiresIn) * time.Second), nil
}

// signRS256JWT builds and signs a JWT assertion.
func signRS256JWT(claims map[string]any, key *rsa.PrivateKey) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(header) + "." + enc.EncodeToString(body)

	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + enc.EncodeToString(signature), nil
}

// parseRSAPrivateKey reads the PEM key out of a service account file. Google
// issues PKCS#8; PKCS#1 is accepted too, because keys get reformatted on their
// way through configuration management.
func parseRSAPrivateKey(pemKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("not a PEM block")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("the key is not RSA; Google service account keys are")
		}
		return rsaKey, nil
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// shortName reduces a GCP resource URL to its last element, so a region reads
// as "us-central1" rather than as a full self-link.
func shortName(link string) string {
	if idx := strings.LastIndex(link, "/"); idx >= 0 {
		return link[idx+1:]
	}
	return link
}
