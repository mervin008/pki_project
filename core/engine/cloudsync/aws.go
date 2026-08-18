package cloudsync

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ACM reads AWS Certificate Manager.
//
// The reason this provider exists in a certificate lifecycle tool, rather than
// "because AWS is popular": **ACM does not renew everything in it, and the
// belief that it does is close to universal.**
//
// AWS renews a certificate it issued, for a domain it can still validate. It
// never renews one that was imported — a certificate from an internal CA, or
// bought from a commercial one, uploaded to put in front of a load balancer.
// AWS reports this in `RenewalEligibility`, a field beside `Status: ISSUED` on
// a green console page, and the two certificates are otherwise indistinguishable
// until the imported one expires.
type ACM struct {
	region string
	client *http.Client

	// static credentials, when configured directly.
	static awsCredentials
	// web identity, for EKS: a token file the cluster rotates, exchanged for
	// short-lived credentials. The shape a real organisation deploys, because
	// it means no long-lived key exists to be leaked.
	roleARN        string
	tokenFile      string
	sessionName    string
	now            func() time.Time
	stsEndpointFmt string
	acmEndpointFmt string

	mu     sync.Mutex
	cached awsCredentials
}

func newACM(config map[string]any) (*ACM, error) {
	a := &ACM{
		region:         configString(config, "region"),
		client:         defaultClient(),
		now:            time.Now,
		stsEndpointFmt: "https://sts.%s.amazonaws.com/",
		acmEndpointFmt: "https://acm.%s.amazonaws.com/",
	}
	if a.region == "" {
		return nil, missingField("aws_acm", "region", "ACM is regional, e.g. eu-west-1; add one connection per region you use")
	}

	a.static = awsCredentials{
		AccessKeyID:     configString(config, "access_key_id"),
		SecretAccessKey: configString(config, "secret_access_key"),
		SessionToken:    configString(config, "session_token"),
	}
	a.roleARN = configString(config, "role_arn")
	a.tokenFile = configString(config, "web_identity_token_file")
	a.sessionName = configString(config, "role_session_name")
	if a.sessionName == "" {
		a.sessionName = "certpilot-discovery"
	}

	if endpoint := configString(config, "endpoint_url"); endpoint != "" {
		// A test server, or a VPC endpoint. Taken verbatim: whoever set it
		// meant it.
		a.acmEndpointFmt = strings.TrimRight(endpoint, "/") + "/"
		a.stsEndpointFmt = a.acmEndpointFmt
	}

	switch {
	case a.static.AccessKeyID != "" && a.static.SecretAccessKey != "":
	case a.roleARN != "" && a.tokenFile != "":
	default:
		return nil, fmt.Errorf(
			"an aws_acm connection needs either access_key_id and secret_access_key, " +
				"or role_arn and web_identity_token_file for a role assumed from a Kubernetes service account. " +
				"Read-only is enough: acm:ListCertificates and acm:GetCertificate")
	}
	return a, nil
}

// Type identifies the provider.
func (a *ACM) Type() string { return "aws_acm" }

// Describe names the account being read.
func (a *ACM) Describe() string {
	if a.roleARN != "" {
		return fmt.Sprintf("ACM in %s as %s", a.region, a.roleARN)
	}
	return fmt.Sprintf("ACM in %s", a.region)
}

// Scopes says what will be enumerated.
//
// Naming the region is not a formality. ACM is regional, and a certificate in
// us-east-1 is invisible to a connection pointed at eu-west-1 — which is
// exactly the kind of gap that reads as a clean account.
func (a *ACM) Scopes() []string {
	return []string{
		fmt.Sprintf("AWS Certificate Manager in %s only — certificates in other regions are not visible to this connection", a.region),
		"each certificate's PEM body, to match it against inventory by fingerprint",
	}
}

// acmSummary is the part of a CertificateSummary this needs.
type acmSummary struct {
	CertificateArn                string   `json:"CertificateArn"`
	DomainName                    string   `json:"DomainName"`
	SubjectAlternativeNameSummary []string `json:"SubjectAlternativeNameSummary"`
	Status                        string   `json:"Status"`
	Type                          string   `json:"Type"`
	KeyAlgorithm                  string   `json:"KeyAlgorithm"`
	InUse                         *bool    `json:"InUse"`
	RenewalEligibility            string   `json:"RenewalEligibility"`
	NotAfter                      float64  `json:"NotAfter"`
}

// Inventory lists every certificate in the region.
func (a *ACM) Inventory(ctx context.Context) ([]Asset, error) {
	summaries, err := a.listCertificates(ctx)
	if err != nil {
		return nil, err
	}

	assets := make([]Asset, 0, len(summaries))
	for _, s := range summaries {
		asset := Asset{
			ResourceID: s.CertificateArn,
			Name:       s.DomainName,
			Location:   a.region,
		}

		// The verdict AWS itself publishes, kept in AWS's own vocabulary so it
		// can be found again in the console.
		asset.RenewalMode = s.RenewalEligibility
		if asset.RenewalMode == "" {
			asset.RenewalMode = s.Type
		}
		switch strings.ToUpper(s.RenewalEligibility) {
		case "ELIGIBLE":
			yes := true
			asset.WillRenew = &yes
		case "INELIGIBLE":
			no := false
			asset.WillRenew = &no
		}
		if strings.EqualFold(s.Type, "IMPORTED") {
			// Belt and braces. An imported certificate is never renewed by AWS
			// whatever else the summary says, and this is the single most
			// consequential fact this provider reports.
			no := false
			asset.WillRenew = &no
			asset.RenewalMode = "IMPORTED"
		}

		if s.InUse != nil {
			inUse := *s.InUse
			asset.Attached = &inUse
		}
		asset.Disabled = strings.EqualFold(s.Status, "REVOKED") || strings.EqualFold(s.Status, "FAILED")

		// The body, so the fingerprint can decide the verdict. A certificate
		// that is still pending validation has no body yet; that is not an
		// error worth failing the whole sync over, so the record is kept with
		// what the summary said.
		if pem, err := a.getCertificate(ctx, s.CertificateArn); err == nil {
			asset.CertificatePEM = pem
		}

		assets = append(assets, asset)
	}
	return assets, nil
}

func (a *ACM) listCertificates(ctx context.Context) ([]acmSummary, error) {
	out := []acmSummary{}
	var nextToken string

	for {
		body := map[string]any{"MaxItems": 100}
		if nextToken != "" {
			body["NextToken"] = nextToken
		}

		var page struct {
			CertificateSummaryList []acmSummary `json:"CertificateSummaryList"`
			NextToken              string       `json:"NextToken"`
		}
		if err := a.call(ctx, "CertificateManager.ListCertificates", body, &page); err != nil {
			return nil, err
		}
		out = append(out, page.CertificateSummaryList...)

		nextToken = page.NextToken
		if nextToken == "" {
			break
		}
		if len(out) > 5000 {
			// A bound rather than a promise. Beyond this the sync would be
			// reporting an estate nobody reads as a list anyway, and an
			// unbounded loop against a paging API is how a sync becomes an
			// outage.
			return out, nil
		}
	}
	return out, nil
}

func (a *ACM) getCertificate(ctx context.Context, arn string) (string, error) {
	var resp struct {
		Certificate      string `json:"Certificate"`
		CertificateChain string `json:"CertificateChain"`
	}
	if err := a.call(ctx, "CertificateManager.GetCertificate",
		map[string]any{"CertificateArn": arn}, &resp); err != nil {
		return "", err
	}
	return resp.Certificate, nil
}

// call performs one signed AWS JSON 1.1 request.
func (a *ACM) call(ctx context.Context, target string, body any, out any) error {
	creds, err := a.credentials(ctx)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	endpoint := a.acmEndpointFmt
	if strings.Contains(endpoint, "%s") {
		endpoint = fmt.Sprintf(endpoint, a.region)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)

	signV4(req, payload, creds, a.region, "acm", a.now())
	return doJSON(a.client, req, out)
}

// credentials returns usable credentials, exchanging a web identity token when
// that is how this connection is configured.
func (a *ACM) credentials(ctx context.Context) (awsCredentials, error) {
	if a.static.AccessKeyID != "" {
		return a.static, nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cached.AccessKeyID != "" && !a.cached.expired(a.now()) {
		return a.cached, nil
	}

	creds, err := a.assumeRoleWithWebIdentity(ctx)
	if err != nil {
		return awsCredentials{}, err
	}
	a.cached = creds
	return creds, nil
}

// stsAssumeRoleResponse is the XML STS returns.
type stsAssumeRoleResponse struct {
	XMLName xml.Name `xml:"AssumeRoleWithWebIdentityResponse"`
	Result  struct {
		Credentials struct {
			AccessKeyID     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
}

// assumeRoleWithWebIdentity exchanges the projected service account token for
// short-lived AWS credentials.
//
// The token file is read on every exchange rather than cached. Kubernetes
// rotates projected tokens — roughly hourly — and a copy taken at startup stops
// working within the hour, which then reads as AWS refusing the connection
// rather than as this process holding a stale file.
func (a *ACM) assumeRoleWithWebIdentity(ctx context.Context) (awsCredentials, error) {
	raw, err := os.ReadFile(a.tokenFile)
	if err != nil {
		return awsCredentials{}, fmt.Errorf("the web identity token at %s could not be read: %w", a.tokenFile, err)
	}

	form := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"Version":          {"2011-06-15"},
		"RoleArn":          {a.roleARN},
		"RoleSessionName":  {a.sessionName},
		"WebIdentityToken": {strings.TrimSpace(string(raw))},
	}

	endpoint := a.stsEndpointFmt
	if strings.Contains(endpoint, "%s") {
		endpoint = fmt.Sprintf(endpoint, a.region)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return awsCredentials{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Unsigned by design: proving who you are is what the web identity token
	// is for, and there are no credentials yet with which to sign.
	resp, err := a.client.Do(req)
	if err != nil {
		return awsCredentials{}, fmt.Errorf("exchanging the web identity token with STS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return awsCredentials{}, fmt.Errorf("STS refused the web identity token (%d): %s",
			resp.StatusCode, readableBody(resp.Body))
	}

	var parsed stsAssumeRoleResponse
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return awsCredentials{}, fmt.Errorf("STS returned something that is not the expected XML: %w", err)
	}

	creds := awsCredentials{
		AccessKeyID:     parsed.Result.Credentials.AccessKeyID,
		SecretAccessKey: parsed.Result.Credentials.SecretAccessKey,
		SessionToken:    parsed.Result.Credentials.SessionToken,
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return awsCredentials{}, fmt.Errorf("STS answered without credentials; the role or the token audience is probably wrong")
	}
	if t, err := time.Parse(time.RFC3339, parsed.Result.Credentials.Expiration); err == nil {
		creds.Expires = t
	}
	return creds, nil
}
