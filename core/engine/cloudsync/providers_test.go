package cloudsync

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testCertPEM builds a certificate the providers can hand back, so the parsing
// and fingerprinting path is exercised on real DER rather than on a string.
func testCertPEM(t *testing.T, commonName string, notAfter time.Time) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func assetByID(assets []Asset, id string) *Asset {
	for i := range assets {
		if assets[i].ResourceID == id {
			return &assets[i]
		}
	}
	return nil
}

// ── Kubernetes ──────────────────────────────────────────────

// The finding this provider exists for: cert-manager renews the secrets it
// owns, and nothing else in the cluster. A hand-made secret looks identical
// until the day it expires.
func TestKubernetesSeparatesCertManagerFromHandMadeSecrets(t *testing.T) {
	certPEM := testCertPEM(t, "shop.internal", time.Now().Add(60*24*time.Hour))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Unauthorized"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/secrets"):
			if got := r.URL.Query().Get("fieldSelector"); got != "type=kubernetes.io/tls" {
				t.Errorf("fieldSelector = %q; the whole cluster's secrets must not be pulled over the wire", got)
			}
			_, _ = w.Write([]byte(`{"items":[
				{"metadata":{"name":"managed-tls","namespace":"shop",
				  "annotations":{"cert-manager.io/certificate-name":"shop-cert"}},
				 "type":"kubernetes.io/tls","data":{"tls.crt":"` + base64.StdEncoding.EncodeToString([]byte(certPEM)) + `"}},
				{"metadata":{"name":"handmade-tls","namespace":"shop","annotations":{}},
				 "type":"kubernetes.io/tls","data":{"tls.crt":"` + base64.StdEncoding.EncodeToString([]byte(certPEM)) + `"}}
			],"metadata":{}}`))
		case strings.Contains(r.URL.Path, "/ingresses"):
			_, _ = w.Write([]byte(`{"items":[
				{"metadata":{"name":"shop","namespace":"shop"},
				 "spec":{"tls":[{"secretName":"managed-tls","hosts":["shop.internal"]}]}}
			],"metadata":{}}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	provider, err := newKubernetes(map[string]any{"api_url": srv.URL, "token": "test-token"})
	if err != nil {
		t.Fatal(err)
	}

	assets, err := provider.Inventory(context.Background())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("got %d secrets, want 2", len(assets))
	}

	managed := assetByID(assets, "shop/managed-tls")
	if managed == nil || managed.WillRenew == nil || !*managed.WillRenew {
		t.Fatalf("a cert-manager secret is not reported as renewed: %+v", managed)
	}
	if !strings.Contains(managed.RenewalMode, "shop-cert") {
		t.Errorf("renewal mode %q does not name the Certificate that owns it", managed.RenewalMode)
	}
	if managed.Attached == nil || !*managed.Attached {
		t.Error("a secret referenced by an ingress is not reported as attached")
	}

	handmade := assetByID(assets, "shop/handmade-tls")
	if handmade == nil || handmade.WillRenew == nil || *handmade.WillRenew {
		t.Fatalf("a hand-made secret is not reported as unrenewed: %+v", handmade)
	}
	if handmade.Attached == nil || *handmade.Attached {
		t.Error("a secret no ingress references is not reported as unattached")
	}
	if handmade.CertificatePEM == "" {
		t.Error("the certificate body was not decoded out of the secret")
	}
}

// Read access to ingresses is a separate RBAC grant from read access to
// secrets. A deployment with one and not the other must report "unknown"
// rather than "nothing uses this" — the second is a finding, and it would be
// a fabricated one.
func TestKubernetesUnknownAttachmentIsNotNoAttachment(t *testing.T) {
	certPEM := testCertPEM(t, "api.internal", time.Now().Add(60*24*time.Hour))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/ingresses") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"ingresses is forbidden"}`))
			return
		}
		_, _ = w.Write([]byte(`{"items":[
			{"metadata":{"name":"api-tls","namespace":"default"},
			 "type":"kubernetes.io/tls","data":{"tls.crt":"` + base64.StdEncoding.EncodeToString([]byte(certPEM)) + `"}}
		],"metadata":{}}`))
	}))
	defer srv.Close()

	provider, _ := newKubernetes(map[string]any{"api_url": srv.URL, "token": "t"})
	assets, err := provider.Inventory(context.Background())
	if err != nil {
		t.Fatalf("a failure listing ingresses must not fail the whole sync: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("got %d assets, want 1", len(assets))
	}
	if assets[0].Attached != nil {
		t.Errorf("attachment = %v, want unknown (nil) when ingresses could not be read", *assets[0].Attached)
	}
}

func TestKubernetesFollowsContinuationTokens(t *testing.T) {
	certPEM := testCertPEM(t, "paged.internal", time.Now().Add(60*24*time.Hour))
	body := base64.StdEncoding.EncodeToString([]byte(certPEM))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/ingresses") {
			_, _ = w.Write([]byte(`{"items":[],"metadata":{}}`))
			return
		}
		if r.URL.Query().Get("continue") == "" {
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"one","namespace":"a"},
				"type":"kubernetes.io/tls","data":{"tls.crt":"` + body + `"}}],
				"metadata":{"continue":"next-page"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"two","namespace":"a"},
			"type":"kubernetes.io/tls","data":{"tls.crt":"` + body + `"}}],"metadata":{}}`))
	}))
	defer srv.Close()

	provider, _ := newKubernetes(map[string]any{"api_url": srv.URL, "token": "t"})
	assets, err := provider.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// A cluster whose secrets do not fit in one page must not report only the
	// first page: a partial inventory is indistinguishable from a small one.
	if len(assets) != 2 {
		t.Fatalf("got %d secrets across pages, want 2", len(assets))
	}
}

// ── AWS ACM ─────────────────────────────────────────────────

func TestACMReportsImportedCertificatesAsNeverRenewed(t *testing.T) {
	issued := testCertPEM(t, "issued.example.com", time.Now().Add(60*24*time.Hour))
	imported := testCertPEM(t, "imported.example.com", time.Now().Add(20*24*time.Hour))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("the request was not signed")
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")

		switch r.Header.Get("X-Amz-Target") {
		case "CertificateManager.ListCertificates":
			_, _ = w.Write([]byte(`{"CertificateSummaryList":[
				{"CertificateArn":"arn:aws:acm:eu-west-1:1:certificate/aaa","DomainName":"issued.example.com",
				 "Status":"ISSUED","Type":"AMAZON_ISSUED","RenewalEligibility":"ELIGIBLE","InUse":true},
				{"CertificateArn":"arn:aws:acm:eu-west-1:1:certificate/bbb","DomainName":"imported.example.com",
				 "Status":"ISSUED","Type":"IMPORTED","RenewalEligibility":"INELIGIBLE","InUse":false}
			]}`))
		case "CertificateManager.GetCertificate":
			arn, _ := body["CertificateArn"].(string)
			pemBody := issued
			if strings.HasSuffix(arn, "bbb") {
				pemBody = imported
			}
			payload, _ := json.Marshal(map[string]string{"Certificate": pemBody})
			_, _ = w.Write(payload)
		default:
			t.Errorf("unexpected target %s", r.Header.Get("X-Amz-Target"))
		}
	}))
	defer srv.Close()

	provider, err := newACM(map[string]any{
		"region": "eu-west-1", "access_key_id": "AKID", "secret_access_key": "secret",
		"endpoint_url": srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	assets, err := provider.Inventory(context.Background())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("got %d certificates, want 2", len(assets))
	}

	amazon := assetByID(assets, "arn:aws:acm:eu-west-1:1:certificate/aaa")
	if amazon.WillRenew == nil || !*amazon.WillRenew {
		t.Error("an ELIGIBLE ACM-issued certificate is not reported as renewed by AWS")
	}
	if amazon.Attached == nil || !*amazon.Attached {
		t.Error("InUse was not carried through")
	}

	// The single most consequential fact this provider reports.
	brought := assetByID(assets, "arn:aws:acm:eu-west-1:1:certificate/bbb")
	if brought.WillRenew == nil || *brought.WillRenew {
		t.Fatal("an IMPORTED certificate is reported as one AWS will renew; AWS never renews these")
	}
	if brought.RenewalMode != "IMPORTED" {
		t.Errorf("renewal mode = %q, want AWS's own word", brought.RenewalMode)
	}
	if brought.CertificatePEM == "" {
		t.Error("the certificate body was not fetched, so it could never be matched to inventory")
	}
}

// An account whose credentials have gone stale must produce an error, not an
// empty inventory. An empty inventory is an all-clear.
func TestACMFailureIsAnErrorNotAnEmptyAccount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"__type":"ExpiredTokenException","message":"The security token included in the request is expired"}`))
	}))
	defer srv.Close()

	provider, _ := newACM(map[string]any{
		"region": "eu-west-1", "access_key_id": "AKID", "secret_access_key": "s", "endpoint_url": srv.URL,
	})
	assets, err := provider.Inventory(context.Background())
	if err == nil {
		t.Fatalf("an expired token produced %d assets and no error", len(assets))
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("the error does not carry AWS's own words: %v", err)
	}
}

// ── Azure Key Vault ─────────────────────────────────────────

// Key Vault's trap is one word. Issuer "Unknown" means the certificate was
// imported, so the vault has no issuer to go back to and cannot renew it — no
// matter what its lifetime actions appear to promise on the portal.
func TestKeyVaultTreatsUnknownIssuerAsUnrenewable(t *testing.T) {
	certPEM := testCertPEM(t, "vault.example.com", time.Now().Add(45*24*time.Hour))
	block, _ := pem.Decode([]byte(certPEM))
	der := base64.StdEncoding.EncodeToString(block.Bytes)

	var vaultURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			_, _ = w.Write([]byte(`{"access_token":"vault-token","expires_in":3600}`))
		case r.URL.Path == "/certificates":
			_, _ = w.Write([]byte(`{"value":[
				{"id":"` + vaultURL + `/certificates/imported"},
				{"id":"` + vaultURL + `/certificates/rotating"}
			]}`))
		case r.URL.Path == "/certificates/imported":
			_, _ = w.Write([]byte(`{"id":"` + vaultURL + `/certificates/imported","cer":"` + der + `",
				"attributes":{"enabled":true},
				"policy":{"issuer":{"name":"Unknown"},
				          "lifetime_actions":[{"action":{"action_type":"EmailContacts"}}]}}`))
		case r.URL.Path == "/certificates/rotating":
			_, _ = w.Write([]byte(`{"id":"` + vaultURL + `/certificates/rotating","cer":"` + der + `",
				"attributes":{"enabled":true},
				"policy":{"issuer":{"name":"DigiCert"},
				          "lifetime_actions":[{"action":{"action_type":"AutoRenew"}}]}}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	vaultURL = srv.URL

	provider, err := newKeyVault(map[string]any{
		"vault_url": srv.URL, "tenant_id": "t", "client_id": "c", "client_secret": "s",
		"login_url": srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	assets, err := provider.Inventory(context.Background())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("got %d certificates, want 2", len(assets))
	}

	imported := assetByID(assets, vaultURL+"/certificates/imported")
	if imported.WillRenew == nil || *imported.WillRenew {
		t.Fatal("a certificate whose policy issuer is Unknown is reported as renewable; the vault cannot renew it")
	}
	if !strings.Contains(imported.RenewalMode, "imported") {
		t.Errorf("renewal mode = %q, want it to say why", imported.RenewalMode)
	}
	if imported.CertificatePEM == "" {
		t.Error("the base64 DER body was not turned back into a certificate")
	}

	rotating := assetByID(assets, vaultURL+"/certificates/rotating")
	if rotating.WillRenew == nil || !*rotating.WillRenew {
		t.Error("a certificate with an AutoRenew policy and a real issuer is not reported as renewable")
	}

	// A vault does not know what is serving its certificates. Saying "nothing
	// is using this" would be inventing a finding.
	if imported.Attached != nil {
		t.Error("Key Vault reported an attachment state it has no way of knowing")
	}
}

// ── GCP ─────────────────────────────────────────────────────

func TestGCPSeparatesManagedFromSelfManaged(t *testing.T) {
	managedPEM := testCertPEM(t, "managed.example.com", time.Now().Add(70*24*time.Hour))
	selfPEM := testCertPEM(t, "self.example.com", time.Now().Add(25*24*time.Hour))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/token"):
			_, _ = w.Write([]byte(`{"access_token":"gcp-token","expires_in":3600}`))
		case strings.HasSuffix(r.URL.Path, "/aggregated/sslCertificates"):
			_, _ = w.Write([]byte(`{"items":{
				"global/sslCertificates":{"sslCertificates":[
					{"name":"managed-cert","selfLink":"https://x/global/sslCertificates/managed-cert",
					 "type":"MANAGED","managed":{"status":"ACTIVE"},"certificate":` + mustJSON(managedPEM) + `},
					{"name":"legacy-upload","selfLink":"https://x/global/sslCertificates/legacy-upload",
					 "type":"SELF_MANAGED","certificate":` + mustJSON(selfPEM) + `}
				]}}}`))
		case strings.HasSuffix(r.URL.Path, "/aggregated/targetHttpsProxies"):
			_, _ = w.Write([]byte(`{"items":{"global/targetHttpsProxies":{"targetHttpsProxies":[
				{"name":"web-proxy","sslCertificates":["https://x/global/sslCertificates/managed-cert"]}
			]}}}`))
		case strings.HasSuffix(r.URL.Path, "/aggregated/targetSslProxies"):
			_, _ = w.Write([]byte(`{"items":{}}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	provider, err := newGCP(map[string]any{
		"project_id": "demo", "use_metadata_server": true,
		"metadata_url": srv.URL + "/token", "compute_api_url": srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	assets, err := provider.Inventory(context.Background())
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("got %d certificates, want 2", len(assets))
	}

	managed := assetByID(assets, "https://x/global/sslCertificates/managed-cert")
	if managed.WillRenew == nil || !*managed.WillRenew {
		t.Error("a MANAGED certificate is not reported as renewed by Google")
	}
	if managed.Attached == nil || !*managed.Attached {
		t.Error("a certificate on a target HTTPS proxy is not reported as attached")
	}

	// Uploaded once, renewed by nobody, and identical to its neighbour on the
	// console.
	legacy := assetByID(assets, "https://x/global/sslCertificates/legacy-upload")
	if legacy.WillRenew == nil || *legacy.WillRenew {
		t.Fatal("a SELF_MANAGED certificate is reported as one Google will renew")
	}
	if legacy.Attached == nil || *legacy.Attached {
		t.Error("a certificate no proxy references is not reported as unattached")
	}
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// ── configuration ───────────────────────────────────────────

// A configuration mistake must be a 400 when it is typed, not a sync failure
// six hours later that reads on a dashboard like the account rejecting us.
func TestConfigurationIsRejectedWhenItIsWritten(t *testing.T) {
	cases := map[string]struct {
		provider string
		config   map[string]any
		wantWord string
	}{
		"acm without a region": {
			"aws_acm", map[string]any{"access_key_id": "a", "secret_access_key": "b"}, "region",
		},
		"acm without credentials": {
			"aws_acm", map[string]any{"region": "eu-west-1"}, "access_key_id",
		},
		"key vault without a url": {
			"azure_key_vault", map[string]any{"tenant_id": "t", "client_id": "c", "client_secret": "s"}, "vault_url",
		},
		"key vault without a secret": {
			"azure_key_vault", map[string]any{"vault_url": "https://v.vault.azure.net", "tenant_id": "t", "client_id": "c"}, "client_secret",
		},
		"gcp without a project": {
			"gcp", map[string]any{"use_metadata_server": true}, "project_id",
		},
		"gcp with a key that is not a key": {
			"gcp", map[string]any{"project_id": "p", "service_account_json": "{}"}, "client_email",
		},
		"kubernetes without a token": {
			"kubernetes", map[string]any{"api_url": "https://k8s.internal:6443"}, "token",
		},
		"an unknown provider": {
			"oracle_cloud", map[string]any{}, "unknown cloud provider",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ValidateConfig(tc.provider, tc.config)
			if err == nil {
				t.Fatal("accepted a configuration that cannot work")
			}
			if !strings.Contains(err.Error(), tc.wantWord) {
				t.Errorf("error %q does not name %q, so nobody can tell what to fix", err, tc.wantWord)
			}
		})
	}
}

// Scopes are what stop a narrow search reading as a small estate.
func TestScopesNameWhatWasNotLookedAt(t *testing.T) {
	gcp, err := newGCP(map[string]any{"project_id": "p", "use_metadata_server": true})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(gcp.Scopes(), " ")
	if !strings.Contains(joined, "NOT Certificate Manager") {
		t.Errorf("the GCP scopes do not say what is out of reach: %v", gcp.Scopes())
	}

	acm, err := newACM(map[string]any{"region": "eu-west-1", "access_key_id": "a", "secret_access_key": "b"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(acm.Scopes(), " "), "other regions") {
		t.Errorf("the ACM scopes do not say that other regions are invisible: %v", acm.Scopes())
	}
}
