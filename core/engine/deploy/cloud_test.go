package deploy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTheIdentityOfWhatIsBeingReplacedIsRequired.
//
// The one failure all three cloud deployers share, and the reason it is refused
// at binding time rather than at deploy time: in every case the install
// *succeeds*, under an identity nothing is pointing at, while the thing in
// front of the users expires on schedule and the provider's console shows a
// fresh green certificate.
func TestTheIdentityOfWhatIsBeingReplacedIsRequired(t *testing.T) {
	cases := map[string]struct {
		targetType string
		options    map[string]any
		mentions   string
	}{
		"ACM without an ARN": {
			TypeACM, nil, "no load balancer is pointing at",
		},
		"ACM with an empty ARN": {
			TypeACM, map[string]any{"certificate_arn": "  "}, "no load balancer is pointing at",
		},
		"Key Vault without a name": {
			TypeKeyVault, nil, "nothing is configured to read",
		},
		"F5 without a name": {
			TypeF5, map[string]any{"partition": "Common"}, "previous certificate",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := ValidateOptions(tc.targetType, tc.options)
			if err == nil {
				t.Fatal("this binding should have been refused")
			}
			if !strings.Contains(err.Error(), tc.mentions) {
				t.Fatalf("the error should name the consequence, got: %v", err)
			}
		})
	}

	// And the ones that name it are accepted.
	for _, ok := range []struct {
		targetType string
		options    map[string]any
	}{
		{TypeACM, map[string]any{"certificate_arn": "arn:aws:acm:eu-west-1:1:certificate/abc"}},
		{TypeKeyVault, map[string]any{"certificate_name": "shop-example-com"}},
		{TypeF5, map[string]any{"name": "shop.example.com"}},
		{TypeWebhook, nil},
	} {
		if err := ValidateOptions(ok.targetType, ok.options); err != nil {
			t.Fatalf("%s should have been accepted: %v", ok.targetType, err)
		}
	}
}

// acmStub answers like ACM does, and records what it was asked.
type acmStub struct {
	body   map[string]any
	target string
	// createNew makes it behave like an ImportCertificate that created rather
	// than replaced — which is what AWS does when the ARN is omitted.
	createNew bool
	status    string
	inUseBy   []string
}

func (s *acmStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		target := r.Header.Get("X-Amz-Target")

		switch {
		case strings.HasSuffix(target, "ImportCertificate"):
			s.target = target
			s.body = map[string]any{}
			_ = json.Unmarshal(raw, &s.body)
			arn, _ := s.body["CertificateArn"].(string)
			if s.createNew || arn == "" {
				arn = "arn:aws:acm:eu-west-1:1:certificate/a-brand-new-one"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"CertificateArn": arn})

		case strings.HasSuffix(target, "DescribeCertificate"):
			status := s.status
			if status == "" {
				status = "ISSUED"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Certificate": map[string]any{"Status": status, "InUseBy": s.inUseBy},
			})

		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})
}

func acmAgainst(t *testing.T, server *httptest.Server) Deployer {
	t.Helper()
	d, err := newACMDeployer(map[string]any{
		connectionField:     "a-connection",
		"region":            "eu-west-1",
		"access_key_id":     "AKIAEXAMPLE",
		"secret_access_key": "secret",
		"endpoint_url":      server.URL,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return d
}

// TestACMReplacesInPlaceAndRefusesToHaveCreatedSomethingNew.
//
// ImportCertificate with an ARN replaces the material behind it and every
// listener follows. Without one it creates a new certificate, attached to
// nothing, and returns 200. This test is the difference.
func TestACMReplacesInPlaceAndRefusesToHaveCreatedSomethingNew(t *testing.T) {
	const arn = "arn:aws:acm:eu-west-1:1:certificate/the-one-in-use"

	stub := &acmStub{inUseBy: []string{"arn:aws:elasticloadbalancing:…"}}
	server := httptest.NewServer(stub.handler())
	defer server.Close()

	bundle := Bundle{
		CommonName: "shop.example.com", CertificatePEM: "cert", PrivateKeyPEM: "key",
		ChainPEM: "chain", Options: map[string]any{"certificate_arn": arn},
	}

	detail, err := acmAgainst(t, server).Deploy(context.Background(), bundle)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if got, _ := stub.body["CertificateArn"].(string); got != arn {
		t.Fatalf("the ARN must be sent, or ACM creates a new certificate; sent %q", got)
	}
	if _, ok := stub.body["CertificateChain"]; !ok {
		t.Fatal("the chain belongs in the import; ACM rejects a leaf that carries it inline")
	}
	if !strings.Contains(detail, "in use by 1") {
		t.Fatalf("the detail should say what is actually using it: %q", detail)
	}

	// Now ACM behaves as it does when the ARN did not take: 200, a new ARN,
	// and nothing pointing at it.
	stub.createNew = true
	_, err = acmAgainst(t, server).Deploy(context.Background(), bundle)
	if err == nil {
		t.Fatal("a create-instead-of-replace must not be reported as a successful deployment")
	}
	if !strings.Contains(err.Error(), "still serving the previous certificate") {
		t.Fatalf("the error should say what is actually being served, got: %v", err)
	}
}

// TestACMSaysSoWhenNothingIsUsingTheCertificate.
//
// A successful import into an ARN no load balancer references is the failure
// this package exists to prevent, arriving as a success. AWS will say so if
// asked, so it is asked.
func TestACMSaysSoWhenNothingIsUsingTheCertificate(t *testing.T) {
	stub := &acmStub{inUseBy: nil}
	server := httptest.NewServer(stub.handler())
	defer server.Close()

	detail, err := acmAgainst(t, server).Deploy(context.Background(), Bundle{
		CommonName: "shop.example.com", CertificatePEM: "cert", PrivateKeyPEM: "key",
		Options: map[string]any{"certificate_arn": "arn:aws:acm:eu-west-1:1:certificate/orphan"},
	})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if !strings.Contains(detail, "may not be attached to a listener") {
		t.Fatalf("an unattached ARN should be said out loud: %q", detail)
	}
}

// TestACMRefusesWithoutAPrivateKey.
//
// ACM stores the key with the certificate. A discovered or imported certificate
// has none here, and the message has to say that rather than report a
// permissions problem.
func TestACMRefusesWithoutAPrivateKey(t *testing.T) {
	server := httptest.NewServer((&acmStub{}).handler())
	defer server.Close()

	_, err := acmAgainst(t, server).Deploy(context.Background(), Bundle{
		CommonName: "shop.example.com", CertificatePEM: "cert",
		Options: map[string]any{"certificate_arn": "arn:aws:acm:eu-west-1:1:certificate/x"},
	})
	if err == nil || !strings.Contains(err.Error(), "until it is reissued through CertPilot") {
		t.Fatalf("expected a message about where the key is, got: %v", err)
	}
}

// TestACloudTargetWillNotHoldItsOwnCredentials.
//
// Two copies of one account's credentials — one for discovery, one for
// deployment — is one rotation away from a system that can read an account it
// can no longer write to.
func TestACloudTargetWillNotHoldItsOwnCredentials(t *testing.T) {
	for _, targetType := range []string{TypeACM, TypeKeyVault} {
		_, err := build(targetType, map[string]any{
			"region":            "eu-west-1",
			"access_key_id":     "AKIAEXAMPLE",
			"secret_access_key": "secret",
			"vault_url":         "https://contoso.vault.azure.net",
		})
		if err == nil {
			t.Fatalf("%s accepted credentials of its own", targetType)
		}
		if !strings.Contains(err.Error(), connectionField) {
			t.Fatalf("%s should ask for a connection: %v", targetType, err)
		}
		if !RequiresConnection(targetType) {
			t.Fatalf("%s should be marked as borrowing a connection", targetType)
		}
	}
	if RequiresConnection(TypeWebhook) || RequiresConnection(TypeF5) {
		t.Fatal("only the cloud providers borrow a connection; an appliance is not an account")
	}
}

// TestAnF5ManagementAddressMustBeHTTPS.
//
// The certificate and its private key travel over this connection.
func TestAnF5ManagementAddressMustBeHTTPS(t *testing.T) {
	_, err := newF5Deployer(map[string]any{
		"host": "http://bigip.internal", "username": "admin", "password": "x",
	})
	if err == nil || !strings.Contains(err.Error(), "private key travel") {
		t.Fatalf("plaintext management should be refused by name, got: %v", err)
	}

	// https is accepted, and a bare hostname is assumed to be https rather than
	// quietly downgraded.
	d, err := newF5Deployer(map[string]any{
		"host": "bigip.internal", "username": "admin", "password": "x",
	})
	if err != nil {
		t.Fatalf("a bare hostname should be accepted: %v", err)
	}
	if !strings.HasPrefix(d.Describe(), "https://") {
		t.Fatalf("a bare hostname should become https, got %q", d.Describe())
	}

	// Turning verification off is allowed and must be visible.
	off, err := newF5Deployer(map[string]any{
		"host": "bigip.internal", "username": "admin", "password": "x",
		"insecure_skip_verify": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(off.Describe(), "TLS verification off") {
		t.Fatalf("a target that skips verification should say so: %q", off.Describe())
	}
}

// TestEveryCloudTargetShipsThePrivateKey.
//
// All three terminate TLS, so all three hold the key — and that has to show up
// in the column a security team reads without the KEK.
func TestEveryCloudTargetShipsThePrivateKey(t *testing.T) {
	for _, tc := range []struct {
		targetType string
		config     map[string]any
	}{
		{TypeACM, map[string]any{connectionField: "c", "region": "eu-west-1",
			"access_key_id": "A", "secret_access_key": "s"}},
		{TypeKeyVault, map[string]any{connectionField: "c",
			"vault_url": "https://contoso.vault.azure.net",
			"tenant_id": "t", "client_id": "c", "client_secret": "s"}},
		{TypeF5, map[string]any{"host": "bigip.internal", "username": "a", "password": "b"}},
	} {
		d, err := build(tc.targetType, tc.config)
		if err != nil {
			t.Fatalf("%s: %v", tc.targetType, err)
		}
		if !d.NeedsPrivateKey() {
			t.Fatalf("%s terminates TLS and must be recorded as receiving key material", tc.targetType)
		}
	}
}
