package acme

import (
	"context"
	"testing"

	providerv1 "github.com/certpilot/certpilot/pkg/pb/provider/v1"
)

func TestACMECapabilities(t *testing.T) {
	p := NewProvider("")

	resp, err := p.GetCapabilities(context.Background(), &providerv1.GetCapabilitiesRequest{})
	if err != nil {
		t.Fatalf("GetCapabilities failed: %v", err)
	}

	if resp.Capabilities.ProviderName != "acme" {
		t.Errorf("expected provider name acme, got %s", resp.Capabilities.ProviderName)
	}
	if !resp.Capabilities.SupportsWildcard {
		t.Errorf("expected SupportsWildcard=true")
	}
}

func TestACMEIssuePreparesRequest(t *testing.T) {
	p := NewProvider("https://acme-staging-v02.api.letsencrypt.org/directory")

	req := &providerv1.IssueCertificateRequest{
		Domains:      []string{"example.com", "www.example.com"},
		KeyType:      "RSA",
		KeySize:      2048,
		ValidityDays: 90,
	}

	resp, err := p.IssueCertificate(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	if resp.Certificate.CommonName != "example.com" {
		t.Errorf("expected CN example.com, got %s", resp.Certificate.CommonName)
	}
	if len(resp.Certificate.PrivateKeyPem) == 0 {
		t.Errorf("expected generated private key PEM")
	}
	if len(resp.Certificate.CertificatePem) == 0 {
		t.Errorf("expected generated CSR/PEM")
	}
}
