package selfsigned

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"

	providerv1 "github.com/certpilot/certpilot/pkg/pb/provider/v1"
)

func TestIssueCertificate(t *testing.T) {
	p := NewProvider()

	req := &providerv1.IssueCertificateRequest{
		Domains:      []string{"test.example.com", "api.example.com"},
		KeyType:      "RSA",
		KeySize:      2048,
		ValidityDays: 90,
	}

	resp, err := p.IssueCertificate(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueCertificate failed: %v", err)
	}

	if resp.Certificate == nil {
		t.Fatal("expected certificate in response, got nil")
	}

	if resp.Certificate.CommonName != "test.example.com" {
		t.Errorf("expected CN test.example.com, got %s", resp.Certificate.CommonName)
	}

	if len(resp.Certificate.Sans) != 2 {
		t.Errorf("expected 2 SANs, got %d", len(resp.Certificate.Sans))
	}

	// Decode and parse the returned PEM
	block, _ := pem.Decode(resp.Certificate.CertificatePem)
	if block == nil {
		t.Fatal("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("parsed cert CN mismatch: %s", cert.Subject.CommonName)
	}

	// Test self-signature verification
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("self-signature verification failed: %v", err)
	}
}

func TestCapabilities(t *testing.T) {
	p := NewProvider()

	resp, err := p.GetCapabilities(context.Background(), &providerv1.GetCapabilitiesRequest{})
	if err != nil {
		t.Fatalf("GetCapabilities failed: %v", err)
	}

	if resp.Capabilities.ProviderName != "selfsigned" {
		t.Errorf("expected provider name selfsigned, got %s", resp.Capabilities.ProviderName)
	}
	if !resp.Capabilities.SupportsWildcard {
		t.Errorf("expected SupportsWildcard=true")
	}
}

func TestHealthCheck(t *testing.T) {
	p := NewProvider()

	resp, err := p.HealthCheck(context.Background(), &providerv1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}

	if resp.Status == 0 {
		t.Errorf("expected valid health status, got 0")
	}
}
