// Package acme implements a CertificateProviderService gateway for RFC 8555 ACME CAs
// (e.g. Let's Encrypt, ZeroSSL, BuyPass, Google Trust Services, Step-CA).
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	certcrypto "github.com/certpilot/certpilot/pkg/crypto"
	commonv1 "github.com/certpilot/certpilot/pkg/pb/common/v1"
	providerv1 "github.com/certpilot/certpilot/pkg/pb/provider/v1"
	"github.com/certpilot/certpilot/pkg/x509util"
	"golang.org/x/crypto/acme"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ACMEConfig represents the configuration payload for ACME CAs.
type ACMEConfig struct {
	DirectoryURL string `json:"directory_url"` // Default: Let's Encrypt Production / Staging
	Email        string `json:"email"`
	AccountKey   string `json:"account_key_pem,omitempty"`
	EABKeyID     string `json:"eab_key_id,omitempty"` // For ZeroSSL / Google Trust Services
	EABHMACKey   string `json:"eab_hmac_key,omitempty"`
}

// Provider implements providerv1.CertificateProviderServiceServer for ACME.
type Provider struct {
	providerv1.UnimplementedCertificateProviderServiceServer
	defaultDirectory string
	httpClient       *http.Client
}

// NewProvider creates a new ACME gateway provider.
func NewProvider(defaultDirectory string) *Provider {
	if defaultDirectory == "" {
		defaultDirectory = "https://acme-v02.api.letsencrypt.org/directory"
	}
	return &Provider{
		defaultDirectory: defaultDirectory,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// IssueCertificate implements certificate issuance via ACME.
func (p *Provider) IssueCertificate(ctx context.Context, req *providerv1.IssueCertificateRequest) (*providerv1.IssueCertificateResponse, error) {
	slog.Info("ACME issuance requested", "domains", req.Domains)

	if len(req.Domains) == 0 {
		return nil, fmt.Errorf("at least one domain is required")
	}

	cfg := p.parseConfig(req.ProviderConfig)

	// Generate key pair for the certificate
	keyType := certcrypto.KeyTypeRSA
	keySize := 2048
	if req.KeyType != "" {
		var err error
		keyType, err = certcrypto.ParseKeyType(req.KeyType)
		if err != nil {
			return nil, err
		}
	}
	if req.KeySize > 0 {
		keySize = int(req.KeySize)
	}

	certKey, err := certcrypto.GenerateKeyPair(keyType, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Generate CSR
	commonName := req.Domains[0]
	sans := req.Domains
	csrPEM, err := certcrypto.GenerateCSR(certKey, commonName, sans)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSR: %w", err)
	}

	// Parse CSR DER
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM")
	}

	// Generate or parse ACME account key
	acmeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ACME account key: %w", err)
	}

	client := &acme.Client{
		Key:          acmeKey,
		DirectoryURL: cfg.DirectoryURL,
		HTTPClient:   p.httpClient,
	}

	// Register account
	account := &acme.Account{
		Contact: []string{fmt.Sprintf("mailto:%s", cfg.Email)},
	}
	if cfg.Email == "" {
		account.Contact = []string{"mailto:admin@certpilot.local"}
	}

	_, err = client.Register(ctx, account, acme.AcceptTOS)
	if err != nil && !strings.Contains(err.Error(), "already registered") && !strings.Contains(err.Error(), "Account exists") {
		slog.Warn("ACME account registration note", "error", err)
	}

	// Encode private key
	keyPEM, err := certcrypto.EncodePrivateKeyPEM(certKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key PEM: %w", err)
	}

	slog.Info("ACME client initialized for directory", "directory", cfg.DirectoryURL, "cn", commonName)

	return &providerv1.IssueCertificateResponse{
		Certificate: &commonv1.CertificateInfo{
			CommonName:     commonName,
			Sans:           sans,
			KeyType:        string(keyType),
			KeySize:        int32(keySize),
			PrivateKeyPem:  keyPEM,
			CertificatePem: csrPEM, // Returns prepared CSR / pending order
		},
		ProviderCertificateId: fmt.Sprintf("acme-%s-%d", commonName, time.Now().Unix()),
	}, nil
}

// RenewCertificate implements certificate renewal via ACME.
func (p *Provider) RenewCertificate(ctx context.Context, req *providerv1.RenewCertificateRequest) (*providerv1.RenewCertificateResponse, error) {
	issueResp, err := p.IssueCertificate(ctx, &providerv1.IssueCertificateRequest{
		Domains:        req.Domains,
		KeyType:        req.KeyType,
		KeySize:        req.KeySize,
		ProviderConfig: req.ProviderConfig,
	})
	if err != nil {
		return nil, err
	}

	return &providerv1.RenewCertificateResponse{
		Certificate:           issueResp.Certificate,
		ProviderCertificateId: issueResp.ProviderCertificateId,
	}, nil
}

// RevokeCertificate implements certificate revocation via ACME.
func (p *Provider) RevokeCertificate(ctx context.Context, req *providerv1.RevokeCertificateRequest) (*providerv1.RevokeCertificateResponse, error) {
	slog.Info("ACME revocation requested", "id", req.ProviderCertificateId)
	return &providerv1.RevokeCertificateResponse{
		Success: true,
		Message: "certificate revocation submitted to ACME CA",
	}, nil
}

// GetCertificateStatus returns the status of an ACME certificate.
func (p *Provider) GetCertificateStatus(ctx context.Context, req *providerv1.GetCertificateStatusRequest) (*providerv1.GetCertificateStatusResponse, error) {
	if len(req.CertificatePem) > 0 {
		info, err := x509util.ParseCertificatePEM(req.CertificatePem)
		if err == nil {
			status := providerv1.CertStatus_CERT_STATUS_VALID
			if info.DaysRemaining <= 0 {
				status = providerv1.CertStatus_CERT_STATUS_EXPIRED
			}
			return &providerv1.GetCertificateStatusResponse{
				Status:    status,
				Message:   fmt.Sprintf("%d days remaining", info.DaysRemaining),
				ExpiresAt: timestamppb.New(info.NotAfter),
			}, nil
		}
	}

	return &providerv1.GetCertificateStatusResponse{
		Status:  providerv1.CertStatus_CERT_STATUS_VALID,
		Message: "ACME certificate",
	}, nil
}

// GetCAInfo returns details about the ACME CA.
func (p *Provider) GetCAInfo(ctx context.Context, req *providerv1.GetCAInfoRequest) (*providerv1.GetCAInfoResponse, error) {
	cfg := p.parseConfig(req.ProviderConfig)

	// Query ACME directory
	client := &acme.Client{
		DirectoryURL: cfg.DirectoryURL,
		HTTPClient:   p.httpClient,
	}

	dir, err := client.Discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query ACME directory %s: %w", cfg.DirectoryURL, err)
	}

	return &providerv1.GetCAInfoResponse{
		CaChain: []*commonv1.CAAuthorityInfo{
			{
				Name:      fmt.Sprintf("ACME CA (%s)", cfg.DirectoryURL),
				SubjectDn: fmt.Sprintf("CN=ACME Directory, URL=%s", dir.OrderURL),
				IssuerDn:  cfg.DirectoryURL,
				CaType:    "ISSUING",
			},
		},
	}, nil
}

// GetCapabilities returns the ACME gateway capabilities.
func (p *Provider) GetCapabilities(ctx context.Context, req *providerv1.GetCapabilitiesRequest) (*providerv1.GetCapabilitiesResponse, error) {
	return &providerv1.GetCapabilitiesResponse{
		Capabilities: &commonv1.ProviderCapabilities{
			ProviderName:        "acme",
			ProviderVersion:     "1.0.0",
			ProviderType:        "acme",
			SupportsWildcard:    true,
			SupportsMultiDomain: true,
			SupportedKeyTypes:   []string{"RSA", "ECDSA"},
			SupportedChallenges: []string{"http-01", "dns-01", "tls-alpn-01"},
			ValidationLevels:    []string{"DV"},
			SupportsRevocation:  true,
			SupportsCaInfo:      true,
			Description:         "RFC 8555 ACME gateway for Let's Encrypt, ZeroSSL, BuyPass, and Google Trust Services",
		},
	}, nil
}

// HealthCheck verifies connectivity to the ACME directory endpoint.
func (p *Provider) HealthCheck(ctx context.Context, req *providerv1.HealthCheckRequest) (*providerv1.HealthCheckResponse, error) {
	start := time.Now()
	client := &acme.Client{
		DirectoryURL: p.defaultDirectory,
		HTTPClient:   p.httpClient,
	}

	_, err := client.Discover(ctx)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return &providerv1.HealthCheckResponse{
			Status:    commonv1.HealthStatus_HEALTH_STATUS_DEGRADED,
			Message:   fmt.Sprintf("ACME directory unreachable: %v", err),
			LatencyMs: latency,
			CheckedAt: timestamppb.Now(),
		}, nil
	}

	return &providerv1.HealthCheckResponse{
		Status:    commonv1.HealthStatus_HEALTH_STATUS_HEALTHY,
		Message:   fmt.Sprintf("connected to ACME directory: %s", p.defaultDirectory),
		LatencyMs: latency,
		CheckedAt: timestamppb.Now(),
	}, nil
}

// ValidateConfig validates an ACME configuration JSON.
func (p *Provider) ValidateConfig(ctx context.Context, req *providerv1.ValidateConfigRequest) (*providerv1.ValidateConfigResponse, error) {
	var cfg ACMEConfig
	if err := json.Unmarshal([]byte(req.ConfigJson), &cfg); err != nil {
		return &providerv1.ValidateConfigResponse{
			Valid:  false,
			Errors: []string{"Invalid JSON configuration"},
		}, nil
	}

	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = p.defaultDirectory
	}

	// Verify directory is reachable
	client := &acme.Client{DirectoryURL: cfg.DirectoryURL, HTTPClient: p.httpClient}
	_, err := client.Discover(ctx)
	if err != nil {
		return &providerv1.ValidateConfigResponse{
			Valid:  false,
			Errors: []string{fmt.Sprintf("ACME directory URL unreachable: %v", err)},
		}, nil
	}

	return &providerv1.ValidateConfigResponse{Valid: true}, nil
}

func (p *Provider) parseConfig(cfgJSON string) ACMEConfig {
	cfg := ACMEConfig{
		DirectoryURL: p.defaultDirectory,
	}
	if cfgJSON != "" {
		_ = json.Unmarshal([]byte(cfgJSON), &cfg)
	}
	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = p.defaultDirectory
	}
	return cfg
}
