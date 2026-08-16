// Package renewal manages automated and manual certificate renewal pipelines.
package renewal

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/store"
	providerv1 "github.com/certpilot/certpilot/pkg/pb/provider/v1"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/certpilot/certpilot/pkg/x509util"
)

// Executor coordinates renewing a single certificate through its gateway plugin.
type Executor struct {
	store     store.Store
	pluginMgr *pluginmgr.Manager
	keyring   *secrets.Keyring
}

// NewExecutor creates a new renewal executor.
func NewExecutor(s store.Store, pm *pluginmgr.Manager, kr *secrets.Keyring) *Executor {
	return &Executor{
		store:     s,
		pluginMgr: pm,
		keyring:   kr,
	}
}

// RenewCertificate executes a certificate renewal through the assigned CA
// account gateway.
//
// A renewal is only complete when the new certificate and the key that matches
// it are both persisted. Storing one without the other produces a record that
// looks healthy on a dashboard and cannot terminate TLS.
func (e *Executor) RenewCertificate(ctx context.Context, certID string) (*store.Certificate, error) {
	cert, err := e.store.GetCertificate(ctx, certID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate %s: %w", certID, err)
	}

	if cert.CAAccountID == nil || *cert.CAAccountID == "" {
		return nil, fmt.Errorf("certificate %s has no assigned CA account", certID)
	}

	caAccount, err := e.store.GetCAAccount(ctx, *cert.CAAccountID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CA account: %w", err)
	}

	gw, err := e.pluginMgr.GetGateway(caAccount.Name)
	if err != nil {
		// Fall back to matching by provider type, for deployments that run one
		// shared gateway per protocol rather than one per account.
		gw, err = e.pluginMgr.GetGateway(caAccount.ProviderType)
		if err != nil {
			return nil, fmt.Errorf("gateway for CA account %s is not connected: %w", caAccount.Name, err)
		}
	}

	providerConfig, err := e.decryptCAConfig(caAccount)
	if err != nil {
		return nil, err
	}

	slog.Info("executing certificate renewal",
		"cert_id", certID,
		"common_name", cert.CommonName,
		"gateway", gw.Name,
	)

	now := time.Now()
	cert.LastRenewalAttempt = &now

	renewReq := &providerv1.RenewCertificateRequest{
		ProviderCertificateId: cert.SerialNumber,
		Domains:               append([]string{cert.CommonName}, cert.SANs...),
		KeyType:               cert.KeyType,
		KeySize:               int32(cert.KeySize),
		ProviderConfig:        providerConfig,
	}
	if cert.CertificatePEM != nil {
		renewReq.CurrentCertificatePem = []byte(*cert.CertificatePEM)
	}

	resp, err := gw.Client.RenewCertificate(ctx, renewReq)
	if err != nil {
		return nil, e.recordFailure(ctx, cert, err)
	}

	if resp.Certificate == nil || len(resp.Certificate.CertificatePem) == 0 {
		return nil, e.recordFailure(ctx, cert, fmt.Errorf("gateway reported success but returned no certificate"))
	}

	// Parse before persisting. A gateway that returns something that is not a
	// certificate must not be able to overwrite a working record with it.
	info, err := x509util.ParseCertificatePEM(resp.Certificate.CertificatePem)
	if err != nil {
		return nil, e.recordFailure(ctx, cert,
			fmt.Errorf("gateway returned data that is not a valid X.509 certificate: %w", err))
	}

	// Seal the rotated key before anything else is written. Renewal normally
	// rotates the key, and dropping the new key here is what previously left
	// the stored certificate and key mismatched after every renewal.
	if len(resp.Certificate.PrivateKeyPem) > 0 {
		sealed, err := e.keyring.Encrypt(resp.Certificate.PrivateKeyPem, secrets.ContextCertificatePrivKey)
		if err != nil {
			return nil, e.recordFailure(ctx, cert,
				fmt.Errorf("failed to encrypt the renewed private key, refusing to store it in the clear: %w", err))
		}
		cert.PrivateKeyEncrypted = &sealed
	}

	certPEM := string(resp.Certificate.CertificatePem)
	cert.CertificatePEM = &certPEM
	if len(resp.Certificate.ChainPem) > 0 {
		chainPEM := string(resp.Certificate.ChainPem)
		cert.ChainPEM = &chainPEM
	}

	notBefore, notAfter := info.NotBefore, info.NotAfter
	cert.NotBefore = &notBefore
	cert.NotAfter = &notAfter
	cert.DaysRemaining = info.DaysRemaining
	cert.SerialNumber = info.SerialNumber
	cert.IssuerDN = info.IssuerDN
	cert.FingerprintSHA256 = info.FingerprintSHA256
	cert.KeyType = info.KeyType
	cert.KeySize = info.KeySize

	cert.Status = "ISSUED"
	cert.RenewalError = nil
	cert.RenewalCount++

	if err := e.store.UpdateCertificate(ctx, cert); err != nil {
		return nil, fmt.Errorf("failed to save renewed certificate: %w", err)
	}

	_ = e.store.CreateAuditLog(ctx, &store.AuditLog{
		Action:     "cert.renewed",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		Details: fmt.Sprintf(`{"cn": %q, "serial": %q, "not_after": %q, "renewal_count": %d}`,
			cert.CommonName, cert.SerialNumber, notAfter.Format(time.RFC3339), cert.RenewalCount),
	})

	slog.Info("certificate renewed successfully",
		"cert_id", cert.ID,
		"common_name", cert.CommonName,
		"serial", cert.SerialNumber,
		"days_remaining", cert.DaysRemaining,
	)

	return cert, nil
}

// recordFailure marks a renewal as failed, audits it, and returns the error to
// propagate.
func (e *Executor) recordFailure(ctx context.Context, cert *store.Certificate, cause error) error {
	errMsg := cause.Error()
	cert.RenewalError = &errMsg
	cert.Status = "RENEWAL_FAILED"

	if err := e.store.UpdateCertificate(ctx, cert); err != nil {
		slog.Error("failed to record renewal failure", "cert_id", cert.ID, "error", err)
	}

	_ = e.store.CreateAuditLog(ctx, &store.AuditLog{
		Action:     "cert.renewal_failed",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		Details:    fmt.Sprintf(`{"error": %q, "cn": %q}`, errMsg, cert.CommonName),
	})

	return fmt.Errorf("renewal failed for %s: %w", cert.CommonName, cause)
}

func (e *Executor) decryptCAConfig(acc *store.CAAccount) (string, error) {
	if acc.ConfigEncrypted == "" {
		return "", nil
	}
	// Accounts written before encryption existed are stored as plaintext JSON.
	if !secrets.IsEnvelope(acc.ConfigEncrypted) {
		return acc.ConfigEncrypted, nil
	}
	plaintext, err := e.keyring.DecryptString(acc.ConfigEncrypted, secrets.ContextCAAccountConfig)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt the configuration for CA account %q: %w", acc.Name, err)
	}
	return plaintext, nil
}
