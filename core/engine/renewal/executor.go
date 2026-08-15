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
	"github.com/certpilot/certpilot/pkg/x509util"
)

// Executor coordinates renewing a single certificate through its gateway plugin.
type Executor struct {
	store     store.Store
	pluginMgr *pluginmgr.Manager
}

// NewExecutor creates a new renewal executor.
func NewExecutor(s store.Store, pm *pluginmgr.Manager) *Executor {
	return &Executor{
		store:     s,
		pluginMgr: pm,
	}
}

// RenewCertificate executes a certificate renewal through the assigned CA account gateway.
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

	// Find the gateway plugin
	gw, err := e.pluginMgr.GetGateway(caAccount.Name)
	if err != nil {
		// Try by provider type
		gw, err = e.pluginMgr.GetGateway(caAccount.ProviderType)
		if err != nil {
			return nil, fmt.Errorf("gateway for CA account %s not connected: %w", caAccount.Name, err)
		}
	}

	slog.Info("executing certificate renewal",
		"cert_id", certID,
		"common_name", cert.CommonName,
		"gateway", gw.Name,
	)

	now := time.Now()
	cert.LastRenewalAttempt = &now

	// Build renew request
	renewReq := &providerv1.RenewCertificateRequest{
		ProviderCertificateId: cert.SerialNumber,
		Domains:               append([]string{cert.CommonName}, cert.SANs...),
		KeyType:               cert.KeyType,
		KeySize:               int32(cert.KeySize),
		ProviderConfig:        caAccount.ConfigEncrypted,
	}
	if cert.CertificatePEM != nil {
		renewReq.CurrentCertificatePem = []byte(*cert.CertificatePEM)
	}

	resp, err := gw.Client.RenewCertificate(ctx, renewReq)
	if err != nil {
		errMsg := err.Error()
		cert.RenewalError = &errMsg
		cert.Status = "RENEWAL_FAILED"
		_ = e.store.UpdateCertificate(ctx, cert)

		// Audit failure
		_ = e.store.CreateAuditLog(ctx, &store.AuditLog{
			Action:     "cert.renewal_failed",
			EntityType: "certificate",
			EntityID:   &cert.ID,
			Details:    fmt.Sprintf(`{"error": %q, "cn": %q}`, errMsg, cert.CommonName),
		})

		return nil, fmt.Errorf("gateway renewal failed: %w", err)
	}

	// Renewal succeeded — update cert details
	if resp.Certificate != nil {
		certPEM := string(resp.Certificate.CertificatePem)
		cert.CertificatePEM = &certPEM
		if len(resp.Certificate.ChainPem) > 0 {
			chainPEM := string(resp.Certificate.ChainPem)
			cert.ChainPEM = &chainPEM
		}

		if resp.Certificate.NotBefore != nil {
			nb := resp.Certificate.NotBefore.AsTime()
			cert.NotBefore = &nb
		}
		if resp.Certificate.NotAfter != nil {
			na := resp.Certificate.NotAfter.AsTime()
			cert.NotAfter = &na
			cert.DaysRemaining = int(time.Until(na).Hours() / 24)
		}
		if resp.Certificate.SerialNumber != "" {
			cert.SerialNumber = resp.Certificate.SerialNumber
		}

		// Re-compute SHA256 fingerprint if PEM updated
		if info, err := x509util.ParseCertificatePEM(resp.Certificate.CertificatePem); err == nil {
			cert.FingerprintSHA256 = info.FingerprintSHA256
		}
	}

	cert.Status = "ISSUED"
	cert.RenewalError = nil
	cert.RenewalCount++

	if err := e.store.UpdateCertificate(ctx, cert); err != nil {
		return nil, fmt.Errorf("failed to save renewed certificate: %w", err)
	}

	// Audit success
	_ = e.store.CreateAuditLog(ctx, &store.AuditLog{
		Action:     "cert.renewed",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		Details:    fmt.Sprintf(`{"cn": %q, "serial": %q, "days_remaining": %d}`, cert.CommonName, cert.SerialNumber, cert.DaysRemaining),
	})

	slog.Info("certificate renewed successfully",
		"cert_id", cert.ID,
		"common_name", cert.CommonName,
		"days_remaining", cert.DaysRemaining,
	)

	return cert, nil
}
