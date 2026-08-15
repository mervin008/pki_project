// Package pki provides background health monitoring and trust chain analysis for Certificate Authorities.
package pki

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/x509util"
)

// CAMonitor periodically inspects all registered CA authorities.
type CAMonitor struct {
	store      store.Store
	httpClient *http.Client
}

// NewCAMonitor creates a new CA health monitor.
func NewCAMonitor(s store.Store) *CAMonitor {
	return &CAMonitor{
		store: s,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// CheckAllCAs runs a full health check across all CA authorities.
func (m *CAMonitor) CheckAllCAs(ctx context.Context) error {
	cas, err := m.store.ListCAAuthorities(ctx)
	if err != nil {
		return fmt.Errorf("failed to list CAs: %w", err)
	}

	slog.Info("running CA health check", "total_cas", len(cas))

	for _, ca := range cas {
		if err := m.CheckCA(ctx, ca); err != nil {
			slog.Warn("CA check encountered error", "ca_name", ca.Name, "error", err)
		}
	}

	return nil
}

// CheckCA checks an individual CA authority: expiry, status, CRL, and OCSP.
func (m *CAMonitor) CheckCA(ctx context.Context, ca *store.CAAuthority) error {
	now := time.Now()

	// 1. Parse CA certificate if PEM is present
	if ca.CertificatePEM != "" {
		certInfo, err := x509util.ParseCertificatePEM([]byte(ca.CertificatePEM))
		if err == nil {
			ca.NotBefore = certInfo.NotBefore
			ca.NotAfter = certInfo.NotAfter
			ca.SerialNumber = certInfo.SerialNumber
			ca.IssuerDN = certInfo.IssuerDN
			ca.SubjectDN = certInfo.SubjectDN
			ca.KeyType = certInfo.KeyType
			ca.KeySize = certInfo.KeySize
			ca.FingerprintSHA256 = certInfo.FingerprintSHA256

			if len(certInfo.CRLURLs) > 0 && ca.CRLDistributionURL == "" {
				ca.CRLDistributionURL = certInfo.CRLURLs[0]
			}
			if len(certInfo.OCSPURLs) > 0 && ca.OCSPResponderURL == "" {
				ca.OCSPResponderURL = certInfo.OCSPURLs[0]
			}
		}
	}

	// 2. Compute days remaining and health status
	daysRemaining := int(time.Until(ca.NotAfter).Hours() / 24)
	if daysRemaining < 0 {
		daysRemaining = 0
		ca.Status = "EXPIRED"
	} else if daysRemaining <= 30 {
		ca.Status = "CRITICAL"
	} else if daysRemaining <= 180 {
		ca.Status = "WARNING"
	} else {
		ca.Status = "HEALTHY"
	}
	ca.DaysRemaining = daysRemaining

	// 3. Check CRL freshness if URL is configured
	if ca.CRLDistributionURL != "" {
		isFresh, err := m.checkCRL(ctx, ca.CRLDistributionURL)
		t := time.Now()
		ca.CRLLastChecked = &t
		ca.IsCRLFresh = (err == nil && isFresh)
	}

	// 4. Check OCSP responder if URL is configured
	if ca.OCSPResponderURL != "" {
		isResponsive := m.checkOCSP(ctx, ca.OCSPResponderURL)
		t := time.Now()
		ca.OCSPLastChecked = &t
		ca.IsOCSPResponsive = isResponsive
	}

	// 5. Check alert thresholds
	m.evaluateAlertThresholds(ca, daysRemaining, now)

	// 6. Persist updates
	return m.store.UpdateCAAuthority(ctx, ca)
}

func (m *CAMonitor) checkCRL(ctx context.Context, crlURL string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", crlURL, nil)
	if err != nil {
		return false, err
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("CRL returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	// Try DER or PEM parsing
	crlDER := body
	if block, _ := pem.Decode(body); block != nil {
		crlDER = block.Bytes
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return false, err
	}

	// Check if NextUpdate is in the future
	if crl.NextUpdate.Before(time.Now()) {
		return false, fmt.Errorf("CRL is expired (nextUpdate was %s)", crl.NextUpdate)
	}

	return true, nil
}

func (m *CAMonitor) checkOCSP(ctx context.Context, ocspURL string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", ocspURL, nil)
	if err != nil {
		return false
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Any non-5xx response indicates the responder is up
	return resp.StatusCode < 500
}

func (m *CAMonitor) evaluateAlertThresholds(ca *store.CAAuthority, daysRemaining int, now time.Time) {
	var thresholds []int
	if ca.AlertThresholds != "" {
		_ = json.Unmarshal([]byte(ca.AlertThresholds), &thresholds)
	}
	if len(thresholds) == 0 {
		thresholds = []int{365, 180, 90, 30, 14, 7}
	}

	for _, t := range thresholds {
		if daysRemaining <= t {
			if ca.LastAlertThreshold == nil || *ca.LastAlertThreshold != t {
				slog.Warn("CA threshold alert triggered",
					"ca_name", ca.Name,
					"days_remaining", daysRemaining,
					"threshold", t,
				)
				ca.LastAlertThreshold = &t
				ca.LastAlertSentAt = &now
			}
			break
		}
	}
}
