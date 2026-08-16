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
	"sort"
	"sync"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/x509util"
)

// CAMonitor periodically inspects all registered CA authorities.
type CAMonitor struct {
	store      store.Store
	broker     *events.Broker
	httpClient *http.Client
	stopCh     chan struct{}
	stopOnce   sync.Once
}

// NewCAMonitor creates a new CA health monitor. The broker may be nil, in which
// case no events are published.
func NewCAMonitor(s store.Store, broker *events.Broker) *CAMonitor {
	return &CAMonitor{
		store:  s,
		broker: broker,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		stopCh: make(chan struct{}),
	}
}

// Start runs a health check across every CA on the given interval.
//
// An expiring issuing CA is the highest-consequence failure in a PKI: it does
// not take down one service, it takes down everything that CA signs, and no
// amount of certificate automation helps once the CA above it has expired. So
// the sweep runs on a timer rather than waiting for someone to open the
// dashboard and press a button.
func (m *CAMonitor) Start(interval time.Duration) {
	if interval <= 0 {
		interval = 6 * time.Hour
	}

	slog.Info("starting CA health monitor", "interval", interval)

	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()

		// Run immediately, so a freshly started core reports real CA state
		// rather than whatever was last persisted.
		if err := m.CheckAllCAs(context.Background()); err != nil {
			slog.Error("initial CA health check failed", "error", err)
		}

		for {
			select {
			case <-ticker.C:
				if err := m.CheckAllCAs(context.Background()); err != nil {
					slog.Error("CA health check failed", "error", err)
				}
			case <-m.stopCh:
				return
			}
		}
	}()
}

// Stop halts the monitor. It is safe to call more than once.
func (m *CAMonitor) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh) })
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

	// Remember where this CA started so a status change can be reported as a
	// transition. Without the prior value "HEALTHY -> WARNING" is invisible:
	// the record is overwritten in place and the dashboard only ever sees the
	// end state, with no way to tell a fresh degradation from a steady one.
	previousStatus := ca.Status

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
	m.evaluateAlertThresholds(ctx, ca, daysRemaining, now)

	// 6. Persist updates
	if err := m.store.UpdateCAAuthority(ctx, ca); err != nil {
		return err
	}

	// 7. Announce a status change. Published after the write so a subscriber
	// that reacts by re-reading the CA sees the state the event describes.
	if ca.Status != previousStatus {
		severity := events.SeverityInfo
		switch ca.Status {
		case "CRITICAL", "EXPIRED":
			severity = events.SeverityCritical
		case "WARNING":
			severity = events.SeverityWarning
		}

		slog.Info("CA status changed",
			"ca_name", ca.Name, "from", previousStatus, "to", ca.Status,
			"days_remaining", daysRemaining)

		m.broker.Publish(events.Event{
			Topic:    events.TopicCAHealth,
			Severity: severity,
			EntityID: ca.ID,
			Payload: map[string]any{
				"ca_name":         ca.Name,
				"ca_type":         ca.CAType,
				"previous_status": previousStatus,
				"status":          ca.Status,
				"days_remaining":  daysRemaining,
				"is_crl_fresh":    ca.IsCRLFresh,
				"not_after":       ca.NotAfter.Format(time.RFC3339),
			},
		})
	}

	return nil
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

// evaluateAlertThresholds fires an alert the first time a CA crosses each
// configured threshold.
//
// Crossings are recorded to the audit log, not just to the process log. A
// monitoring team watches a dashboard, not stdout, and an alert nobody sees is
// the same as no alert — which is how CAs expire in organisations that believed
// they were monitoring them.
func (m *CAMonitor) evaluateAlertThresholds(ctx context.Context, ca *store.CAAuthority, daysRemaining int, now time.Time) {
	var thresholds []int
	if ca.AlertThresholds != "" {
		_ = json.Unmarshal([]byte(ca.AlertThresholds), &thresholds)
	}
	if len(thresholds) == 0 {
		thresholds = []int{365, 180, 90, 30, 14, 7}
	}

	// Ascending, so the first threshold the CA has crossed is also the
	// tightest one. A CA 10 days from expiry should report "14 days", not
	// "365 days" — the urgency is the point of the alert. Configuration order
	// is not guaranteed, hence the sort.
	sort.Ints(thresholds)

	for _, t := range thresholds {
		if daysRemaining > t {
			continue
		}

		// Already alerted at this threshold or a tighter one — do not repeat
		// until the situation actually worsens.
		if ca.LastAlertThreshold != nil && *ca.LastAlertThreshold <= t {
			return
		}

		severity := "WARNING"
		if daysRemaining <= 30 {
			severity = "CRITICAL"
		}

		slog.Warn("CA expiry threshold crossed",
			"ca_name", ca.Name,
			"ca_type", ca.CAType,
			"days_remaining", daysRemaining,
			"threshold", t,
			"severity", severity,
		)

		_ = m.store.CreateAuditLog(ctx, &store.AuditLog{
			Action:     "ca.expiry_alert",
			EntityType: "ca_authority",
			EntityID:   &ca.ID,
			Details: fmt.Sprintf(
				`{"ca_name": %q, "ca_type": %q, "days_remaining": %d, "threshold": %d, "severity": %q, "not_after": %q}`,
				ca.Name, ca.CAType, daysRemaining, t, severity, ca.NotAfter.Format(time.RFC3339)),
		})

		m.broker.Publish(events.Event{
			Topic:    events.TopicCAExpiryAlert,
			Severity: severity,
			EntityID: ca.ID,
			Payload: map[string]any{
				"ca_name":        ca.Name,
				"ca_type":        ca.CAType,
				"days_remaining": daysRemaining,
				"threshold":      t,
				"severity":       severity,
				"not_after":      ca.NotAfter.Format(time.RFC3339),
			},
		})

		ca.LastAlertThreshold = &t
		ca.LastAlertSentAt = &now
		return
	}
}
