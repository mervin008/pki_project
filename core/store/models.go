// Package store provides database access models and queries for CertPilot.
package store

import (
	"time"
)

// CAAuthority represents a Certificate Authority record.
type CAAuthority struct {
	ID                      string     `json:"id"`
	Name                    string     `json:"name"`
	CAType                  string     `json:"ca_type"` // ROOT, INTERMEDIATE, ISSUING
	SubjectDN               string     `json:"subject_dn"`
	IssuerDN                string     `json:"issuer_dn"`
	SerialNumber            string     `json:"serial_number,omitempty"`
	NotBefore               time.Time  `json:"not_before"`
	NotAfter                time.Time  `json:"not_after"`
	DaysRemaining           int        `json:"days_remaining"`
	KeyType                 string     `json:"key_type"`
	KeySize                 int        `json:"key_size"`
	FingerprintSHA256       string     `json:"fingerprint_sha256"`
	CertificatePEM          string     `json:"certificate_pem"`
	ParentCAID              *string    `json:"parent_ca_id,omitempty"`
	CRLDistributionURL      string     `json:"crl_distribution_url,omitempty"`
	OCSPResponderURL        string     `json:"ocsp_responder_url,omitempty"`
	IsCRLFresh              bool       `json:"is_crl_fresh"`
	CRLLastChecked          *time.Time `json:"crl_last_checked,omitempty"`
	IsOCSPResponsive        bool       `json:"is_ocsp_responsive"`
	OCSPLastChecked         *time.Time `json:"ocsp_last_checked,omitempty"`
	CertificatesIssuedCount int64      `json:"certificates_issued_count"`
	AlertThresholds         string     `json:"alert_thresholds,omitempty"` // JSON string
	LastAlertSentAt         *time.Time `json:"last_alert_sent_at,omitempty"`
	LastAlertThreshold      *int       `json:"last_alert_threshold,omitempty"`
	Status                  string     `json:"status"` // HEALTHY, WARNING, CRITICAL, EXPIRED, UNKNOWN
	CAAccountID             *string    `json:"ca_account_id,omitempty"`
	// OwnerTeam and OwnerEmail say who to call. Free text: team names and
	// distribution lists do not live in CertPilot, and a foreign key to
	// something it does not own would mean either an import step or a wrong
	// answer on a row someone is reading at 2am.
	OwnerTeam  *string `json:"owner_team,omitempty"`
	OwnerEmail *string `json:"owner_email,omitempty"`
	Tags       string  `json:"tags,omitempty"`
	Notes      string  `json:"notes,omitempty"`
	// Acknowledgement is the current acknowledgement, when the caller asked for
	// it to be resolved. Not a stored column — see AlertAcknowledgement.
	Acknowledgement *AlertAcknowledgement `json:"acknowledgement,omitempty"`
	CreatedAt       time.Time             `json:"created_at"`
	UpdatedAt       time.Time             `json:"updated_at"`
}

// Entity types an acknowledgement can cover.
const (
	AckEntityCAAuthority = "ca_authority"
	AckEntityCertificate = "certificate"
)

// AlertAcknowledgement records that a human has seen an alert and, optionally,
// that delivery should stay quiet for a while.
//
// The rule this type exists to enforce: **silencing suppresses delivery, never
// display.** An acknowledged CA still appears on the dashboard and in the wall
// view, marked as acknowledged and by whom. Hiding a problem because someone
// clicked a button is how CAs expire in organisations that believed they were
// monitoring them.
type AlertAcknowledgement struct {
	ID         string `json:"id"`
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	// Threshold is the expiry threshold, in days, that this acknowledgement
	// covers. Nil means it is not tied to one.
	//
	// This is the field that makes acknowledgement safe rather than dangerous.
	// Acknowledging a CA at 30 days must not silence its 7-day alert: the
	// situation has materially worsened, and the earlier "yes, we know" was an
	// answer to a different question.
	Threshold           *int       `json:"threshold,omitempty"`
	AcknowledgedBy      *string    `json:"acknowledged_by,omitempty"`
	AcknowledgedByEmail *string    `json:"acknowledged_by_email,omitempty"`
	AcknowledgedAt      time.Time  `json:"acknowledged_at"`
	Note                string     `json:"note,omitempty"`
	SilenceUntil        *time.Time `json:"silence_until,omitempty"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
	RevokedBy           *string    `json:"revoked_by,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

// IsActive reports whether this acknowledgement still stands at the given
// instant, for an alert at the given threshold.
//
// `currentThreshold` is the threshold the alert is being raised at. A nil value
// means the caller is asking about the entity generally rather than about one
// alert.
func (a *AlertAcknowledgement) IsActive(now time.Time, currentThreshold *int) bool {
	if a == nil || a.RevokedAt != nil {
		return false
	}
	// A tighter threshold than the one acknowledged is a new situation, not a
	// repeat of the acknowledged one.
	if a.Threshold != nil && currentThreshold != nil && *currentThreshold < *a.Threshold {
		return false
	}
	return true
}

// SuppressesDelivery reports whether an alert should stay out of Slack and
// email right now.
//
// Deliberately distinct from IsActive: acknowledging without silencing is the
// common case — the alert stops being *new*, but still goes out — and only an
// explicit `silence_until` in the future stops delivery.
func (a *AlertAcknowledgement) SuppressesDelivery(now time.Time, currentThreshold *int) bool {
	if !a.IsActive(now, currentThreshold) {
		return false
	}
	return a.SilenceUntil != nil && a.SilenceUntil.After(now)
}

// CAAccount represents a Gateway Connection configuration.
type CAAccount struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ProviderType string `json:"provider_type"` // acme, vault, selfsigned, etc.
	GatewayAddr  string `json:"gateway_addr"`
	// ConfigEncrypted holds the sealed CA credentials. It is never serialized
	// to API clients: the ciphertext is not a secret by itself, but shipping
	// it to every dashboard reader turns one compromised KEK into a total
	// credential loss instead of requiring database access as well.
	ConfigEncrypted string     `json:"-"`
	IsDefault       bool       `json:"is_default"`
	Status          string     `json:"status"` // CONNECTED, DISCONNECTED, ERROR
	LastHealthAt    *time.Time `json:"last_health_at,omitempty"`
	CreatedBy       *string    `json:"created_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// Certificate represents a managed TLS certificate.
type Certificate struct {
	ID                 string     `json:"id"`
	FingerprintSHA256  string     `json:"fingerprint_sha256"`
	CommonName         string     `json:"common_name"`
	SANs               []string   `json:"sans"`
	SerialNumber       string     `json:"serial_number,omitempty"`
	IssuerDN           string     `json:"issuer_dn,omitempty"`
	NotBefore          *time.Time `json:"not_before,omitempty"`
	NotAfter           *time.Time `json:"not_after,omitempty"`
	DaysRemaining      int        `json:"days_remaining"`
	KeyType            string     `json:"key_type,omitempty"`
	KeySize            int        `json:"key_size,omitempty"`
	Status             string     `json:"status"` // PENDING, ISSUED, EXPIRING, EXPIRED, REVOKED, RENEWAL_FAILED
	AutoRenew          bool       `json:"auto_renew"`
	RenewalLeadDays    int        `json:"renewal_lead_days"`
	LastRenewalAttempt *time.Time `json:"last_renewal_attempt,omitempty"`
	RenewalError       *string    `json:"renewal_error,omitempty"`
	RenewalCount       int        `json:"renewal_count"`
	CAAccountID        *string    `json:"ca_account_id,omitempty"`
	CAAuthorityID      *string    `json:"ca_authority_id,omitempty"`
	DeploymentTargetID *string    `json:"deployment_target_id,omitempty"`
	// PrivateKeyEncrypted holds the sealed private key. It is never serialized
	// in a list or detail response; retrieving a key is a separate,
	// admin-only, audited operation.
	PrivateKeyEncrypted *string   `json:"-"`
	CertificatePEM      *string   `json:"certificate_pem,omitempty"`
	ChainPEM            *string   `json:"chain_pem,omitempty"`
	DiscoveredVia       string    `json:"discovered_via"` // MANUAL, SCAN, CT_LOG, IMPORT, REQUESTED
	Environment         string    `json:"environment,omitempty"`
	Team                string    `json:"team,omitempty"`
	Tags                []string  `json:"tags,omitempty"`
	CreatedBy           *string   `json:"created_by,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// DeploymentTarget represents where certs are installed.
type DeploymentTarget struct {
	ID                   string     `json:"id"`
	Name                 string     `json:"name"`
	TargetType           string     `json:"target_type"` // filesystem, aws_acm, kubernetes, etc.
	ConfigEncrypted      string     `json:"-"`
	LastDeploymentAt     *time.Time `json:"last_deployment_at,omitempty"`
	LastDeploymentStatus *string    `json:"last_deployment_status,omitempty"`
	CreatedBy            *string    `json:"created_by,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// Policy represents a security/compliance policy rule.
type Policy struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Description   string    `json:"description,omitempty"`
	IsEnabled     bool      `json:"is_enabled"`
	RuleType      string    `json:"rule_type"`
	RuleConfig    string    `json:"rule_config"` // JSON string
	DomainPattern string    `json:"domain_pattern,omitempty"`
	Severity      string    `json:"severity"` // INFO, WARNING, BLOCK
	CreatedBy     *string   `json:"created_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// AuditLog represents an immutable audit log entry.
type AuditLog struct {
	ID         string    `json:"id"`
	Action     string    `json:"action"`
	EntityType string    `json:"entity_type"`
	EntityID   *string   `json:"entity_id,omitempty"`
	ActorID    *string   `json:"actor_id,omitempty"`
	ActorEmail *string   `json:"actor_email,omitempty"`
	Details    string    `json:"details,omitempty"` // JSON string
	IPAddress  *string   `json:"ip_address,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// DisplayToken is a long-lived, read-only credential for an unattended screen.
//
// It exists because a browser's EventSource cannot set an Authorization header,
// and because the alternative — an operator session left logged in on a machine
// in a corridor — carries the authority to issue, revoke, and export private
// keys. This credential carries none of that: the role it grants is hardcoded
// to viewer and the middleware refuses it on anything but a GET.
type DisplayToken struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// TokenHash is never serialized. It is not directly usable as a
	// credential, but shipping it to API clients would let anyone who can read
	// a list response confirm a guessed token offline.
	TokenHash  string     `json:"-"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	LastSeenIP *string    `json:"last_seen_ip,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RevokedBy  *string    `json:"revoked_by,omitempty"`
	CreatedBy  *string    `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Display token lifecycle states.
const (
	DisplayTokenActive  = "ACTIVE"
	DisplayTokenExpired = "EXPIRED"
	DisplayTokenRevoked = "REVOKED"
)

// Status reports the token's lifecycle state at the given instant.
//
// Revocation outranks expiry: a token that was revoked and has since also
// expired should still read as revoked, because that is the fact someone
// reviewing the list needs to see.
func (t *DisplayToken) Status(now time.Time) string {
	switch {
	case t.RevokedAt != nil:
		return DisplayTokenRevoked
	case !t.ExpiresAt.After(now):
		return DisplayTokenExpired
	default:
		return DisplayTokenActive
	}
}

// IsUsable reports whether the token may authenticate a request.
func (t *DisplayToken) IsUsable(now time.Time) bool {
	return t.Status(now) == DisplayTokenActive
}

// NotificationChannel is a destination alerts are delivered to.
type NotificationChannel struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ChannelType string `json:"channel_type"` // email, slack, webhook
	// ConfigEncrypted holds the sealed destination credentials — a Slack
	// webhook URL, an SMTP password. Never serialized, for the same reason as
	// CAAccount.ConfigEncrypted: a webhook URL is a bearer credential.
	ConfigEncrypted string `json:"-"`
	IsEnabled       bool   `json:"is_enabled"`
	// SeverityThreshold is the minimum severity this channel delivers.
	SeverityThreshold string `json:"severity_threshold"` // INFO, WARNING, CRITICAL
	// Topics restricts which event topics reach this channel. Empty means all
	// of them — a channel that matches nothing looks configured and delivers
	// nothing, which is the failure this whole subsystem exists to avoid.
	Topics     []string   `json:"topics"`
	LastSentAt *time.Time `json:"last_sent_at,omitempty"`
	CreatedBy  *string    `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// Severity ordering, lowest first. Used to compare a channel's threshold
// against an event.
var severityRank = map[string]int{
	"INFO":     0,
	"WARNING":  1,
	"CRITICAL": 2,
}

// Accepts reports whether an event of this topic and severity should be
// delivered to the channel.
//
// A channel that is disabled accepts nothing. An unrecognised severity is
// treated as CRITICAL rather than dropped: failing to deliver an alert because
// its severity was spelled unexpectedly is the worse of the two mistakes.
func (c *NotificationChannel) Accepts(topic, severity string) bool {
	if !c.IsEnabled {
		return false
	}

	rank, ok := severityRank[severity]
	if !ok {
		rank = severityRank["CRITICAL"]
	}
	threshold, ok := severityRank[c.SeverityThreshold]
	if !ok {
		threshold = severityRank["WARNING"]
	}
	if rank < threshold {
		return false
	}

	if len(c.Topics) == 0 {
		return true
	}
	for _, t := range c.Topics {
		if t == topic {
			return true
		}
	}
	return false
}

// DashboardStats holds summary statistics for the overview dashboard.
//
// The five CA counts partition the estate: every CA lands in exactly one, and
// they sum to TotalCAs. That matters more than it looks. Before this split,
// one implementation folded UNKNOWN into CriticalCAs and the other dropped it
// entirely, so the same database produced different numbers depending on which
// store was running — and a dashboard whose figures do not add up is one nobody
// trusts enough to act on.
type DashboardStats struct {
	TotalCertificates int64 `json:"total_certificates"`
	HealthyCerts      int64 `json:"healthy_certs"`
	ExpiringSoonCerts int64 `json:"expiring_soon_certs"`
	ExpiredCerts      int64 `json:"expired_certs"`
	TotalCAs          int64 `json:"total_cas"`
	HealthyCAs        int64 `json:"healthy_cas"`
	WarningCAs        int64 `json:"warning_cas"`
	CriticalCAs       int64 `json:"critical_cas"`
	ExpiredCAs        int64 `json:"expired_cas"`
	// UnknownCAs counts authorities that have never been checked, or whose
	// certificate could not be parsed. Shown rather than hidden: a CA nobody
	// can assess is not a healthy one.
	UnknownCAs int64 `json:"unknown_cas"`
	TotalScans int64 `json:"total_scans"`
}
