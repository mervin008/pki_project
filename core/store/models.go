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

// Discovery scan types, matching the check constraint on discovery_scans.
const (
	ScanTypeNetwork = "network"
	ScanTypeCTLog   = "ct_log"
	ScanTypeCloud   = "cloud"
)

// Discovery scan lifecycle states.
const (
	ScanPending   = "PENDING"
	ScanRunning   = "RUNNING"
	ScanCompleted = "COMPLETED"
	ScanFailed    = "FAILED"
)

// Whether CertPilot already knows about a discovered certificate.
//
// This is the verdict discovery exists to produce. A scan of a real estate
// returns mostly certificates the team issued itself; the rows that matter are
// the ones it did not.
const (
	// DiscoveryManaged means the served certificate's fingerprint matches a
	// row in `certificates`.
	DiscoveryManaged = "MANAGED"
	// DiscoveryUnmanaged means it does not. Something is serving TLS with a
	// certificate this system has never seen, and nothing will renew it.
	DiscoveryUnmanaged = "UNMANAGED"
	// DiscoveryUnreachable means the endpoint did not complete a TLS
	// handshake, so there is no certificate to judge.
	DiscoveryUnreachable = "UNREACHABLE"
)

// What the served chain terminates in.
const (
	// TrustPublic — verifies against the host's public root store.
	TrustPublic = "PUBLIC"
	// TrustInternal — verifies against a CA registered in CertPilot. This is
	// the normal answer inside an organisation running private PKI, and it is
	// the one that ties an endpoint to a CA whose expiry is being watched.
	TrustInternal = "INTERNAL"
	// TrustSelfSigned — the leaf signed itself. Common on appliances and
	// forgotten test rigs, and a fair description of "nobody is managing this".
	TrustSelfSigned = "SELF_SIGNED"
	// TrustUntrusted — chains to neither. Either an intermediate is missing
	// from the served chain, or the issuing CA is one nobody has registered.
	TrustUntrusted = "UNTRUSTED"
	// TrustUnknown — not established, because the endpoint was unreachable.
	TrustUnknown = "UNKNOWN"
)

// Finding is one thing wrong with a discovered endpoint.
//
// Stored with the result rather than recomputed on read. A result is a record
// of what was observed at a moment; deriving findings at read time would mean a
// scan from March silently re-judged by today's rules, against a certificate
// that has since been replaced.
type Finding struct {
	// Code is a stable machine-readable identifier, e.g. "hostname_mismatch".
	Code string `json:"code"`
	// Severity is INFO, WARNING, or CRITICAL — the same vocabulary the event
	// stream and the notification channels use, so a finding can be routed
	// without translation.
	Severity string `json:"severity"`
	// Detail is a sentence someone can act on, naming the specific values
	// involved. "RSA-1024" beats "weak key".
	Detail string `json:"detail"`
}

// DiscoveryScan is one run of the scanner over a set of targets.
type DiscoveryScan struct {
	ID       string `json:"id"`
	ScanType string `json:"scan_type"`
	// Targets is what was asked for, as given. Kept verbatim so a scan can be
	// repeated and so an unexpected result can be traced back to the input
	// that produced it.
	Targets      []string `json:"targets"`
	Status       string   `json:"status"`
	ResultsCount int      `json:"results_count"`
	// The three counts partition ResultsCount. UnmanagedCount is the headline:
	// it is the number a PKI team reads first and the only one that implies
	// work.
	UnmanagedCount   int        `json:"unmanaged_count"`
	ManagedCount     int        `json:"managed_count"`
	UnreachableCount int        `json:"unreachable_count"`
	StartedAt        *time.Time `json:"started_at,omitempty"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	Error            string     `json:"error,omitempty"`
	TriggeredBy      *string    `json:"triggered_by,omitempty"`
	ActorEmail       *string    `json:"actor_email,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// DiscoveryResult is what one endpoint was serving when it was asked.
type DiscoveryResult struct {
	ID     string `json:"id"`
	ScanID string `json:"scan_id"`
	Host   string `json:"host"`
	Port   int    `json:"port"`

	// Reachable is false when no TLS handshake completed. Error then carries
	// the dialler's own words — "connection refused" and "certificate signed
	// by unknown authority" are different problems and only one of them is
	// about certificates.
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`

	ManagementState string `json:"management_state"`
	TrustState      string `json:"trust_state"`
	// MatchedCertificateID names the managed certificate this fingerprint
	// belongs to, when there is one.
	MatchedCertificateID *string `json:"matched_certificate_id,omitempty"`

	CommonName        string     `json:"common_name,omitempty"`
	SubjectDN         string     `json:"subject_dn,omitempty"`
	SANs              []string   `json:"sans"`
	IssuerDN          string     `json:"issuer_dn,omitempty"`
	SerialNumber      string     `json:"serial_number,omitempty"`
	NotBefore         *time.Time `json:"not_before,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	KeyType           string     `json:"key_type,omitempty"`
	KeySize           int        `json:"key_size,omitempty"`
	IsCA              bool       `json:"is_ca"`
	FingerprintSHA256 string     `json:"fingerprint_sha256,omitempty"`
	CertificatePEM    string     `json:"certificate_pem,omitempty"`
	ChainPEM          string     `json:"chain_pem,omitempty"`
	// ChainLength is how many certificates the server sent, leaf included. One
	// means it sent no intermediates, which works only for clients that
	// already happen to hold them.
	ChainLength int `json:"chain_length"`

	TLSVersion  string `json:"tls_version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	// KeyExchange is the negotiated group, e.g. "X25519MLKEM768". Recorded on
	// every scan because it is unrecoverable afterwards and is the basis of
	// any later answer about quantum readiness.
	KeyExchange string `json:"key_exchange,omitempty"`
	ALPN        string `json:"alpn,omitempty"`

	Findings []Finding `json:"findings"`

	IsImported            bool      `json:"is_imported"`
	ImportedCertificateID *string   `json:"imported_certificate_id,omitempty"`
	ScannedAt             time.Time `json:"scanned_at"`
	CreatedAt             time.Time `json:"created_at"`
}

// WorstSeverity returns the highest severity among the result's findings, or
// "" when there are none. Used to sort a result list by how much attention it
// needs rather than by hostname.
func (r *DiscoveryResult) WorstSeverity() string {
	worst := ""
	worstRank := -1
	for _, f := range r.Findings {
		rank, ok := severityRank[f.Severity]
		if !ok {
			continue
		}
		if rank > worstRank {
			worstRank, worst = rank, f.Severity
		}
	}
	return worst
}

// DiscoveryResultFilter narrows a result list.
type DiscoveryResultFilter struct {
	// ScanID restricts to one run. Empty means across every scan, which is how
	// "everything unmanaged we have ever found" is asked.
	ScanID string
	// ManagementState is MANAGED, UNMANAGED, or UNREACHABLE.
	ManagementState string
	// TrustState is PUBLIC, INTERNAL, SELF_SIGNED, UNTRUSTED, or UNKNOWN.
	TrustState string
	// Host matches exactly.
	Host string
	// UnimportedOnly hides results someone has already adopted into inventory.
	UnimportedOnly bool
	Limit          int
	Offset         int
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
