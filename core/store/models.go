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
	Tags                    string     `json:"tags,omitempty"`
	Notes                   string     `json:"notes,omitempty"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
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

// DashboardStats holds summary statistics for the overview dashboard.
type DashboardStats struct {
	TotalCertificates int64 `json:"total_certificates"`
	HealthyCerts      int64 `json:"healthy_certs"`
	ExpiringSoonCerts int64 `json:"expiring_soon_certs"`
	ExpiredCerts      int64 `json:"expired_certs"`
	TotalCAs          int64 `json:"total_cas"`
	HealthyCAs        int64 `json:"healthy_cas"`
	WarningCAs        int64 `json:"warning_cas"`
	CriticalCAs       int64 `json:"critical_cas"`
	TotalScans        int64 `json:"total_scans"`
}
