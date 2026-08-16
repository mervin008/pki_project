package store

import (
	"context"
	"time"
)

// Store defines all database operations for CertPilot.
type Store interface {
	// ── Certificates ────────────────────────────────────────
	ListCertificates(ctx context.Context, filter CertificateFilter) ([]*Certificate, int64, error)
	GetCertificate(ctx context.Context, id string) (*Certificate, error)
	GetCertificateByFingerprint(ctx context.Context, fingerprint string) (*Certificate, error)
	CreateCertificate(ctx context.Context, cert *Certificate) error
	UpdateCertificate(ctx context.Context, cert *Certificate) error
	DeleteCertificate(ctx context.Context, id string) error
	GetCertificatesDueForRenewal(ctx context.Context, leadDays int) ([]*Certificate, error)

	// ── CA Authorities ──────────────────────────────────────
	ListCAAuthorities(ctx context.Context) ([]*CAAuthority, error)
	GetCAAuthority(ctx context.Context, id string) (*CAAuthority, error)
	CreateCAAuthority(ctx context.Context, ca *CAAuthority) error
	UpdateCAAuthority(ctx context.Context, ca *CAAuthority) error
	DeleteCAAuthority(ctx context.Context, id string) error
	GetCAChain(ctx context.Context, id string) ([]*CAAuthority, error)

	// ── CA Accounts ─────────────────────────────────────────
	ListCAAccounts(ctx context.Context) ([]*CAAccount, error)
	GetCAAccount(ctx context.Context, id string) (*CAAccount, error)
	CreateCAAccount(ctx context.Context, acc *CAAccount) error
	UpdateCAAccount(ctx context.Context, acc *CAAccount) error
	DeleteCAAccount(ctx context.Context, id string) error

	// ── Deployment Targets ──────────────────────────────────
	ListDeploymentTargets(ctx context.Context) ([]*DeploymentTarget, error)
	GetDeploymentTarget(ctx context.Context, id string) (*DeploymentTarget, error)
	CreateDeploymentTarget(ctx context.Context, target *DeploymentTarget) error
	DeleteDeploymentTarget(ctx context.Context, id string) error

	// ── Policies ────────────────────────────────────────────
	ListPolicies(ctx context.Context) ([]*Policy, error)
	GetPolicy(ctx context.Context, id string) (*Policy, error)
	CreatePolicy(ctx context.Context, p *Policy) error
	UpdatePolicy(ctx context.Context, p *Policy) error
	DeletePolicy(ctx context.Context, id string) error

	// ── Display Tokens ──────────────────────────────────────
	ListDisplayTokens(ctx context.Context) ([]*DisplayToken, error)
	// GetDisplayTokenByHash resolves a presented token. It returns the record
	// whatever its lifecycle state — revocation and expiry are decided by the
	// caller, so that "this token was revoked" is distinguishable from "this
	// token never existed" in the logs, while both stay a flat 401 on the wire.
	GetDisplayTokenByHash(ctx context.Context, tokenHash string) (*DisplayToken, error)
	CreateDisplayToken(ctx context.Context, t *DisplayToken) error
	RevokeDisplayToken(ctx context.Context, id string, revokedBy *string) error
	// TouchDisplayToken records where and when a token was last used, so a
	// credential in use somewhere unexpected is discoverable.
	TouchDisplayToken(ctx context.Context, id string, seenAt time.Time, ip string) error

	// ── Audit Logs ──────────────────────────────────────────
	CreateAuditLog(ctx context.Context, log *AuditLog) error
	ListAuditLogs(ctx context.Context, limit, offset int) ([]*AuditLog, int64, error)

	// ── Dashboard ───────────────────────────────────────────
	GetDashboardStats(ctx context.Context) (*DashboardStats, error)

	// Lifecycle
	Close()
}

// CertificateFilter defines query filtering options for certificates.
type CertificateFilter struct {
	Status      string
	Environment string
	CommonName  string
	CAAccountID string
	Limit       int
	Offset      int
}
