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
	// GetCertificatePrivateKey reads the sealed private key for one
	// certificate, and is the only way to obtain it.
	//
	// Deliberately not a field on the records the other readers return: those
	// run on every dashboard refresh, and a secret that is loaded constantly is
	// a secret that eventually gets logged, cached, or serialized by accident.
	// Returns "" when no key is stored, which is the normal case for imported,
	// discovered, and CSR-based certificates.
	GetCertificatePrivateKey(ctx context.Context, id string) (string, error)

	// ── CA Authorities ──────────────────────────────────────
	ListCAAuthorities(ctx context.Context, filter CAFilter) ([]*CAAuthority, error)
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

	// ── Notification Channels ───────────────────────────────
	ListNotificationChannels(ctx context.Context) ([]*NotificationChannel, error)
	GetNotificationChannel(ctx context.Context, id string) (*NotificationChannel, error)
	CreateNotificationChannel(ctx context.Context, ch *NotificationChannel) error
	UpdateNotificationChannel(ctx context.Context, ch *NotificationChannel) error
	DeleteNotificationChannel(ctx context.Context, id string) error
	// MarkNotificationChannelSent records a successful delivery. Separate from
	// UpdateNotificationChannel so the dispatcher, which runs concurrently with
	// whoever is editing the channel, cannot write back a stale configuration
	// as a side effect of recording that a message went out.
	MarkNotificationChannelSent(ctx context.Context, id string, sentAt time.Time) error

	// ── Alert Acknowledgements ──────────────────────────────

	// CreateAcknowledgement records that a human has seen an alert.
	CreateAcknowledgement(ctx context.Context, ack *AlertAcknowledgement) error
	// GetActiveAcknowledgement returns the newest un-revoked acknowledgement
	// for an entity, or nil when there is none.
	//
	// Returns the record regardless of threshold, because whether it still
	// applies is a decision only the caller can make — it depends on which
	// threshold the alert is being raised at, and AlertAcknowledgement.IsActive
	// is where that comparison lives.
	GetActiveAcknowledgement(ctx context.Context, entityType, entityID string) (*AlertAcknowledgement, error)
	// ListAcknowledgements returns the history for an entity, newest first,
	// including revoked ones. Who acknowledged what and when is what an
	// incident review reads.
	ListAcknowledgements(ctx context.Context, entityType, entityID string) ([]*AlertAcknowledgement, error)
	// GetActiveAcknowledgements resolves acknowledgements for many entities in
	// one query, so the CA list does not issue one per row.
	GetActiveAcknowledgements(ctx context.Context, entityType string, entityIDs []string) (map[string]*AlertAcknowledgement, error)
	// RevokeAcknowledgement withdraws one, keeping the record that it was made.
	RevokeAcknowledgement(ctx context.Context, id string, revokedBy *string) error

	// ── Discovery ───────────────────────────────────────────

	// CreateDiscoveryScan records a run before it starts, so a scan that
	// crashes halfway leaves evidence that it was attempted.
	CreateDiscoveryScan(ctx context.Context, scan *DiscoveryScan) error
	// UpdateDiscoveryScan writes the outcome: status, counts, completion.
	UpdateDiscoveryScan(ctx context.Context, scan *DiscoveryScan) error
	GetDiscoveryScan(ctx context.Context, id string) (*DiscoveryScan, error)
	ListDiscoveryScans(ctx context.Context, limit, offset int) ([]*DiscoveryScan, int64, error)
	// CreateDiscoveryResults writes a run's findings in one call. Batched
	// because a scan produces one row per endpoint and a per-row round trip
	// would make the write slower than the scanning.
	CreateDiscoveryResults(ctx context.Context, results []*DiscoveryResult) error
	ListDiscoveryResults(ctx context.Context, filter DiscoveryResultFilter) ([]*DiscoveryResult, int64, error)
	GetDiscoveryResult(ctx context.Context, id string) (*DiscoveryResult, error)
	// MarkDiscoveryResultImported links a result to the certificate someone
	// adopted it into, so the same endpoint stops being reported as an
	// unmanaged finding on the next scan.
	MarkDiscoveryResultImported(ctx context.Context, id, certificateID string) error
	// GetLatestDiscoveryResults returns what each of these endpoints was last
	// seen serving, keyed by "host:port".
	//
	// This is what makes a repeated scan worth more than the first one: the
	// value of the second run is not the list, it is the difference. Loaded in
	// one call before the run, not per endpoint during it.
	GetLatestDiscoveryResults(ctx context.Context, endpoints []string) (map[string]*DiscoveryResult, error)

	// ── Discovery schedules ─────────────────────────────────

	ListDiscoverySchedules(ctx context.Context) ([]*DiscoverySchedule, error)
	GetDiscoverySchedule(ctx context.Context, id string) (*DiscoverySchedule, error)
	CreateDiscoverySchedule(ctx context.Context, s *DiscoverySchedule) error
	UpdateDiscoverySchedule(ctx context.Context, s *DiscoverySchedule) error
	DeleteDiscoverySchedule(ctx context.Context, id string) error
	// GetDueDiscoverySchedules returns the schedules that should run now.
	GetDueDiscoverySchedules(ctx context.Context, now time.Time) ([]*DiscoverySchedule, error)
	// MarkDiscoveryScheduleRun records an attempt and moves the schedule on.
	//
	// Separate from UpdateDiscoverySchedule so the scheduler, which runs
	// concurrently with whoever is editing the schedule, cannot write back a
	// stale definition as a side effect of recording that it ran.
	MarkDiscoveryScheduleRun(ctx context.Context, id string, ranAt, nextRunAt time.Time, scanID *string, runErr string) error

	// ── Certificate Transparency ────────────────────────────

	ListCTMonitors(ctx context.Context) ([]*CTMonitor, error)
	GetCTMonitor(ctx context.Context, id string) (*CTMonitor, error)
	CreateCTMonitor(ctx context.Context, m *CTMonitor) error
	UpdateCTMonitor(ctx context.Context, m *CTMonitor) error
	DeleteCTMonitor(ctx context.Context, id string) error
	GetDueCTMonitors(ctx context.Context, now time.Time) ([]*CTMonitor, error)
	// MarkCTMonitorChecked records the outcome of one check.
	//
	// Takes `success` explicitly rather than inferring it from an error string,
	// because the two timestamps it maintains answer different questions: when
	// did we last try, and when did we last actually learn anything. A monitor
	// that has been unable to reach the log for a week must not look like one
	// that has found nothing for a week.
	MarkCTMonitorChecked(ctx context.Context, id string, checkedAt, nextCheckAt time.Time,
		success bool, lastEntryID *int64, seen, unmanaged int, checkErr string) error

	// RecordCTCertificates stores what a check found, ignoring entries already
	// known. Returns only the ones that were new, which is what an alert is
	// built from — re-reporting the same certificate every six hours is how a
	// channel gets muted.
	RecordCTCertificates(ctx context.Context, certs []*CTCertificate) ([]*CTCertificate, error)
	ListCTCertificates(ctx context.Context, filter CTCertificateFilter) ([]*CTCertificate, int64, error)

	// ── Cloud inventory ─────────────────────────────────────
	ListCloudConnections(ctx context.Context) ([]*CloudConnection, error)
	GetCloudConnection(ctx context.Context, id string) (*CloudConnection, error)
	CreateCloudConnection(ctx context.Context, conn *CloudConnection) error
	UpdateCloudConnection(ctx context.Context, conn *CloudConnection) error
	DeleteCloudConnection(ctx context.Context, id string) error
	GetDueCloudConnections(ctx context.Context, now time.Time) ([]*CloudConnection, error)
	// MarkCloudConnectionSynced records the outcome of one sync.
	//
	// syncedAt always moves; the success timestamp moves only when the provider
	// actually answered. Everything on screen that says "this account is being
	// watched" is really saying "we last heard from it at this time", and a
	// connection with expired credentials must not read as a quiet one.
	//
	// scopes is what the sync enumerated, in the provider's own words, so a
	// short result is never mistaken for a small estate.
	MarkCloudConnectionSynced(ctx context.Context, id string, syncedAt, nextSyncAt time.Time,
		success bool, scopes []string, seen, unmanaged int, syncErr string) error

	// UpsertCloudCertificates writes what a sync found, keyed on the provider's
	// own resource id. Returns only the certificates that were new to this
	// connection — an alert is built from those, because a sync every six hours
	// re-reporting the same ACM inventory is how a channel gets muted.
	UpsertCloudCertificates(ctx context.Context, certs []*CloudCertificate) ([]*CloudCertificate, error)
	// MarkCloudCertificatesRemoved flags the certificates a successful sync did
	// not find any more. Called only after a sync that answered: marking
	// everything removed because an API call failed would report an estate
	// being dismantled.
	MarkCloudCertificatesRemoved(ctx context.Context, connectionID string, seenResourceIDs []string, at time.Time) (int, error)
	ListCloudCertificates(ctx context.Context, filter CloudCertificateFilter) ([]*CloudCertificate, int64, error)
	GetCloudCertificate(ctx context.Context, id string) (*CloudCertificate, error)
	// MarkCloudCertificateImported links a cloud certificate to the inventory
	// record somebody adopted it into, and settles its verdict.
	MarkCloudCertificateImported(ctx context.Context, id, certificateID string) error

	// ── Renewal queue ───────────────────────────────────────
	//
	// Renewal is the only part of this system that changes the world, so it
	// exists as durable rows rather than as calls: a process that dies
	// mid-renewal leaves behind something another process can pick up.

	// EnqueueRenewal creates a job unless one is already outstanding for this
	// certificate.
	//
	// Returns the existing job and false when there is one. This — rather than
	// leader election — is what makes the scheduler safe to run on every
	// replica: two of them enqueueing the same renewal in the same second is a
	// no-op for the second, not a duplicate issuance against a weekly rate
	// limit.
	EnqueueRenewal(ctx context.Context, job *RenewalJob) (created bool, err error)
	// ClaimRenewalJob takes the most urgent ready job and leases it.
	//
	// Ready means pending and due, or running with an expired lease — a worker
	// that was killed releases its job by the lease running out rather than by
	// anything having to reap it. Returns nil when the queue has nothing ready,
	// which is the ordinary case and not an error.
	ClaimRenewalJob(ctx context.Context, worker string, lease time.Duration, now time.Time) (*RenewalJob, error)
	// ExtendRenewalLease keeps a long-running job's claim alive. An ACME order
	// waiting on DNS propagation can outlive a short lease, and having it
	// stolen mid-flight is how one renewal becomes two certificates.
	ExtendRenewalLease(ctx context.Context, id, worker string, until time.Time) error
	// CompleteRenewalJob records the outcome of an attempt.
	//
	// A failed attempt that will be retried stays outstanding with run_after
	// moved forward; a terminal one is closed. The attempt is appended to the
	// log either way, because the history is what distinguishes a blip from a
	// fortnight of the same error.
	CompleteRenewalJob(ctx context.Context, id string, status string, attempt RenewalAttempt,
		runAfter time.Time, escalate bool) error
	GetRenewalJob(ctx context.Context, id string) (*RenewalJob, error)
	ListRenewalJobs(ctx context.Context, filter RenewalJobFilter) ([]*RenewalJob, int64, error)
	// CancelRenewalJob stops an outstanding job. Never used for failures — a
	// renewal nobody cancelled must keep trying.
	CancelRenewalJob(ctx context.Context, id string) error
	// DeferRenewalJob puts a claimed job back without counting the claim as an
	// attempt.
	//
	// Used when a CA's rate limit has no room. A deferral is not a failure —
	// nothing was tried — and recording it as one would inflate the attempt
	// count and escalate a certificate that is not broken.
	DeferRenewalJob(ctx context.Context, id string, runAfter time.Time, reason string, escalate bool) error
	// CountRecentRenewals reports how many renewals this CA account has
	// completed inside the window, and when the oldest of them ages out of it.
	//
	// Counted in the database rather than per process: N replicas each holding
	// their own token bucket would allow N times the limit, which for a public
	// CA means the whole organisation loses issuance for a week.
	CountRecentRenewals(ctx context.Context, caAccountID string, since time.Time) (count int, oldest *time.Time, err error)

	// ── Audit Logs ──────────────────────────────────────────
	CreateAuditLog(ctx context.Context, log *AuditLog) error
	ListAuditLogs(ctx context.Context, filter AuditLogFilter) ([]*AuditLog, int64, error)

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

// CA list sort orders.
const (
	// CASortUrgency puts the CA closest to expiry first. This is the order the
	// health view is built on: the question a PKI team asks a wall display is
	// "what breaks first", and a list sorted by name buries that answer
	// somewhere in the middle.
	CASortUrgency = "urgency"
	// CASortName is alphabetical, for the inventory view where someone is
	// looking for a specific CA rather than for trouble.
	CASortName = "name"
)

// CAFilter defines query filtering options for CA authorities.
type CAFilter struct {
	// Status matches exactly: HEALTHY, WARNING, CRITICAL, EXPIRED, UNKNOWN.
	Status string
	// ExpiringWithinDays keeps only CAs whose certificate expires within the
	// window. Zero means no window.
	//
	// Evaluated against not_after rather than the stored days_remaining
	// column: days_remaining is a snapshot written by the health sweep and is
	// wrong by however long it has been since the last one. A filter that
	// reports yesterday's urgency on a dashboard defeats the purpose.
	ExpiringWithinDays int
	// IncludeExpired controls whether already-expired CAs pass the
	// ExpiringWithinDays window. They do by default — an expired issuing CA is
	// the most urgent row on the screen, not one to filter out for having gone
	// past zero.
	ExcludeExpired bool
	// Sort is CASortUrgency or CASortName. Empty means CASortName.
	Sort string

	// IncludePEM asks for the certificate_pem column.
	//
	// Off by default: it is several kilobytes per CA, no dashboard renders it,
	// and the event-stream snapshot that carries this data is re-sent on every
	// client reconnect and every resynchronise. Only the health sweep, which
	// re-parses the certificate, needs it.
	IncludePEM bool
}

// AuditLogFilter defines query filtering options for audit log entries.
//
// Filtering exists chiefly so CA alerts are reachable. They share a table with
// every certificate issued, and at the issuance rates 47-day certificates imply
// a day's routine traffic buries a week of expiry warnings.
type AuditLogFilter struct {
	// Actions matches any of the listed actions. Empty means all of them.
	Actions []string
	// EntityType and EntityID narrow to one object's history.
	EntityType string
	EntityID   string
	// Since keeps entries at or after this instant. Zero means no lower bound.
	Since time.Time
	Limit int
	// Offset paginates. Note that new entries arrive at the head, so a deep
	// offset walked slowly will re-show rows; for a feed, filter by Since.
	Offset int
}
