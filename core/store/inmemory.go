package store

import (
	"context"
	"crypto/subtle"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryStore provides a thread-safe in-memory store for local testing without external database dependencies.
//
// Every read returns copies of the stored records, never the stored pointers.
// PostgresStore has no choice about this — a row scanned out of the database is
// already a copy — and the in-memory store handing out live pointers made the
// two behave differently in the one way that matters: the CA health sweep reads
// every authority and mutates it field by field, while the event stream reads
// the same records to build a snapshot. Sharing pointers between those two made
// a data race out of an ordinary dashboard refresh.
type MemoryStore struct {
	mu            sync.RWMutex
	certificates  map[string]*Certificate
	caAuthorities map[string]*CAAuthority
	caAccounts    map[string]*CAAccount
	targets       map[string]*DeploymentTarget
	policies      map[string]*Policy
	displayTokens map[string]*DisplayToken
	notifChannels map[string]*NotificationChannel
	// acks is append-only, newest last. Who acknowledged what and when is the
	// record an incident review reads, so an acknowledgement is never
	// overwritten by the next one.
	acks      []*AlertAcknowledgement
	auditLogs []*AuditLog
	// Discovery runs and their results, both append-only and newest last.
	discoveryScans     []*DiscoveryScan
	discoveryResults   []*DiscoveryResult
	discoverySchedules map[string]*DiscoverySchedule
	ctMonitors         map[string]*CTMonitor
	ctCertificates     []*CTCertificate
	cloudConnections   map[string]*CloudConnection
	cloudCertificates  []*CloudCertificate
	renewalJobs        []*RenewalJob
}

// clone returns a shallow copy of a stored record.
//
// Shallow is sufficient here. The pointer and slice fields on these models
// (*time.Time, *string, []string) are only ever replaced wholesale, never
// written through, so no caller can reach back into the store's copy.
func clone[T any](v *T) *T {
	c := *v
	return &c
}

// NewMemoryStore creates a new in-memory store pre-populated with sample demonstration data.
func NewMemoryStore() *MemoryStore {
	now := time.Now()
	rootExpiry := now.Add(3650 * 24 * time.Hour)
	interExpiry := now.Add(730 * 24 * time.Hour)
	expiringDate := now.Add(14 * 24 * time.Hour)
	validDate := now.Add(85 * 24 * time.Hour)

	rootID := uuid.New().String()
	interID := uuid.New().String()

	rootCA := &CAAuthority{
		ID:                      rootID,
		Name:                    "CertPilot Global Root CA 2026",
		CAType:                  "ROOT",
		SubjectDN:               "CN=CertPilot Global Root CA 2026, O=CertPilot OSS, C=US",
		IssuerDN:                "CN=CertPilot Global Root CA 2026, O=CertPilot OSS, C=US",
		SerialNumber:            "01a4f892bc901e88",
		NotBefore:               now.Add(-30 * 24 * time.Hour),
		NotAfter:                rootExpiry,
		DaysRemaining:           3620,
		KeyType:                 "RSA",
		KeySize:                 4096,
		FingerprintSHA256:       "a3f9e4b108c992d19f88e102bc450091884711823901eabbc38210398492019a",
		CRLDistributionURL:      "http://crl.certpilot.local/root.crl",
		OCSPResponderURL:        "http://ocsp.certpilot.local",
		IsCRLFresh:              true,
		IsOCSPResponsive:        true,
		CertificatesIssuedCount: 1420,
		Status:                  "HEALTHY",
		CreatedAt:               now,
		UpdatedAt:               now,
	}

	interCA := &CAAuthority{
		ID:                      interID,
		Name:                    "CertPilot Production Intermediate CA G1",
		CAType:                  "INTERMEDIATE",
		SubjectDN:               "CN=CertPilot Production Intermediate CA G1, O=CertPilot OSS, C=US",
		IssuerDN:                "CN=CertPilot Global Root CA 2026, O=CertPilot OSS, C=US",
		ParentCAID:              &rootID,
		SerialNumber:            "0284f183cc919a02",
		NotBefore:               now.Add(-10 * 24 * time.Hour),
		NotAfter:                interExpiry,
		DaysRemaining:           720,
		KeyType:                 "ECDSA",
		KeySize:                 384,
		FingerprintSHA256:       "c81048f02919abccde0192849102948201948291039482019482019384910294",
		CRLDistributionURL:      "http://crl.certpilot.local/intermediate.crl",
		OCSPResponderURL:        "http://ocsp.certpilot.local",
		IsCRLFresh:              true,
		IsOCSPResponsive:        true,
		CertificatesIssuedCount: 850,
		Status:                  "HEALTHY",
		CreatedAt:               now,
		UpdatedAt:               now,
	}

	accSelfSignedID := uuid.New().String()
	accSelfSigned := &CAAccount{
		ID:           accSelfSignedID,
		Name:         "selfsigned-dev",
		ProviderType: "selfsigned",
		GatewayAddr:  "localhost:9091",
		IsDefault:    true,
		Status:       "CONNECTED",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	accACMEID := uuid.New().String()
	accACME := &CAAccount{
		ID:           accACMEID,
		Name:         "letsencrypt-staging",
		ProviderType: "acme",
		GatewayAddr:  "localhost:9092",
		Status:       "CONNECTED",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	cert1ID := uuid.New().String()
	cert1 := &Certificate{
		ID:                cert1ID,
		FingerprintSHA256: "9482019482019384910294820194820194820193849102948201948201938491",
		CommonName:        "api.prod.example.com",
		SANs:              []string{"api.prod.example.com", "gateway.prod.example.com"},
		SerialNumber:      "74892019482019482",
		IssuerDN:          "CN=CertPilot Production Intermediate CA G1",
		NotBefore:         &now,
		NotAfter:          &validDate,
		DaysRemaining:     85,
		KeyType:           "RSA",
		KeySize:           2048,
		Status:            "ISSUED",
		AutoRenew:         true,
		RenewalLeadDays:   30,
		CAAccountID:       &accSelfSignedID,
		CAAuthorityID:     &interID,
		Environment:       "production",
		Team:              "Platform Engineering",
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	cert2ID := uuid.New().String()
	cert2 := &Certificate{
		ID:                cert2ID,
		FingerprintSHA256: "1029482019482019384910294820194820194820193849102948201948201938",
		CommonName:        "auth.prod.example.com",
		SANs:              []string{"auth.prod.example.com"},
		SerialNumber:      "84920194820194833",
		IssuerDN:          "CN=CertPilot Production Intermediate CA G1",
		NotBefore:         &now,
		NotAfter:          &expiringDate,
		DaysRemaining:     14,
		KeyType:           "ECDSA",
		KeySize:           256,
		Status:            "EXPIRING",
		AutoRenew:         true,
		RenewalLeadDays:   30,
		CAAccountID:       &accSelfSignedID,
		CAAuthorityID:     &interID,
		Environment:       "production",
		Team:              "Security & IAM",
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	polID := uuid.New().String()
	policy1 := &Policy{
		ID:            polID,
		Name:          "Enforce RSA >= 2048 bits",
		Description:   "Blocks certificate issuance for weak RSA keys under 2048 bits",
		IsEnabled:     true,
		RuleType:      "key_size",
		RuleConfig:    `{"min_key_size": 2048}`,
		DomainPattern: "*",
		Severity:      "BLOCK",
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	log1 := &AuditLog{
		ID:         uuid.New().String(),
		Action:     "cert.issued",
		EntityType: "certificate",
		EntityID:   &cert1ID,
		ActorEmail: strPtr("admin@certpilot.local"),
		Details:    `{"cn": "api.prod.example.com", "gateway": "selfsigned-dev"}`,
		CreatedAt:  now.Add(-2 * time.Hour),
	}

	return &MemoryStore{
		certificates: map[string]*Certificate{
			cert1ID: cert1,
			cert2ID: cert2,
		},
		caAuthorities: map[string]*CAAuthority{
			rootID:  rootCA,
			interID: interCA,
		},
		caAccounts: map[string]*CAAccount{
			accSelfSignedID: accSelfSigned,
			accACMEID:       accACME,
		},
		targets:  make(map[string]*DeploymentTarget),
		policies: map[string]*Policy{polID: policy1},
		// Deliberately empty. Every other map here carries sample data so a
		// first run has something to render, but a seeded credential is a
		// credential someone forgets to remove.
		displayTokens: make(map[string]*DisplayToken),
		// Also empty, for the same reason: a channel's config holds a Slack
		// webhook URL or an SMTP password.
		notifChannels: make(map[string]*NotificationChannel),
		auditLogs:     []*AuditLog{log1},
		// Empty: a schedule is an outbound action on a timer, and seeding one
		// would have a fresh install scanning something nobody asked it to.
		discoverySchedules: make(map[string]*DiscoverySchedule),
		// Also empty. A monitor is an outbound query on a timer, and a seeded
		// one would have a fresh install polling a public service about a
		// domain nobody asked it to watch.
		ctMonitors:       make(map[string]*CTMonitor),
		cloudConnections: make(map[string]*CloudConnection),
	}
}

func (m *MemoryStore) Close() {}

func (m *MemoryStore) ListCertificates(ctx context.Context, filter CertificateFilter) ([]*Certificate, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Certificate, 0)
	for _, c := range m.certificates {
		if filter.Status != "" && c.Status != filter.Status {
			continue
		}
		if filter.Environment != "" && c.Environment != filter.Environment {
			continue
		}
		if filter.CommonName != "" && !strings.Contains(strings.ToLower(c.CommonName), strings.ToLower(filter.CommonName)) {
			continue
		}
		// Previously ignored, while Postgres honoured it — so a filtered view
		// looked correct in development and changed meaning in production.
		if filter.CAAccountID != "" && (c.CAAccountID == nil || *c.CAAccountID != filter.CAAccountID) {
			continue
		}
		result = append(result, clone(c))
	}

	// Soonest expiry first, matching the Postgres ORDER BY. Map iteration order
	// is randomised, so without this the same request returns the same rows in
	// a different order every time.
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i].NotAfter, result[j].NotAfter
		switch {
		case a == nil && b == nil:
			return result[i].ID < result[j].ID
		case a == nil:
			return false // NULLS LAST
		case b == nil:
			return true
		case a.Equal(*b):
			return result[i].ID < result[j].ID
		default:
			return a.Before(*b)
		}
	})

	// The total is the size of the filtered set, before the page is taken.
	total := int64(len(result))
	return paginate(result, filter.Limit, filter.Offset), total, nil
}

// paginate applies limit and offset with the same defaults as PostgresStore.
func paginate[T any](items []T, limit, offset int) []T {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	if offset >= len(items) {
		return []T{}
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}

func (m *MemoryStore) GetCertificate(ctx context.Context, id string) (*Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.certificates[id]
	if !ok {
		return nil, fmt.Errorf("certificate %s not found", id)
	}
	return clone(c), nil
}

func (m *MemoryStore) GetCertificateByFingerprint(ctx context.Context, fingerprint string) (*Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.certificates {
		if c.FingerprintSHA256 == fingerprint {
			return clone(c), nil
		}
	}
	return nil, nil
}

func (m *MemoryStore) CreateCertificate(ctx context.Context, cert *Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cert.ID == "" {
		cert.ID = uuid.New().String()
	}
	now := time.Now()
	cert.CreatedAt = now
	cert.UpdatedAt = now
	if cert.NotAfter != nil {
		d := time.Until(*cert.NotAfter).Hours() / 24
		if d > 0 {
			cert.DaysRemaining = int(d)
		}
	}
	m.certificates[cert.ID] = clone(cert)
	return nil
}

func (m *MemoryStore) UpdateCertificate(ctx context.Context, cert *Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cert.UpdatedAt = time.Now()
	if cert.NotAfter != nil {
		d := time.Until(*cert.NotAfter).Hours() / 24
		if d > 0 {
			cert.DaysRemaining = int(d)
		}
	}
	stored := clone(cert)
	// Matches the COALESCE in PostgresStore.UpdateCertificate: a supplied key
	// replaces the stored one, an absent key leaves it alone. No read path
	// populates this field, so without the second half every ordinary update
	// would destroy the key.
	if stored.PrivateKeyEncrypted == nil {
		if prev, ok := m.certificates[cert.ID]; ok {
			stored.PrivateKeyEncrypted = prev.PrivateKeyEncrypted
		}
	}
	m.certificates[cert.ID] = stored
	return nil
}

func (m *MemoryStore) DeleteCertificate(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.certificates, id)
	return nil
}

func (m *MemoryStore) GetCertificatesDueForRenewal(ctx context.Context, leadDays int) ([]*Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	due := make([]*Certificate, 0)
	for _, c := range m.certificates {
		if c.AutoRenew && (c.DaysRemaining <= leadDays || c.Status == "EXPIRING" || c.Status == "RENEWAL_FAILED") {
			due = append(due, clone(c))
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i].DaysRemaining < due[j].DaysRemaining })
	return due, nil
}

func (m *MemoryStore) GetCertificatePrivateKey(ctx context.Context, id string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.certificates[id]
	if !ok {
		return "", fmt.Errorf("certificate %s not found", id)
	}
	if c.PrivateKeyEncrypted == nil {
		return "", nil
	}
	return *c.PrivateKeyEncrypted, nil
}

func (m *MemoryStore) ListCAAuthorities(ctx context.Context, filter CAFilter) ([]*CAAuthority, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	list := make([]*CAAuthority, 0)
	for _, ca := range m.caAuthorities {
		if filter.Status != "" && ca.Status != filter.Status {
			continue
		}
		// Against NotAfter, matching the Postgres predicate. Filtering on the
		// cached DaysRemaining here would have made the two stores disagree
		// about which CAs are urgent whenever a sweep was overdue.
		if filter.ExpiringWithinDays > 0 {
			cutoff := now.AddDate(0, 0, filter.ExpiringWithinDays)
			if ca.NotAfter.After(cutoff) {
				continue
			}
		}
		if filter.ExcludeExpired && !ca.NotAfter.After(now) {
			continue
		}

		c := clone(ca)
		if !filter.IncludePEM {
			c.CertificatePEM = ""
		}
		list = append(list, c)
	}

	if filter.Sort == CASortUrgency {
		sort.Slice(list, func(i, j int) bool {
			if list[i].NotAfter.Equal(list[j].NotAfter) {
				return list[i].Name < list[j].Name
			}
			return list[i].NotAfter.Before(list[j].NotAfter)
		})
	} else {
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	}
	return list, nil
}

func (m *MemoryStore) GetCAAuthority(ctx context.Context, id string) (*CAAuthority, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ca, ok := m.caAuthorities[id]
	if !ok {
		return nil, fmt.Errorf("CA authority %s not found", id)
	}
	return clone(ca), nil
}

func (m *MemoryStore) CreateCAAuthority(ctx context.Context, ca *CAAuthority) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ca.ID == "" {
		ca.ID = uuid.New().String()
	}
	now := time.Now()
	ca.CreatedAt = now
	ca.UpdatedAt = now
	m.caAuthorities[ca.ID] = clone(ca)
	return nil
}

func (m *MemoryStore) UpdateCAAuthority(ctx context.Context, ca *CAAuthority) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ca.UpdatedAt = time.Now()
	stored := clone(ca)
	// The stored PEM survives the update, because PostgresStore's UPDATE does
	// not include the column. A caller that listed without CAFilter.IncludePEM
	// holds a record whose PEM is blank; writing that back would destroy the
	// only copy of the CA certificate the system has, and the next health sweep
	// would report the CA as UNKNOWN rather than as expiring.
	if prev, ok := m.caAuthorities[ca.ID]; ok {
		stored.CertificatePEM = prev.CertificatePEM
	}
	m.caAuthorities[ca.ID] = stored
	return nil
}

func (m *MemoryStore) DeleteCAAuthority(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.caAuthorities, id)
	return nil
}

func (m *MemoryStore) GetCAChain(ctx context.Context, id string) ([]*CAAuthority, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	chain := []*CAAuthority{}
	currID := id
	visited := make(map[string]bool)

	for currID != "" && !visited[currID] {
		visited[currID] = true
		ca, ok := m.caAuthorities[currID]
		if !ok {
			break
		}
		chain = append(chain, clone(ca))
		if ca.ParentCAID != nil && *ca.ParentCAID != "" {
			currID = *ca.ParentCAID
		} else {
			break
		}
	}
	return chain, nil
}

func (m *MemoryStore) ListCAAccounts(ctx context.Context) ([]*CAAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]*CAAccount, 0, len(m.caAccounts))
	for _, acc := range m.caAccounts {
		list = append(list, clone(acc))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

func (m *MemoryStore) GetCAAccount(ctx context.Context, id string) (*CAAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	acc, ok := m.caAccounts[id]
	if ok {
		return clone(acc), nil
	}
	for _, a := range m.caAccounts {
		if a.Name == id {
			return clone(a), nil
		}
	}
	return nil, fmt.Errorf("CA account %s not found", id)
}

func (m *MemoryStore) CreateCAAccount(ctx context.Context, acc *CAAccount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if acc.ID == "" {
		acc.ID = uuid.New().String()
	}
	now := time.Now()
	acc.CreatedAt = now
	acc.UpdatedAt = now
	m.caAccounts[acc.ID] = clone(acc)
	return nil
}

func (m *MemoryStore) UpdateCAAccount(ctx context.Context, acc *CAAccount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	acc.UpdatedAt = time.Now()
	m.caAccounts[acc.ID] = clone(acc)
	return nil
}

func (m *MemoryStore) DeleteCAAccount(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.caAccounts, id)
	return nil
}

func (m *MemoryStore) ListDeploymentTargets(ctx context.Context) ([]*DeploymentTarget, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]*DeploymentTarget, 0, len(m.targets))
	for _, t := range m.targets {
		list = append(list, clone(t))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

func (m *MemoryStore) GetDeploymentTarget(ctx context.Context, id string) (*DeploymentTarget, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.targets[id]
	if !ok {
		return nil, fmt.Errorf("target %s not found", id)
	}
	return clone(t), nil
}

func (m *MemoryStore) CreateDeploymentTarget(ctx context.Context, target *DeploymentTarget) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if target.ID == "" {
		target.ID = uuid.New().String()
	}
	m.targets[target.ID] = clone(target)
	return nil
}

func (m *MemoryStore) DeleteDeploymentTarget(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.targets, id)
	return nil
}

func (m *MemoryStore) ListPolicies(ctx context.Context) ([]*Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]*Policy, 0, len(m.policies))
	for _, p := range m.policies {
		list = append(list, clone(p))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

func (m *MemoryStore) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.policies[id]
	if !ok {
		return nil, fmt.Errorf("policy %s not found", id)
	}
	return clone(p), nil
}

func (m *MemoryStore) CreatePolicy(ctx context.Context, p *Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
	m.policies[p.ID] = clone(p)
	return nil
}

func (m *MemoryStore) UpdatePolicy(ctx context.Context, p *Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p.UpdatedAt = time.Now()
	m.policies[p.ID] = clone(p)
	return nil
}

func (m *MemoryStore) DeletePolicy(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.policies, id)
	return nil
}

// ── Display Tokens ──────────────────────────────────────

func (m *MemoryStore) ListDisplayTokens(ctx context.Context) ([]*DisplayToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*DisplayToken, 0, len(m.displayTokens))
	for _, t := range m.displayTokens {
		clone := *t
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// GetDisplayTokenByHash finds a token by its hash.
//
// The comparison walks every token in constant time rather than indexing a map.
// A map lookup would return as soon as the first differing byte was found, and
// with a handful of tokens the difference is measurable; the linear scan costs
// nothing at this scale. Postgres reaches the same place by comparing a hash
// rather than the secret itself.
func (m *MemoryStore) GetDisplayTokenByHash(ctx context.Context, tokenHash string) (*DisplayToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var found *DisplayToken
	want := []byte(tokenHash)
	for _, t := range m.displayTokens {
		if subtle.ConstantTimeCompare([]byte(t.TokenHash), want) == 1 {
			found = t
		}
	}
	if found == nil {
		return nil, fmt.Errorf("display token not found")
	}
	clone := *found
	return &clone, nil
}

func (m *MemoryStore) CreateDisplayToken(ctx context.Context, t *DisplayToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, existing := range m.displayTokens {
		if existing.Name == t.Name {
			return fmt.Errorf("a display token named %q already exists", t.Name)
		}
	}
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	t.CreatedAt = time.Now()
	clone := *t
	m.displayTokens[t.ID] = &clone
	return nil
}

func (m *MemoryStore) RevokeDisplayToken(ctx context.Context, id string, revokedBy *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.displayTokens[id]
	if !ok {
		return fmt.Errorf("display token %s not found", id)
	}
	// Revoking twice is not an error. The caller wants the token dead, and it
	// is; failing here would only encourage retry loops.
	if t.RevokedAt == nil {
		now := time.Now()
		t.RevokedAt = &now
		t.RevokedBy = revokedBy
	}
	return nil
}

func (m *MemoryStore) TouchDisplayToken(ctx context.Context, id string, seenAt time.Time, ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.displayTokens[id]
	if !ok {
		return fmt.Errorf("display token %s not found", id)
	}
	t.LastSeenAt = &seenAt
	if ip != "" {
		t.LastSeenIP = &ip
	}
	return nil
}

func (m *MemoryStore) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if log.ID == "" {
		log.ID = uuid.New().String()
	}
	log.CreatedAt = time.Now()
	m.auditLogs = append([]*AuditLog{clone(log)}, m.auditLogs...)
	return nil
}

func (m *MemoryStore) ListAuditLogs(ctx context.Context, filter AuditLogFilter) ([]*AuditLog, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// m.auditLogs is already newest-first; CreateAuditLog prepends.
	matched := make([]*AuditLog, 0)
	for _, l := range m.auditLogs {
		if len(filter.Actions) > 0 && !containsString(filter.Actions, l.Action) {
			continue
		}
		if filter.EntityType != "" && l.EntityType != filter.EntityType {
			continue
		}
		if filter.EntityID != "" && (l.EntityID == nil || *l.EntityID != filter.EntityID) {
			continue
		}
		if !filter.Since.IsZero() && l.CreatedAt.Before(filter.Since) {
			continue
		}
		// A copy, and a fresh slice. This previously returned a subslice of the
		// live backing array: the caller held memory that CreateAuditLog would
		// go on to write through, so reading a returned entry raced every
		// subsequent audit write. Harmless while nothing read audit logs
		// concurrently — which stopped being true the moment the event stream
		// arrived.
		matched = append(matched, clone(l))
	}

	total := int64(len(matched))
	return paginate(matched, filter.Limit, filter.Offset), total, nil
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// ── Notification Channels ───────────────────────────────

func (m *MemoryStore) ListNotificationChannels(ctx context.Context) ([]*NotificationChannel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]*NotificationChannel, 0, len(m.notifChannels))
	for _, ch := range m.notifChannels {
		list = append(list, clone(ch))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

func (m *MemoryStore) GetNotificationChannel(ctx context.Context, id string) (*NotificationChannel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ch, ok := m.notifChannels[id]
	if !ok {
		return nil, fmt.Errorf("notification channel %s not found", id)
	}
	return clone(ch), nil
}

func (m *MemoryStore) CreateNotificationChannel(ctx context.Context, ch *NotificationChannel) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, existing := range m.notifChannels {
		if existing.Name == ch.Name {
			return fmt.Errorf("a notification channel named %q already exists", ch.Name)
		}
	}
	if ch.ID == "" {
		ch.ID = uuid.New().String()
	}
	now := time.Now()
	ch.CreatedAt = now
	ch.UpdatedAt = now
	stored := clone(ch)
	stored.Topics = normalizeTopics(ch.Topics)
	m.notifChannels[ch.ID] = stored
	return nil
}

func (m *MemoryStore) UpdateNotificationChannel(ctx context.Context, ch *NotificationChannel) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	prev, ok := m.notifChannels[ch.ID]
	if !ok {
		return fmt.Errorf("notification channel %s not found", ch.ID)
	}
	ch.UpdatedAt = time.Now()
	stored := clone(ch)
	stored.Topics = normalizeTopics(ch.Topics)
	// last_sent_at belongs to the dispatcher, matching PostgresStore.
	stored.LastSentAt = prev.LastSentAt
	m.notifChannels[ch.ID] = stored
	return nil
}

func (m *MemoryStore) DeleteNotificationChannel(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.notifChannels, id)
	return nil
}

func (m *MemoryStore) MarkNotificationChannelSent(ctx context.Context, id string, sentAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.notifChannels[id]
	if !ok {
		return fmt.Errorf("notification channel %s not found", id)
	}
	ch.LastSentAt = &sentAt
	return nil
}

func (m *MemoryStore) GetDashboardStats(ctx context.Context) (*DashboardStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	stats := &DashboardStats{
		TotalCertificates: int64(len(m.certificates)),
		TotalCAs:          int64(len(m.caAuthorities)),
	}
	// Deliberately mirrors the SQL in PostgresStore.GetDashboardStats, clause
	// for clause. The expired test comes first: previously an expired
	// certificate matched the `days_remaining <= 30` branch and was reported as
	// "expiring soon", so the dashboard showed nothing expired no matter how
	// much of the estate already had.
	for _, c := range m.certificates {
		switch {
		case c.Status == "EXPIRED" || c.DaysRemaining == 0:
			stats.ExpiredCerts++
		case c.Status == "EXPIRING" || (c.Status == "ISSUED" && c.DaysRemaining <= 30):
			stats.ExpiringSoonCerts++
		case c.Status == "ISSUED" && c.DaysRemaining > 30:
			stats.HealthyCerts++
		}
	}
	for _, ca := range m.caAuthorities {
		switch ca.Status {
		case "HEALTHY":
			stats.HealthyCAs++
		case "WARNING":
			stats.WarningCAs++
		case "CRITICAL":
			stats.CriticalCAs++
		case "EXPIRED":
			stats.ExpiredCAs++
		default:
			stats.UnknownCAs++
		}
	}
	return stats, nil
}

func strPtr(s string) *string {
	return &s
}

// ── Alert Acknowledgements ──────────────────────────────

func (m *MemoryStore) CreateAcknowledgement(ctx context.Context, ack *AlertAcknowledgement) error {
	if ack.EntityType != AckEntityCAAuthority && ack.EntityType != AckEntityCertificate {
		return fmt.Errorf("unknown acknowledgement entity type %q", ack.EntityType)
	}
	if ack.EntityID == "" {
		return fmt.Errorf("an acknowledgement needs an entity id")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if ack.ID == "" {
		ack.ID = uuid.New().String()
	}
	now := time.Now()
	if ack.AcknowledgedAt.IsZero() {
		ack.AcknowledgedAt = now
	}
	ack.CreatedAt = now

	m.acks = append(m.acks, clone(ack))
	return nil
}

func (m *MemoryStore) GetActiveAcknowledgement(ctx context.Context, entityType, entityID string) (*AlertAcknowledgement, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.newestActive(entityType, entityID), nil
}

// newestActive walks backwards, so the first un-revoked match is the newest.
// Callers must hold the lock.
func (m *MemoryStore) newestActive(entityType, entityID string) *AlertAcknowledgement {
	for i := len(m.acks) - 1; i >= 0; i-- {
		a := m.acks[i]
		if a.EntityType == entityType && a.EntityID == entityID && a.RevokedAt == nil {
			return clone(a)
		}
	}
	return nil
}

func (m *MemoryStore) ListAcknowledgements(ctx context.Context, entityType, entityID string) ([]*AlertAcknowledgement, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Copies, not the stored pointers. Returning the live records is the defect
	// ListAuditLogs shipped with: a caller holding them races every later write.
	out := make([]*AlertAcknowledgement, 0)
	for i := len(m.acks) - 1; i >= 0; i-- {
		if a := m.acks[i]; a.EntityType == entityType && a.EntityID == entityID {
			out = append(out, clone(a))
		}
	}
	return out, nil
}

func (m *MemoryStore) GetActiveAcknowledgements(ctx context.Context, entityType string, entityIDs []string) (map[string]*AlertAcknowledgement, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	wanted := make(map[string]bool, len(entityIDs))
	for _, id := range entityIDs {
		wanted[id] = true
	}

	out := make(map[string]*AlertAcknowledgement, len(entityIDs))
	for i := len(m.acks) - 1; i >= 0; i-- {
		a := m.acks[i]
		if a.EntityType != entityType || a.RevokedAt != nil || !wanted[a.EntityID] {
			continue
		}
		if _, seen := out[a.EntityID]; !seen {
			out[a.EntityID] = clone(a)
		}
	}
	return out, nil
}

func (m *MemoryStore) RevokeAcknowledgement(ctx context.Context, id string, revokedBy *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, a := range m.acks {
		if a.ID != id {
			continue
		}
		// Already revoked stays as it was: who first withdrew it is the answer
		// a review needs, not whoever pressed the button again.
		if a.RevokedAt == nil {
			now := time.Now()
			a.RevokedAt = &now
			a.RevokedBy = revokedBy
		}
		return nil
	}
	return fmt.Errorf("acknowledgement %s not found", id)
}

// ── Discovery ───────────────────────────────────────────

func (m *MemoryStore) CreateDiscoveryScan(ctx context.Context, scan *DiscoveryScan) error {
	if scan.ScanType == "" {
		return fmt.Errorf("a discovery scan needs a type")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if scan.ID == "" {
		scan.ID = uuid.New().String()
	}
	scan.CreatedAt = time.Now()
	if scan.Status == "" {
		scan.Status = ScanPending
	}
	m.discoveryScans = append(m.discoveryScans, clone(scan))
	return nil
}

func (m *MemoryStore) UpdateDiscoveryScan(ctx context.Context, scan *DiscoveryScan) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, s := range m.discoveryScans {
		if s.ID == scan.ID {
			// CreatedAt is the store's, not the caller's: a scan record that
			// could be back-dated by whoever updates it is not evidence.
			updated := clone(scan)
			updated.CreatedAt = s.CreatedAt
			m.discoveryScans[i] = updated
			return nil
		}
	}
	return fmt.Errorf("discovery scan %s not found", scan.ID)
}

func (m *MemoryStore) GetDiscoveryScan(ctx context.Context, id string) (*DiscoveryScan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.discoveryScans {
		if s.ID == id {
			return clone(s), nil
		}
	}
	return nil, fmt.Errorf("discovery scan %s not found", id)
}

func (m *MemoryStore) ListDiscoveryScans(ctx context.Context, limit, offset int) ([]*DiscoveryScan, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total := int64(len(m.discoveryScans))
	if limit <= 0 {
		limit = 50
	}

	// Newest first, which is the only order a scan history is ever read in.
	out := make([]*DiscoveryScan, 0)
	skipped := 0
	for i := len(m.discoveryScans) - 1; i >= 0; i-- {
		if skipped < offset {
			skipped++
			continue
		}
		if len(out) >= limit {
			break
		}
		out = append(out, clone(m.discoveryScans[i]))
	}
	return out, total, nil
}

func (m *MemoryStore) CreateDiscoveryResults(ctx context.Context, results []*DiscoveryResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for _, r := range results {
		if r.ScanID == "" {
			return fmt.Errorf("a discovery result needs a scan id")
		}
		if r.ID == "" {
			r.ID = uuid.New().String()
		}
		r.CreatedAt = now
		if r.ScannedAt.IsZero() {
			r.ScannedAt = now
		}
		m.discoveryResults = append(m.discoveryResults, clone(r))
	}
	return nil
}

func (m *MemoryStore) ListDiscoveryResults(ctx context.Context, filter DiscoveryResultFilter) ([]*DiscoveryResult, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	matched := make([]*DiscoveryResult, 0)
	// Walked newest first, so the first result seen for an endpoint is its
	// latest observation.
	seenEndpoint := map[string]bool{}
	for i := len(m.discoveryResults) - 1; i >= 0; i-- {
		r := m.discoveryResults[i]
		if filter.LatestPerEndpoint {
			key := endpointKey(r.Host, r.Port)
			if seenEndpoint[key] {
				continue
			}
			seenEndpoint[key] = true
		}
		if filter.ScanID != "" && r.ScanID != filter.ScanID {
			continue
		}
		if filter.ManagementState != "" && r.ManagementState != filter.ManagementState {
			continue
		}
		if filter.TrustState != "" && r.TrustState != filter.TrustState {
			continue
		}
		if filter.Host != "" && r.Host != filter.Host {
			continue
		}
		if filter.UnimportedOnly && r.IsImported {
			continue
		}
		matched = append(matched, clone(r))
	}

	total := int64(len(matched))
	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}
	if filter.Offset >= len(matched) {
		return []*DiscoveryResult{}, total, nil
	}
	end := filter.Offset + limit
	if end > len(matched) {
		end = len(matched)
	}
	return matched[filter.Offset:end], total, nil
}

func (m *MemoryStore) GetDiscoveryResult(ctx context.Context, id string) (*DiscoveryResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, r := range m.discoveryResults {
		if r.ID == id {
			return clone(r), nil
		}
	}
	return nil, fmt.Errorf("discovery result %s not found", id)
}

func (m *MemoryStore) MarkDiscoveryResultImported(ctx context.Context, id, certificateID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, r := range m.discoveryResults {
		if r.ID != id {
			continue
		}
		certID := certificateID
		r.IsImported = true
		r.ImportedCertificateID = &certID
		// Adopting a result also settles the question it was raised about: the
		// certificate is managed from this moment on, and a results list that
		// still called it unmanaged would keep asking for work already done.
		r.ManagementState = DiscoveryManaged
		r.MatchedCertificateID = &certID
		return nil
	}
	return fmt.Errorf("discovery result %s not found", id)
}

// GetLatestDiscoveryResults returns what each endpoint was last seen serving.
func (m *MemoryStore) GetLatestDiscoveryResults(ctx context.Context, endpoints []string) (map[string]*DiscoveryResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	wanted := make(map[string]bool, len(endpoints))
	for _, e := range endpoints {
		wanted[e] = true
	}
	// Empty means every endpoint, which is how the whole estate's current state
	// is asked for.
	all := len(endpoints) == 0

	out := make(map[string]*DiscoveryResult, len(endpoints))
	for i := len(m.discoveryResults) - 1; i >= 0; i-- {
		r := m.discoveryResults[i]
		key := endpointKey(r.Host, r.Port)
		if !all && !wanted[key] {
			continue
		}
		if _, seen := out[key]; !seen {
			out[key] = clone(r)
		}
	}
	return out, nil
}

func endpointKey(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

// ── Discovery schedules ─────────────────────────────────

func (m *MemoryStore) ListDiscoverySchedules(ctx context.Context) ([]*DiscoverySchedule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*DiscoverySchedule, 0, len(m.discoverySchedules))
	for _, s := range m.discoverySchedules {
		out = append(out, clone(s))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *MemoryStore) GetDiscoverySchedule(ctx context.Context, id string) (*DiscoverySchedule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if s, ok := m.discoverySchedules[id]; ok {
		return clone(s), nil
	}
	return nil, fmt.Errorf("discovery schedule %s not found", id)
}

func (m *MemoryStore) CreateDiscoverySchedule(ctx context.Context, s *DiscoverySchedule) error {
	if len(s.Targets) == 0 {
		return fmt.Errorf("a discovery schedule needs at least one target")
	}
	if s.IntervalMinutes <= 0 {
		return fmt.Errorf("a discovery schedule needs a positive interval")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	now := time.Now()
	s.CreatedAt, s.UpdatedAt = now, now
	m.discoverySchedules[s.ID] = clone(s)
	return nil
}

func (m *MemoryStore) UpdateDiscoverySchedule(ctx context.Context, s *DiscoverySchedule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.discoverySchedules[s.ID]
	if !ok {
		return fmt.Errorf("discovery schedule %s not found", s.ID)
	}
	updated := clone(s)
	updated.CreatedAt = existing.CreatedAt
	updated.UpdatedAt = time.Now()
	m.discoverySchedules[s.ID] = updated
	return nil
}

func (m *MemoryStore) DeleteDiscoverySchedule(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.discoverySchedules[id]; !ok {
		return fmt.Errorf("discovery schedule %s not found", id)
	}
	delete(m.discoverySchedules, id)
	return nil
}

func (m *MemoryStore) GetDueDiscoverySchedules(ctx context.Context, now time.Time) ([]*DiscoverySchedule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*DiscoverySchedule, 0)
	for _, s := range m.discoverySchedules {
		if s.Due(now) {
			out = append(out, clone(s))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *MemoryStore) MarkDiscoveryScheduleRun(ctx context.Context, id string, ranAt, nextRunAt time.Time, scanID *string, runErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.discoverySchedules[id]
	if !ok {
		return fmt.Errorf("discovery schedule %s not found", id)
	}
	s.LastRunAt = &ranAt
	s.NextRunAt = &nextRunAt
	s.LastError = runErr
	// A failed run keeps the previous scan id rather than clearing it: "the
	// last time this worked" is the more useful fact of the two.
	if scanID != nil {
		s.LastScanID = scanID
	}
	s.UpdatedAt = time.Now()
	return nil
}

// ── Certificate Transparency ────────────────────────────

func (m *MemoryStore) ListCTMonitors(ctx context.Context) ([]*CTMonitor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*CTMonitor, 0, len(m.ctMonitors))
	for _, mon := range m.ctMonitors {
		out = append(out, clone(mon))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}

func (m *MemoryStore) GetCTMonitor(ctx context.Context, id string) (*CTMonitor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if mon, ok := m.ctMonitors[id]; ok {
		return clone(mon), nil
	}
	return nil, fmt.Errorf("certificate transparency monitor %s not found", id)
}

func (m *MemoryStore) CreateCTMonitor(ctx context.Context, mon *CTMonitor) error {
	if strings.TrimSpace(mon.Domain) == "" {
		return fmt.Errorf("a monitor needs a domain")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, existing := range m.ctMonitors {
		if strings.EqualFold(existing.Domain, mon.Domain) {
			return fmt.Errorf("%s is already being watched", mon.Domain)
		}
	}
	if mon.ID == "" {
		mon.ID = uuid.New().String()
	}
	now := time.Now()
	mon.CreatedAt, mon.UpdatedAt = now, now
	m.ctMonitors[mon.ID] = clone(mon)
	return nil
}

func (m *MemoryStore) UpdateCTMonitor(ctx context.Context, mon *CTMonitor) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.ctMonitors[mon.ID]
	if !ok {
		return fmt.Errorf("certificate transparency monitor %s not found", mon.ID)
	}
	updated := clone(mon)
	updated.CreatedAt = existing.CreatedAt
	updated.UpdatedAt = time.Now()
	m.ctMonitors[mon.ID] = updated
	return nil
}

func (m *MemoryStore) DeleteCTMonitor(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.ctMonitors[id]; !ok {
		return fmt.Errorf("certificate transparency monitor %s not found", id)
	}
	delete(m.ctMonitors, id)

	kept := m.ctCertificates[:0]
	for _, c := range m.ctCertificates {
		if c.MonitorID != id {
			kept = append(kept, c)
		}
	}
	m.ctCertificates = kept
	return nil
}

func (m *MemoryStore) GetDueCTMonitors(ctx context.Context, now time.Time) ([]*CTMonitor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*CTMonitor, 0)
	for _, mon := range m.ctMonitors {
		if mon.Due(now) {
			out = append(out, clone(mon))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}

func (m *MemoryStore) MarkCTMonitorChecked(ctx context.Context, id string, checkedAt, nextCheckAt time.Time,
	success bool, lastEntryID *int64, seen, unmanaged int, checkErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	mon, ok := m.ctMonitors[id]
	if !ok {
		return fmt.Errorf("certificate transparency monitor %s not found", id)
	}
	mon.LastCheckedAt = &checkedAt
	mon.NextCheckAt = &nextCheckAt
	mon.LastError = checkErr
	if success {
		// Only a check that answered moves this. Everything on screen that says
		// "we are watching this domain" is really saying "we last heard from
		// the log at this time".
		mon.LastSuccessAt = &checkedAt
		if lastEntryID != nil {
			mon.LastEntryID = lastEntryID
		}
		mon.CertificatesSeen += seen
		mon.UnmanagedSeen += unmanaged
	}
	mon.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStore) RecordCTCertificates(ctx context.Context, certs []*CTCertificate) ([]*CTCertificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	known := map[string]bool{}
	for _, existing := range m.ctCertificates {
		known[ctEntryKey(existing)] = true
	}

	now := time.Now()
	added := make([]*CTCertificate, 0, len(certs))
	for _, c := range certs {
		key := ctEntryKey(c)
		if known[key] {
			continue
		}
		known[key] = true
		if c.ID == "" {
			c.ID = uuid.New().String()
		}
		if c.FirstSeenAt.IsZero() {
			c.FirstSeenAt = now
		}
		c.CreatedAt = now
		m.ctCertificates = append(m.ctCertificates, clone(c))
		added = append(added, clone(c))
	}
	return added, nil
}

func ctEntryKey(c *CTCertificate) string {
	if c.EntryID != nil {
		return fmt.Sprintf("%s/%d", c.MonitorID, *c.EntryID)
	}
	return fmt.Sprintf("%s/serial:%s", c.MonitorID, c.SerialNumber)
}

func (m *MemoryStore) ListCTCertificates(ctx context.Context, filter CTCertificateFilter) ([]*CTCertificate, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// A precertificate and its final certificate are two entries for one
	// certificate. Excluding one of them means excluding the *pre*-issuance
	// entry when the real one is also present, never the other way round.
	finalSerials := map[string]bool{}
	if filter.ExcludePrecertificates {
		for _, c := range m.ctCertificates {
			if !c.IsPrecertificate && c.SerialNumber != "" {
				finalSerials[c.SerialNumber] = true
			}
		}
	}

	matched := make([]*CTCertificate, 0)
	for i := len(m.ctCertificates) - 1; i >= 0; i-- {
		c := m.ctCertificates[i]
		if filter.MonitorID != "" && c.MonitorID != filter.MonitorID {
			continue
		}
		if filter.ManagementState != "" && c.ManagementState != filter.ManagementState {
			continue
		}
		if filter.ExcludePrecertificates && c.IsPrecertificate && finalSerials[c.SerialNumber] {
			continue
		}
		matched = append(matched, clone(c))
	}

	total := int64(len(matched))
	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}
	if filter.Offset >= len(matched) {
		return []*CTCertificate{}, total, nil
	}
	end := filter.Offset + limit
	if end > len(matched) {
		end = len(matched)
	}
	return matched[filter.Offset:end], total, nil
}

// ── Cloud inventory ─────────────────────────────────────────

func (m *MemoryStore) ListCloudConnections(ctx context.Context) ([]*CloudConnection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*CloudConnection, 0, len(m.cloudConnections))
	for _, conn := range m.cloudConnections {
		out = append(out, clone(conn))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *MemoryStore) GetCloudConnection(ctx context.Context, id string) (*CloudConnection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if conn, ok := m.cloudConnections[id]; ok {
		return clone(conn), nil
	}
	return nil, fmt.Errorf("cloud connection %s not found", id)
}

func (m *MemoryStore) CreateCloudConnection(ctx context.Context, conn *CloudConnection) error {
	if strings.TrimSpace(conn.Name) == "" {
		return fmt.Errorf("a cloud connection needs a name")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, existing := range m.cloudConnections {
		if strings.EqualFold(existing.Name, conn.Name) {
			return fmt.Errorf("a cloud connection named %q already exists", conn.Name)
		}
	}
	if conn.ID == "" {
		conn.ID = uuid.New().String()
	}
	if conn.Scopes == nil {
		conn.Scopes = []string{}
	}
	now := time.Now()
	conn.CreatedAt, conn.UpdatedAt = now, now
	m.cloudConnections[conn.ID] = clone(conn)
	return nil
}

func (m *MemoryStore) UpdateCloudConnection(ctx context.Context, conn *CloudConnection) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.cloudConnections[conn.ID]
	if !ok {
		return fmt.Errorf("cloud connection %s not found", conn.ID)
	}
	updated := clone(conn)
	// Carried over rather than taken from the caller: an edit is not a sync,
	// and the credentials are only replaced when new ones were supplied.
	updated.CreatedAt = existing.CreatedAt
	updated.UpdatedAt = time.Now()
	updated.LastSyncedAt = existing.LastSyncedAt
	updated.LastSuccessAt = existing.LastSuccessAt
	updated.NextSyncAt = existing.NextSyncAt
	updated.Scopes = existing.Scopes
	updated.CertificatesSeen = existing.CertificatesSeen
	updated.UnmanagedSeen = existing.UnmanagedSeen
	if updated.ConfigEncrypted == "" {
		updated.ConfigEncrypted = existing.ConfigEncrypted
	}
	m.cloudConnections[conn.ID] = updated
	return nil
}

func (m *MemoryStore) DeleteCloudConnection(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.cloudConnections[id]; !ok {
		return fmt.Errorf("cloud connection %s not found", id)
	}
	delete(m.cloudConnections, id)

	kept := m.cloudCertificates[:0]
	for _, c := range m.cloudCertificates {
		if c.ConnectionID != id {
			kept = append(kept, c)
		}
	}
	m.cloudCertificates = kept
	return nil
}

func (m *MemoryStore) GetDueCloudConnections(ctx context.Context, now time.Time) ([]*CloudConnection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*CloudConnection, 0)
	for _, conn := range m.cloudConnections {
		if conn.Due(now) {
			out = append(out, clone(conn))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *MemoryStore) MarkCloudConnectionSynced(ctx context.Context, id string, syncedAt, nextSyncAt time.Time,
	success bool, scopes []string, seen, unmanaged int, syncErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	conn, ok := m.cloudConnections[id]
	if !ok {
		return fmt.Errorf("cloud connection %s not found", id)
	}
	conn.LastSyncedAt = &syncedAt
	conn.NextSyncAt = &nextSyncAt
	conn.LastError = syncErr
	if success {
		// Only a sync that answered moves the success timestamp. This is the
		// whole reason there are two of them.
		conn.LastSuccessAt = &syncedAt
		conn.Scopes = append([]string{}, scopes...)
		conn.CertificatesSeen = seen
		conn.UnmanagedSeen = unmanaged
	}
	conn.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStore) UpsertCloudCertificates(ctx context.Context, certs []*CloudCertificate) ([]*CloudCertificate, error) {
	added := make([]*CloudCertificate, 0, len(certs))

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for _, c := range certs {
		var existing *CloudCertificate
		for _, stored := range m.cloudCertificates {
			if stored.ConnectionID == c.ConnectionID && stored.ResourceID == c.ResourceID {
				existing = stored
				break
			}
		}

		if existing != nil {
			first, created := existing.FirstSeenAt, existing.CreatedAt
			id := existing.ID
			imported, importedID := existing.IsImported, existing.ImportedCertificateID
			*existing = *clone(c)
			existing.ID = id
			// first_seen_at survives: a certificate that came back is the same
			// certificate returning, and when it first appeared is the part
			// worth keeping.
			existing.FirstSeenAt, existing.CreatedAt = first, created
			existing.LastSeenAt = c.LastSeenAt
			existing.RemovedAt = nil
			if imported {
				existing.IsImported, existing.ImportedCertificateID = imported, importedID
				existing.ManagementState = CloudManagedState(existing.ManagementState, true)
			}
			continue
		}

		stored := clone(c)
		if stored.ID == "" {
			stored.ID = uuid.New().String()
		}
		stored.FirstSeenAt = now
		if stored.LastSeenAt.IsZero() {
			stored.LastSeenAt = now
		}
		stored.CreatedAt = now
		m.cloudCertificates = append(m.cloudCertificates, stored)

		c.ID, c.FirstSeenAt, c.CreatedAt = stored.ID, stored.FirstSeenAt, stored.CreatedAt
		added = append(added, clone(stored))
	}
	return added, nil
}

// CloudManagedState keeps an adopted certificate managed.
//
// Exported because the two store implementations must agree on it: a sync that
// ran after somebody imported a certificate would otherwise reset the verdict
// to unmanaged and put the same work back on the list.
func CloudManagedState(state string, imported bool) string {
	if imported {
		return DiscoveryManaged
	}
	return state
}

func (m *MemoryStore) MarkCloudCertificatesRemoved(ctx context.Context, connectionID string,
	seenResourceIDs []string, at time.Time) (int, error) {
	// An empty seen list is not treated as "everything is gone". A provider
	// that answered with nothing is possible, but so is a bug, and reporting an
	// entire estate as deleted is the more expensive mistake of the two.
	if len(seenResourceIDs) == 0 {
		return 0, nil
	}

	seen := make(map[string]bool, len(seenResourceIDs))
	for _, id := range seenResourceIDs {
		seen[id] = true
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for _, c := range m.cloudCertificates {
		if c.ConnectionID != connectionID || c.RemovedAt != nil || seen[c.ResourceID] {
			continue
		}
		when := at
		c.RemovedAt = &when
		count++
	}
	return count, nil
}

func (m *MemoryStore) ListCloudCertificates(ctx context.Context, filter CloudCertificateFilter) ([]*CloudCertificate, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	matched := make([]*CloudCertificate, 0)
	for _, c := range m.cloudCertificates {
		if filter.ConnectionID != "" && c.ConnectionID != filter.ConnectionID {
			continue
		}
		if filter.ManagementState != "" && c.ManagementState != filter.ManagementState {
			continue
		}
		if !filter.IncludeRemoved && c.RemovedAt != nil {
			continue
		}
		if filter.UnimportedOnly && c.IsImported {
			continue
		}
		if filter.FindingCode != "" && !hasFinding(c.Findings, filter.FindingCode) {
			continue
		}
		matched = append(matched, clone(c))
	}

	// Soonest to expire first: the list is read to decide what to deal with
	// today, not to browse an inventory.
	sort.Slice(matched, func(i, j int) bool {
		a, b := matched[i].NotAfter, matched[j].NotAfter
		switch {
		case a == nil && b == nil:
			return matched[i].ResourceID < matched[j].ResourceID
		case a == nil:
			return false
		case b == nil:
			return true
		case a.Equal(*b):
			return matched[i].ResourceID < matched[j].ResourceID
		}
		return a.Before(*b)
	})

	total := int64(len(matched))
	return paginate(matched, filter.Limit, filter.Offset), total, nil
}

func hasFinding(findings []Finding, code string) bool {
	for _, f := range findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func (m *MemoryStore) GetCloudCertificate(ctx context.Context, id string) (*CloudCertificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, c := range m.cloudCertificates {
		if c.ID == id {
			return clone(c), nil
		}
	}
	return nil, fmt.Errorf("cloud certificate %s not found", id)
}

func (m *MemoryStore) MarkCloudCertificateImported(ctx context.Context, id, certificateID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, c := range m.cloudCertificates {
		if c.ID != id {
			continue
		}
		c.IsImported = true
		c.ImportedCertificateID = &certificateID
		c.ManagementState = DiscoveryManaged
		if c.MatchedCertificateID == nil {
			c.MatchedCertificateID = &certificateID
		}
		return nil
	}
	return fmt.Errorf("cloud certificate %s not found", id)
}

// ── Renewal queue ───────────────────────────────────────────

// maxAttemptLog bounds the history kept on one job, so a renewal retrying for
// weeks does not grow without limit. The newest are kept: what a job is doing
// now matters more than what it did a fortnight ago, and the attempt count
// survives separately.
const maxAttemptLog = 50

func (m *MemoryStore) EnqueueRenewal(ctx context.Context, job *RenewalJob) (bool, error) {
	if job.CertificateID == "" {
		return false, fmt.Errorf("a renewal job needs a certificate")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// The in-memory stand-in for the partial unique index: at most one
	// outstanding job per certificate.
	for _, existing := range m.renewalJobs {
		if existing.CertificateID == job.CertificateID && existing.Outstanding() {
			*job = *clone(existing)
			return false, nil
		}
	}

	stored := clone(job)
	if stored.ID == "" {
		stored.ID = uuid.New().String()
	}
	if stored.Status == "" {
		stored.Status = RenewalPending
	}
	if stored.Reason == "" {
		stored.Reason = RenewalReasonScheduled
	}
	if stored.RunAfter.IsZero() {
		stored.RunAfter = time.Now()
	}
	if stored.AttemptLog == nil {
		stored.AttemptLog = []RenewalAttempt{}
	}
	now := time.Now()
	stored.CreatedAt, stored.UpdatedAt = now, now

	m.renewalJobs = append(m.renewalJobs, stored)
	*job = *clone(stored)
	return true, nil
}

func (m *MemoryStore) ClaimRenewalJob(ctx context.Context, worker string, lease time.Duration, now time.Time) (*RenewalJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var best *RenewalJob
	for _, job := range m.renewalJobs {
		ready := (job.Status == RenewalPending && !job.RunAfter.After(now)) ||
			// A worker that was killed releases its job by the lease running
			// out rather than by anything having to reap it.
			(job.Status == RenewalRunning && job.LockedUntil != nil && job.LockedUntil.Before(now))
		if !ready {
			continue
		}
		if best == nil || moreUrgent(job, best) {
			best = job
		}
	}
	if best == nil {
		// An empty queue is the ordinary case, not an error.
		return nil, nil
	}

	until := now.Add(lease)
	holder := worker
	best.Status = RenewalRunning
	best.LockedBy = &holder
	best.LockedUntil = &until
	best.Attempts++
	if best.StartedAt == nil {
		started := now
		best.StartedAt = &started
	}
	best.UpdatedAt = time.Now()
	return clone(best), nil
}

// moreUrgent ranks by the deadline being raced rather than by age. A
// certificate expiring tomorrow outranks one enqueued an hour earlier with a
// month left.
func moreUrgent(a, b *RenewalJob) bool {
	switch {
	case a.NotAfter == nil && b.NotAfter == nil:
		return a.RunAfter.Before(b.RunAfter)
	case a.NotAfter == nil:
		return false
	case b.NotAfter == nil:
		return true
	case a.NotAfter.Equal(*b.NotAfter):
		return a.RunAfter.Before(b.RunAfter)
	}
	return a.NotAfter.Before(*b.NotAfter)
}

func (m *MemoryStore) ExtendRenewalLease(ctx context.Context, id, worker string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, job := range m.renewalJobs {
		if job.ID != id {
			continue
		}
		// Scoped to the holder: a worker whose lease already expired and was
		// taken by somebody else must not extend it back out from under them.
		if job.Status != RenewalRunning || job.LockedBy == nil || *job.LockedBy != worker {
			return fmt.Errorf("renewal job %s is no longer held by %s", id, worker)
		}
		when := until
		job.LockedUntil = &when
		job.UpdatedAt = time.Now()
		return nil
	}
	return fmt.Errorf("renewal job %s not found", id)
}

func (m *MemoryStore) CompleteRenewalJob(ctx context.Context, id, status string,
	attempt RenewalAttempt, runAfter time.Time, escalate bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, job := range m.renewalJobs {
		if job.ID != id {
			continue
		}
		job.Status = status
		job.LastError = attempt.Error
		job.LockedBy, job.LockedUntil = nil, nil

		log := append(append([]RenewalAttempt{}, job.AttemptLog...), attempt)
		if len(log) > maxAttemptLog {
			log = log[len(log)-maxAttemptLog:]
		}
		job.AttemptLog = log

		if status == RenewalPending {
			job.RunAfter = runAfter
		} else {
			done := time.Now()
			job.CompletedAt = &done
		}
		if escalate && job.EscalatedAt == nil {
			// Set once and left: when a job first became somebody's problem is
			// more useful than when it most recently was.
			when := time.Now()
			job.EscalatedAt = &when
		}
		job.UpdatedAt = time.Now()
		return nil
	}
	return fmt.Errorf("renewal job %s not found", id)
}

func (m *MemoryStore) GetRenewalJob(ctx context.Context, id string) (*RenewalJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, job := range m.renewalJobs {
		if job.ID == id {
			return clone(job), nil
		}
	}
	return nil, fmt.Errorf("renewal job %s not found", id)
}

func (m *MemoryStore) ListRenewalJobs(ctx context.Context, filter RenewalJobFilter) ([]*RenewalJob, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	matched := make([]*RenewalJob, 0)
	for _, job := range m.renewalJobs {
		if filter.CertificateID != "" && job.CertificateID != filter.CertificateID {
			continue
		}
		if filter.Status != "" && job.Status != filter.Status {
			continue
		}
		if filter.OutstandingOnly && !job.Outstanding() {
			continue
		}
		if filter.EscalatedOnly && job.EscalatedAt == nil {
			continue
		}
		matched = append(matched, clone(job))
	}

	// The same order the workers claim in, so the screen agrees with what is
	// actually happening next.
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].NotAfter != nil && matched[j].NotAfter != nil &&
			!matched[i].NotAfter.Equal(*matched[j].NotAfter) {
			return matched[i].NotAfter.Before(*matched[j].NotAfter)
		}
		if (matched[i].NotAfter == nil) != (matched[j].NotAfter == nil) {
			return matched[j].NotAfter == nil
		}
		return matched[i].CreatedAt.After(matched[j].CreatedAt)
	})

	total := int64(len(matched))
	return paginate(matched, filter.Limit, filter.Offset), total, nil
}

func (m *MemoryStore) CancelRenewalJob(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, job := range m.renewalJobs {
		if job.ID != id {
			continue
		}
		if !job.Outstanding() {
			return fmt.Errorf("renewal job %s is not outstanding", id)
		}
		job.Status = RenewalCancelled
		job.LockedBy, job.LockedUntil = nil, nil
		done := time.Now()
		job.CompletedAt = &done
		job.UpdatedAt = done
		return nil
	}
	return fmt.Errorf("renewal job %s is not outstanding", id)
}
