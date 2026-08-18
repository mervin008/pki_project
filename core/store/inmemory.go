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
