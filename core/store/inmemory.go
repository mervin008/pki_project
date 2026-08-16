package store

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryStore provides a thread-safe in-memory store for local testing without external database dependencies.
type MemoryStore struct {
	mu            sync.RWMutex
	certificates  map[string]*Certificate
	caAuthorities map[string]*CAAuthority
	caAccounts    map[string]*CAAccount
	targets       map[string]*DeploymentTarget
	policies      map[string]*Policy
	auditLogs     []*AuditLog
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
		targets:   make(map[string]*DeploymentTarget),
		policies:  map[string]*Policy{polID: policy1},
		auditLogs: []*AuditLog{log1},
	}
}

func (m *MemoryStore) Close() {}

func (m *MemoryStore) ListCertificates(ctx context.Context, filter CertificateFilter) ([]*Certificate, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Certificate
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
		result = append(result, c)
	}

	return result, int64(len(result)), nil
}

func (m *MemoryStore) GetCertificate(ctx context.Context, id string) (*Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.certificates[id]
	if !ok {
		return nil, fmt.Errorf("certificate %s not found", id)
	}
	return c, nil
}

func (m *MemoryStore) GetCertificateByFingerprint(ctx context.Context, fingerprint string) (*Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.certificates {
		if c.FingerprintSHA256 == fingerprint {
			return c, nil
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
	m.certificates[cert.ID] = cert
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
	m.certificates[cert.ID] = cert
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
	var due []*Certificate
	for _, c := range m.certificates {
		if c.AutoRenew && (c.DaysRemaining <= leadDays || c.Status == "EXPIRING" || c.Status == "RENEWAL_FAILED") {
			due = append(due, c)
		}
	}
	return due, nil
}

func (m *MemoryStore) ListCAAuthorities(ctx context.Context) ([]*CAAuthority, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var list []*CAAuthority
	for _, ca := range m.caAuthorities {
		list = append(list, ca)
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
	return ca, nil
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
	m.caAuthorities[ca.ID] = ca
	return nil
}

func (m *MemoryStore) UpdateCAAuthority(ctx context.Context, ca *CAAuthority) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ca.UpdatedAt = time.Now()
	m.caAuthorities[ca.ID] = ca
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
	var chain []*CAAuthority
	currID := id
	visited := make(map[string]bool)

	for currID != "" && !visited[currID] {
		visited[currID] = true
		ca, ok := m.caAuthorities[currID]
		if !ok {
			break
		}
		chain = append(chain, ca)
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
	var list []*CAAccount
	for _, acc := range m.caAccounts {
		list = append(list, acc)
	}
	return list, nil
}

func (m *MemoryStore) GetCAAccount(ctx context.Context, id string) (*CAAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	acc, ok := m.caAccounts[id]
	if ok {
		return acc, nil
	}
	for _, a := range m.caAccounts {
		if a.Name == id {
			return a, nil
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
	m.caAccounts[acc.ID] = acc
	return nil
}

func (m *MemoryStore) UpdateCAAccount(ctx context.Context, acc *CAAccount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	acc.UpdatedAt = time.Now()
	m.caAccounts[acc.ID] = acc
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
	var list []*DeploymentTarget
	for _, t := range m.targets {
		list = append(list, t)
	}
	return list, nil
}

func (m *MemoryStore) GetDeploymentTarget(ctx context.Context, id string) (*DeploymentTarget, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.targets[id]
	if !ok {
		return nil, fmt.Errorf("target %s not found", id)
	}
	return t, nil
}

func (m *MemoryStore) CreateDeploymentTarget(ctx context.Context, target *DeploymentTarget) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if target.ID == "" {
		target.ID = uuid.New().String()
	}
	m.targets[target.ID] = target
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
	var list []*Policy
	for _, p := range m.policies {
		list = append(list, p)
	}
	return list, nil
}

func (m *MemoryStore) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.policies[id]
	if !ok {
		return nil, fmt.Errorf("policy %s not found", id)
	}
	return p, nil
}

func (m *MemoryStore) CreatePolicy(ctx context.Context, p *Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
	m.policies[p.ID] = p
	return nil
}

func (m *MemoryStore) UpdatePolicy(ctx context.Context, p *Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p.UpdatedAt = time.Now()
	m.policies[p.ID] = p
	return nil
}

func (m *MemoryStore) DeletePolicy(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.policies, id)
	return nil
}

func (m *MemoryStore) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if log.ID == "" {
		log.ID = uuid.New().String()
	}
	log.CreatedAt = time.Now()
	m.auditLogs = append([]*AuditLog{log}, m.auditLogs...)
	return nil
}

func (m *MemoryStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]*AuditLog, int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	total := int64(len(m.auditLogs))
	if offset >= len(m.auditLogs) {
		return []*AuditLog{}, total, nil
	}
	end := offset + limit
	if end > len(m.auditLogs) {
		end = len(m.auditLogs)
	}
	return m.auditLogs[offset:end], total, nil
}

func (m *MemoryStore) GetDashboardStats(ctx context.Context) (*DashboardStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	stats := &DashboardStats{
		TotalCertificates: int64(len(m.certificates)),
		TotalCAs:          int64(len(m.caAuthorities)),
	}
	for _, c := range m.certificates {
		if c.Status == "ISSUED" && c.DaysRemaining > 30 {
			stats.HealthyCerts++
		} else if c.Status == "EXPIRING" || c.DaysRemaining <= 30 {
			stats.ExpiringSoonCerts++
		} else if c.Status == "EXPIRED" {
			stats.ExpiredCerts++
		}
	}
	for _, ca := range m.caAuthorities {
		if ca.Status == "HEALTHY" {
			stats.HealthyCAs++
		} else if ca.Status == "WARNING" {
			stats.WarningCAs++
		} else {
			stats.CriticalCAs++
		}
	}
	return stats, nil
}

func strPtr(s string) *string {
	return &s
}
