package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implements Store using pgxpool for PostgreSQL.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore connects to PostgreSQL using the provided connection string.
func NewPostgresStore(ctx context.Context, connStr string) (*PostgresStore, error) {
	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse postgres config: %w", err)
	}

	config.MaxConns = 25
	config.MinConns = 2
	config.MaxConnLifetime = 1 * time.Hour
	config.MaxConnIdleTime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test ping
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping postgres: %w", err)
	}

	slog.Info("connected to PostgreSQL/Supabase database")
	return &PostgresStore{pool: pool}, nil
}

// Close terminates all pool connections.
func (s *PostgresStore) Close() {
	s.pool.Close()
}

// ── Certificates ────────────────────────────────────────

func (s *PostgresStore) ListCertificates(ctx context.Context, filter CertificateFilter) ([]*Certificate, int64, error) {
	where := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if filter.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, filter.Status)
		argIdx++
	}
	if filter.Environment != "" {
		where = append(where, fmt.Sprintf("environment = $%d", argIdx))
		args = append(args, filter.Environment)
		argIdx++
	}
	if filter.CommonName != "" {
		where = append(where, fmt.Sprintf("common_name ILIKE $%d", argIdx))
		args = append(args, "%"+filter.CommonName+"%")
		argIdx++
	}
	if filter.CAAccountID != "" {
		where = append(where, fmt.Sprintf("ca_account_id = $%d", argIdx))
		args = append(args, filter.CAAccountID)
		argIdx++
	}

	whereClause := strings.Join(where, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM public.certificates WHERE %s", whereClause)
	var total int64
	if err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Fetch items
	limit := 50
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Offset > 0 {
		offset = filter.Offset
	}

	query := fmt.Sprintf(`
		SELECT id, fingerprint_sha256, common_name, sans, serial_number, issuer_dn,
		       not_before, not_after, days_remaining, key_type, key_size, status,
		       auto_renew, renewal_lead_days, last_renewal_attempt, renewal_error, renewal_count,
		       ca_account_id, ca_authority_id, deployment_target_id, certificate_pem, chain_pem,
		       discovered_via, environment, team, tags, created_by, created_at, updated_at
		FROM public.certificates
		WHERE %s
		ORDER BY not_after ASC NULLS LAST
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var certs []*Certificate
	for rows.Next() {
		cert := &Certificate{}
		var sansJSON, tagsJSON []byte
		err := rows.Scan(
			&cert.ID, &cert.FingerprintSHA256, &cert.CommonName, &sansJSON, &cert.SerialNumber, &cert.IssuerDN,
			&cert.NotBefore, &cert.NotAfter, &cert.DaysRemaining, &cert.KeyType, &cert.KeySize, &cert.Status,
			&cert.AutoRenew, &cert.RenewalLeadDays, &cert.LastRenewalAttempt, &cert.RenewalError, &cert.RenewalCount,
			&cert.CAAccountID, &cert.CAAuthorityID, &cert.DeploymentTargetID, &cert.CertificatePEM, &cert.ChainPEM,
			&cert.DiscoveredVia, &cert.Environment, &cert.Team, &tagsJSON, &cert.CreatedBy, &cert.CreatedAt, &cert.UpdatedAt,
		)
		if err != nil {
			return nil, 0, err
		}
		if len(sansJSON) > 0 {
			_ = json.Unmarshal(sansJSON, &cert.SANs)
		}
		if len(tagsJSON) > 0 {
			_ = json.Unmarshal(tagsJSON, &cert.Tags)
		}
		certs = append(certs, cert)
	}

	return certs, total, nil
}

func (s *PostgresStore) GetCertificate(ctx context.Context, id string) (*Certificate, error) {
	query := `
		SELECT id, fingerprint_sha256, common_name, sans, serial_number, issuer_dn,
		       not_before, not_after, days_remaining, key_type, key_size, status,
		       auto_renew, renewal_lead_days, last_renewal_attempt, renewal_error, renewal_count,
		       ca_account_id, ca_authority_id, deployment_target_id, certificate_pem, chain_pem,
		       discovered_via, environment, team, tags, created_by, created_at, updated_at
		FROM public.certificates WHERE id = $1
	`
	cert := &Certificate{}
	var sansJSON, tagsJSON []byte
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&cert.ID, &cert.FingerprintSHA256, &cert.CommonName, &sansJSON, &cert.SerialNumber, &cert.IssuerDN,
		&cert.NotBefore, &cert.NotAfter, &cert.DaysRemaining, &cert.KeyType, &cert.KeySize, &cert.Status,
		&cert.AutoRenew, &cert.RenewalLeadDays, &cert.LastRenewalAttempt, &cert.RenewalError, &cert.RenewalCount,
		&cert.CAAccountID, &cert.CAAuthorityID, &cert.DeploymentTargetID, &cert.CertificatePEM, &cert.ChainPEM,
		&cert.DiscoveredVia, &cert.Environment, &cert.Team, &tagsJSON, &cert.CreatedBy, &cert.CreatedAt, &cert.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("certificate %s not found", id)
	}
	if err != nil {
		return nil, err
	}
	if len(sansJSON) > 0 {
		_ = json.Unmarshal(sansJSON, &cert.SANs)
	}
	if len(tagsJSON) > 0 {
		_ = json.Unmarshal(tagsJSON, &cert.Tags)
	}
	return cert, nil
}

func (s *PostgresStore) GetCertificateByFingerprint(ctx context.Context, fingerprint string) (*Certificate, error) {
	query := `
		SELECT id, fingerprint_sha256, common_name, sans, serial_number, issuer_dn,
		       not_before, not_after, days_remaining, key_type, key_size, status,
		       auto_renew, renewal_lead_days, last_renewal_attempt, renewal_error, renewal_count,
		       ca_account_id, ca_authority_id, deployment_target_id, certificate_pem, chain_pem,
		       discovered_via, environment, team, tags, created_by, created_at, updated_at
		FROM public.certificates WHERE fingerprint_sha256 = $1
	`
	cert := &Certificate{}
	var sansJSON, tagsJSON []byte
	err := s.pool.QueryRow(ctx, query, fingerprint).Scan(
		&cert.ID, &cert.FingerprintSHA256, &cert.CommonName, &sansJSON, &cert.SerialNumber, &cert.IssuerDN,
		&cert.NotBefore, &cert.NotAfter, &cert.DaysRemaining, &cert.KeyType, &cert.KeySize, &cert.Status,
		&cert.AutoRenew, &cert.RenewalLeadDays, &cert.LastRenewalAttempt, &cert.RenewalError, &cert.RenewalCount,
		&cert.CAAccountID, &cert.CAAuthorityID, &cert.DeploymentTargetID, &cert.CertificatePEM, &cert.ChainPEM,
		&cert.DiscoveredVia, &cert.Environment, &cert.Team, &tagsJSON, &cert.CreatedBy, &cert.CreatedAt, &cert.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(sansJSON) > 0 {
		_ = json.Unmarshal(sansJSON, &cert.SANs)
	}
	if len(tagsJSON) > 0 {
		_ = json.Unmarshal(tagsJSON, &cert.Tags)
	}
	return cert, nil
}

func (s *PostgresStore) CreateCertificate(ctx context.Context, cert *Certificate) error {
	sansJSON, _ := json.Marshal(cert.SANs)
	tagsJSON, _ := json.Marshal(cert.Tags)

	// Calculate days remaining
	daysRemaining := 0
	if cert.NotAfter != nil {
		d := time.Until(*cert.NotAfter).Hours() / 24
		if d > 0 {
			daysRemaining = int(d)
		}
	}
	cert.DaysRemaining = daysRemaining

	query := `
		INSERT INTO public.certificates (
			fingerprint_sha256, common_name, sans, serial_number, issuer_dn,
			not_before, not_after, days_remaining, key_type, key_size, status,
			auto_renew, renewal_lead_days, ca_account_id, ca_authority_id,
			deployment_target_id, private_key_encrypted, certificate_pem, chain_pem,
			discovered_via, environment, team, tags, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24
		) RETURNING id, created_at, updated_at
	`
	return s.pool.QueryRow(ctx, query,
		cert.FingerprintSHA256, cert.CommonName, sansJSON, cert.SerialNumber, cert.IssuerDN,
		cert.NotBefore, cert.NotAfter, cert.DaysRemaining, cert.KeyType, cert.KeySize, cert.Status,
		cert.AutoRenew, cert.RenewalLeadDays, cert.CAAccountID, cert.CAAuthorityID,
		cert.DeploymentTargetID, cert.PrivateKeyEncrypted, cert.CertificatePEM, cert.ChainPEM,
		cert.DiscoveredVia, cert.Environment, cert.Team, tagsJSON, cert.CreatedBy,
	).Scan(&cert.ID, &cert.CreatedAt, &cert.UpdatedAt)
}

func (s *PostgresStore) UpdateCertificate(ctx context.Context, cert *Certificate) error {
	sansJSON, _ := json.Marshal(cert.SANs)
	tagsJSON, _ := json.Marshal(cert.Tags)

	daysRemaining := 0
	if cert.NotAfter != nil {
		d := time.Until(*cert.NotAfter).Hours() / 24
		if d > 0 {
			daysRemaining = int(d)
		}
	}
	cert.DaysRemaining = daysRemaining

	query := `
		UPDATE public.certificates SET
			fingerprint_sha256 = $2, common_name = $3, sans = $4, serial_number = $5, issuer_dn = $6,
			not_before = $7, not_after = $8, days_remaining = $9, key_type = $10, key_size = $11, status = $12,
			auto_renew = $13, renewal_lead_days = $14, last_renewal_attempt = $15, renewal_error = $16,
			renewal_count = $17, ca_account_id = $18, ca_authority_id = $19, deployment_target_id = $20,
			certificate_pem = $21, chain_pem = $22, environment = $23, team = $24, tags = $25, updated_at = now()
		WHERE id = $1
	`
	_, err := s.pool.Exec(ctx, query,
		cert.ID, cert.FingerprintSHA256, cert.CommonName, sansJSON, cert.SerialNumber, cert.IssuerDN,
		cert.NotBefore, cert.NotAfter, cert.DaysRemaining, cert.KeyType, cert.KeySize, cert.Status,
		cert.AutoRenew, cert.RenewalLeadDays, cert.LastRenewalAttempt, cert.RenewalError,
		cert.RenewalCount, cert.CAAccountID, cert.CAAuthorityID, cert.DeploymentTargetID,
		cert.CertificatePEM, cert.ChainPEM, cert.Environment, cert.Team, tagsJSON,
	)
	return err
}

func (s *PostgresStore) DeleteCertificate(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM public.certificates WHERE id = $1", id)
	return err
}

func (s *PostgresStore) GetCertificatesDueForRenewal(ctx context.Context, defaultLeadDays int) ([]*Certificate, error) {
	query := `
		SELECT id, fingerprint_sha256, common_name, sans, serial_number, issuer_dn,
		       not_before, not_after, days_remaining, key_type, key_size, status,
		       auto_renew, renewal_lead_days, last_renewal_attempt, renewal_error, renewal_count,
		       ca_account_id, ca_authority_id, deployment_target_id, certificate_pem, chain_pem,
		       discovered_via, environment, team, tags, created_by, created_at, updated_at
		FROM public.certificates
		WHERE auto_renew = true
		  AND status IN ('ISSUED', 'EXPIRING', 'RENEWAL_FAILED')
		  AND not_after <= (now() + (COALESCE(renewal_lead_days, $1) || ' days')::interval)
	`
	rows, err := s.pool.Query(ctx, query, defaultLeadDays)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []*Certificate
	for rows.Next() {
		cert := &Certificate{}
		var sansJSON, tagsJSON []byte
		err := rows.Scan(
			&cert.ID, &cert.FingerprintSHA256, &cert.CommonName, &sansJSON, &cert.SerialNumber, &cert.IssuerDN,
			&cert.NotBefore, &cert.NotAfter, &cert.DaysRemaining, &cert.KeyType, &cert.KeySize, &cert.Status,
			&cert.AutoRenew, &cert.RenewalLeadDays, &cert.LastRenewalAttempt, &cert.RenewalError, &cert.RenewalCount,
			&cert.CAAccountID, &cert.CAAuthorityID, &cert.DeploymentTargetID, &cert.CertificatePEM, &cert.ChainPEM,
			&cert.DiscoveredVia, &cert.Environment, &cert.Team, &tagsJSON, &cert.CreatedBy, &cert.CreatedAt, &cert.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		if len(sansJSON) > 0 {
			_ = json.Unmarshal(sansJSON, &cert.SANs)
		}
		if len(tagsJSON) > 0 {
			_ = json.Unmarshal(tagsJSON, &cert.Tags)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// ── CA Authorities ──────────────────────────────────────

func (s *PostgresStore) ListCAAuthorities(ctx context.Context) ([]*CAAuthority, error) {
	query := `
		SELECT id, name, ca_type, subject_dn, issuer_dn, serial_number,
		       not_before, not_after, days_remaining, key_type, key_size,
		       fingerprint_sha256, certificate_pem, parent_ca_id, crl_distribution_url,
		       ocsp_responder_url, is_crl_fresh, crl_last_checked, is_ocsp_responsive,
		       ocsp_last_checked, certificates_issued_count, alert_thresholds,
		       last_alert_sent_at, last_alert_threshold, status, ca_account_id,
		       tags, notes, created_at, updated_at
		FROM public.ca_authorities
		ORDER BY name ASC
	`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cas []*CAAuthority
	for rows.Next() {
		ca := &CAAuthority{}
		var alertsJSON, tagsJSON []byte
		err := rows.Scan(
			&ca.ID, &ca.Name, &ca.CAType, &ca.SubjectDN, &ca.IssuerDN, &ca.SerialNumber,
			&ca.NotBefore, &ca.NotAfter, &ca.DaysRemaining, &ca.KeyType, &ca.KeySize,
			&ca.FingerprintSHA256, &ca.CertificatePEM, &ca.ParentCAID, &ca.CRLDistributionURL,
			&ca.OCSPResponderURL, &ca.IsCRLFresh, &ca.CRLLastChecked, &ca.IsOCSPResponsive,
			&ca.OCSPLastChecked, &ca.CertificatesIssuedCount, &alertsJSON,
			&ca.LastAlertSentAt, &ca.LastAlertThreshold, &ca.Status, &ca.CAAccountID,
			&tagsJSON, &ca.Notes, &ca.CreatedAt, &ca.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		ca.AlertThresholds = string(alertsJSON)
		ca.Tags = string(tagsJSON)
		cas = append(cas, ca)
	}
	return cas, nil
}

func (s *PostgresStore) GetCAAuthority(ctx context.Context, id string) (*CAAuthority, error) {
	query := `
		SELECT id, name, ca_type, subject_dn, issuer_dn, serial_number,
		       not_before, not_after, days_remaining, key_type, key_size,
		       fingerprint_sha256, certificate_pem, parent_ca_id, crl_distribution_url,
		       ocsp_responder_url, is_crl_fresh, crl_last_checked, is_ocsp_responsive,
		       ocsp_last_checked, certificates_issued_count, alert_thresholds,
		       last_alert_sent_at, last_alert_threshold, status, ca_account_id,
		       tags, notes, created_at, updated_at
		FROM public.ca_authorities WHERE id = $1
	`
	ca := &CAAuthority{}
	var alertsJSON, tagsJSON []byte
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&ca.ID, &ca.Name, &ca.CAType, &ca.SubjectDN, &ca.IssuerDN, &ca.SerialNumber,
		&ca.NotBefore, &ca.NotAfter, &ca.DaysRemaining, &ca.KeyType, &ca.KeySize,
		&ca.FingerprintSHA256, &ca.CertificatePEM, &ca.ParentCAID, &ca.CRLDistributionURL,
		&ca.OCSPResponderURL, &ca.IsCRLFresh, &ca.CRLLastChecked, &ca.IsOCSPResponsive,
		&ca.OCSPLastChecked, &ca.CertificatesIssuedCount, &alertsJSON,
		&ca.LastAlertSentAt, &ca.LastAlertThreshold, &ca.Status, &ca.CAAccountID,
		&tagsJSON, &ca.Notes, &ca.CreatedAt, &ca.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("CA authority %s not found", id)
	}
	if err != nil {
		return nil, err
	}
	ca.AlertThresholds = string(alertsJSON)
	ca.Tags = string(tagsJSON)
	return ca, nil
}

func (s *PostgresStore) CreateCAAuthority(ctx context.Context, ca *CAAuthority) error {
	daysRemaining := 0
	d := time.Until(ca.NotAfter).Hours() / 24
	if d > 0 {
		daysRemaining = int(d)
	}
	ca.DaysRemaining = daysRemaining

	query := `
		INSERT INTO public.ca_authorities (
			name, ca_type, subject_dn, issuer_dn, serial_number, not_before, not_after,
			days_remaining, key_type, key_size, fingerprint_sha256, certificate_pem,
			parent_ca_id, crl_distribution_url, ocsp_responder_url, ca_account_id,
			status, notes
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		RETURNING id, created_at, updated_at
	`
	return s.pool.QueryRow(ctx, query,
		ca.Name, ca.CAType, ca.SubjectDN, ca.IssuerDN, ca.SerialNumber, ca.NotBefore, ca.NotAfter,
		ca.DaysRemaining, ca.KeyType, ca.KeySize, ca.FingerprintSHA256, ca.CertificatePEM,
		ca.ParentCAID, ca.CRLDistributionURL, ca.OCSPResponderURL, ca.CAAccountID,
		ca.Status, ca.Notes,
	).Scan(&ca.ID, &ca.CreatedAt, &ca.UpdatedAt)
}

func (s *PostgresStore) UpdateCAAuthority(ctx context.Context, ca *CAAuthority) error {
	daysRemaining := 0
	d := time.Until(ca.NotAfter).Hours() / 24
	if d > 0 {
		daysRemaining = int(d)
	}
	ca.DaysRemaining = daysRemaining

	query := `
		UPDATE public.ca_authorities SET
			name = $2, ca_type = $3, subject_dn = $4, issuer_dn = $5, serial_number = $6,
			not_before = $7, not_after = $8, days_remaining = $9, key_type = $10, key_size = $11,
			fingerprint_sha256 = $12, certificate_pem = $13, parent_ca_id = $14,
			crl_distribution_url = $15, ocsp_responder_url = $16, is_crl_fresh = $17,
			crl_last_checked = $18, is_ocsp_responsive = $19, ocsp_last_checked = $20,
			certificates_issued_count = $21, last_alert_sent_at = $22, last_alert_threshold = $23,
			status = $24, ca_account_id = $25, notes = $26, updated_at = now()
		WHERE id = $1
	`
	_, err := s.pool.Exec(ctx, query,
		ca.ID, ca.Name, ca.CAType, ca.SubjectDN, ca.IssuerDN, ca.SerialNumber,
		ca.NotBefore, ca.NotAfter, ca.DaysRemaining, ca.KeyType, ca.KeySize,
		ca.FingerprintSHA256, ca.CertificatePEM, ca.ParentCAID,
		ca.CRLDistributionURL, ca.OCSPResponderURL, ca.IsCRLFresh,
		ca.CRLLastChecked, ca.IsOCSPResponsive, ca.OCSPLastChecked,
		ca.CertificatesIssuedCount, ca.LastAlertSentAt, ca.LastAlertThreshold,
		ca.Status, ca.CAAccountID, ca.Notes,
	)
	return err
}

func (s *PostgresStore) DeleteCAAuthority(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM public.ca_authorities WHERE id = $1", id)
	return err
}

func (s *PostgresStore) GetCAChain(ctx context.Context, id string) ([]*CAAuthority, error) {
	// Recursive CTE to walk up the CA chain to root
	query := `
		WITH RECURSIVE ca_chain AS (
			SELECT id, name, ca_type, subject_dn, issuer_dn, serial_number,
			       not_before, not_after, days_remaining, key_type, key_size,
			       fingerprint_sha256, certificate_pem, parent_ca_id, crl_distribution_url,
			       ocsp_responder_url, is_crl_fresh, crl_last_checked, is_ocsp_responsive,
			       ocsp_last_checked, certificates_issued_count, alert_thresholds,
			       last_alert_sent_at, last_alert_threshold, status, ca_account_id,
			       tags, notes, created_at, updated_at, 1 as depth
			FROM public.ca_authorities WHERE id = $1
			UNION ALL
			SELECT parent.id, parent.name, parent.ca_type, parent.subject_dn, parent.issuer_dn, parent.serial_number,
			       parent.not_before, parent.not_after, parent.days_remaining, parent.key_type, parent.key_size,
			       parent.fingerprint_sha256, parent.certificate_pem, parent.parent_ca_id, parent.crl_distribution_url,
			       parent.ocsp_responder_url, parent.is_crl_fresh, parent.crl_last_checked, parent.is_ocsp_responsive,
			       parent.ocsp_last_checked, parent.certificates_issued_count, parent.alert_thresholds,
			       parent.last_alert_sent_at, parent.last_alert_threshold, parent.status, parent.ca_account_id,
			       parent.tags, parent.notes, parent.created_at, parent.updated_at, child.depth + 1
			FROM public.ca_authorities parent
			INNER JOIN ca_chain child ON child.parent_ca_id = parent.id
		)
		SELECT id, name, ca_type, subject_dn, issuer_dn, serial_number,
		       not_before, not_after, days_remaining, key_type, key_size,
		       fingerprint_sha256, certificate_pem, parent_ca_id, crl_distribution_url,
		       ocsp_responder_url, is_crl_fresh, crl_last_checked, is_ocsp_responsive,
		       ocsp_last_checked, certificates_issued_count, alert_thresholds,
		       last_alert_sent_at, last_alert_threshold, status, ca_account_id,
		       tags, notes, created_at, updated_at
		FROM ca_chain ORDER BY depth ASC
	`
	rows, err := s.pool.Query(ctx, query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var chain []*CAAuthority
	for rows.Next() {
		ca := &CAAuthority{}
		var alertsJSON, tagsJSON []byte
		err := rows.Scan(
			&ca.ID, &ca.Name, &ca.CAType, &ca.SubjectDN, &ca.IssuerDN, &ca.SerialNumber,
			&ca.NotBefore, &ca.NotAfter, &ca.DaysRemaining, &ca.KeyType, &ca.KeySize,
			&ca.FingerprintSHA256, &ca.CertificatePEM, &ca.ParentCAID, &ca.CRLDistributionURL,
			&ca.OCSPResponderURL, &ca.IsCRLFresh, &ca.CRLLastChecked, &ca.IsOCSPResponsive,
			&ca.OCSPLastChecked, &ca.CertificatesIssuedCount, &alertsJSON,
			&ca.LastAlertSentAt, &ca.LastAlertThreshold, &ca.Status, &ca.CAAccountID,
			&tagsJSON, &ca.Notes, &ca.CreatedAt, &ca.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		chain = append(chain, ca)
	}
	return chain, nil
}

// ── CA Accounts ─────────────────────────────────────────

func (s *PostgresStore) ListCAAccounts(ctx context.Context) ([]*CAAccount, error) {
	query := `
		SELECT id, name, provider_type, gateway_addr, config_encrypted, is_default,
		       status, last_health_at, created_by, created_at, updated_at
		FROM public.ca_accounts ORDER BY name ASC
	`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []*CAAccount
	for rows.Next() {
		acc := &CAAccount{}
		err := rows.Scan(
			&acc.ID, &acc.Name, &acc.ProviderType, &acc.GatewayAddr, &acc.ConfigEncrypted,
			&acc.IsDefault, &acc.Status, &acc.LastHealthAt, &acc.CreatedBy,
			&acc.CreatedAt, &acc.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, acc)
	}
	return accounts, nil
}

func (s *PostgresStore) GetCAAccount(ctx context.Context, id string) (*CAAccount, error) {
	query := `
		SELECT id, name, provider_type, gateway_addr, config_encrypted, is_default,
		       status, last_health_at, created_by, created_at, updated_at
		FROM public.ca_accounts WHERE id = $1
	`
	acc := &CAAccount{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&acc.ID, &acc.Name, &acc.ProviderType, &acc.GatewayAddr, &acc.ConfigEncrypted,
		&acc.IsDefault, &acc.Status, &acc.LastHealthAt, &acc.CreatedBy,
		&acc.CreatedAt, &acc.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("CA account %s not found", id)
	}
	return acc, err
}

func (s *PostgresStore) CreateCAAccount(ctx context.Context, acc *CAAccount) error {
	query := `
		INSERT INTO public.ca_accounts (name, provider_type, gateway_addr, config_encrypted, is_default, status)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at
	`
	return s.pool.QueryRow(ctx, query,
		acc.Name, acc.ProviderType, acc.GatewayAddr, acc.ConfigEncrypted, acc.IsDefault, acc.Status,
	).Scan(&acc.ID, &acc.CreatedAt, &acc.UpdatedAt)
}

func (s *PostgresStore) UpdateCAAccount(ctx context.Context, acc *CAAccount) error {
	query := `
		UPDATE public.ca_accounts SET
			name = $2, provider_type = $3, gateway_addr = $4, config_encrypted = $5,
			is_default = $6, status = $7, last_health_at = $8, updated_at = now()
		WHERE id = $1
	`
	_, err := s.pool.Exec(ctx, query,
		acc.ID, acc.Name, acc.ProviderType, acc.GatewayAddr, acc.ConfigEncrypted,
		acc.IsDefault, acc.Status, acc.LastHealthAt,
	)
	return err
}

func (s *PostgresStore) DeleteCAAccount(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM public.ca_accounts WHERE id = $1", id)
	return err
}

// ── Deployment Targets ──────────────────────────────────

func (s *PostgresStore) ListDeploymentTargets(ctx context.Context) ([]*DeploymentTarget, error) {
	rows, err := s.pool.Query(ctx, "SELECT id, name, target_type, config_encrypted, last_deployment_at, last_deployment_status, created_by, created_at, updated_at FROM public.deployment_targets ORDER BY name ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []*DeploymentTarget
	for rows.Next() {
		t := &DeploymentTarget{}
		if err := rows.Scan(&t.ID, &t.Name, &t.TargetType, &t.ConfigEncrypted, &t.LastDeploymentAt, &t.LastDeploymentStatus, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, nil
}

func (s *PostgresStore) GetDeploymentTarget(ctx context.Context, id string) (*DeploymentTarget, error) {
	t := &DeploymentTarget{}
	err := s.pool.QueryRow(ctx, "SELECT id, name, target_type, config_encrypted, last_deployment_at, last_deployment_status, created_by, created_at, updated_at FROM public.deployment_targets WHERE id = $1", id).Scan(
		&t.ID, &t.Name, &t.TargetType, &t.ConfigEncrypted, &t.LastDeploymentAt, &t.LastDeploymentStatus, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt,
	)
	return t, err
}

func (s *PostgresStore) CreateDeploymentTarget(ctx context.Context, target *DeploymentTarget) error {
	return s.pool.QueryRow(ctx, "INSERT INTO public.deployment_targets (name, target_type, config_encrypted) VALUES ($1, $2, $3) RETURNING id, created_at, updated_at",
		target.Name, target.TargetType, target.ConfigEncrypted,
	).Scan(&target.ID, &target.CreatedAt, &target.UpdatedAt)
}

func (s *PostgresStore) DeleteDeploymentTarget(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM public.deployment_targets WHERE id = $1", id)
	return err
}

// ── Policies ────────────────────────────────────────────

func (s *PostgresStore) ListPolicies(ctx context.Context) ([]*Policy, error) {
	rows, err := s.pool.Query(ctx, "SELECT id, name, description, is_enabled, rule_type, rule_config, domain_pattern, severity, created_by, created_at, updated_at FROM public.policies ORDER BY name ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*Policy
	for rows.Next() {
		p := &Policy{}
		var cfgJSON []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.IsEnabled, &p.RuleType, &cfgJSON, &p.DomainPattern, &p.Severity, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.RuleConfig = string(cfgJSON)
		policies = append(policies, p)
	}
	return policies, nil
}

func (s *PostgresStore) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	p := &Policy{}
	var cfgJSON []byte
	err := s.pool.QueryRow(ctx, "SELECT id, name, description, is_enabled, rule_type, rule_config, domain_pattern, severity, created_by, created_at, updated_at FROM public.policies WHERE id = $1", id).Scan(
		&p.ID, &p.Name, &p.Description, &p.IsEnabled, &p.RuleType, &cfgJSON, &p.DomainPattern, &p.Severity, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	p.RuleConfig = string(cfgJSON)
	return p, err
}

func (s *PostgresStore) CreatePolicy(ctx context.Context, p *Policy) error {
	return s.pool.QueryRow(ctx, "INSERT INTO public.policies (name, description, is_enabled, rule_type, rule_config, domain_pattern, severity) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, created_at, updated_at",
		p.Name, p.Description, p.IsEnabled, p.RuleType, []byte(p.RuleConfig), p.DomainPattern, p.Severity,
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
}

func (s *PostgresStore) UpdatePolicy(ctx context.Context, p *Policy) error {
	_, err := s.pool.Exec(ctx, "UPDATE public.policies SET name = $2, description = $3, is_enabled = $4, rule_type = $5, rule_config = $6, domain_pattern = $7, severity = $8, updated_at = now() WHERE id = $1",
		p.ID, p.Name, p.Description, p.IsEnabled, p.RuleType, []byte(p.RuleConfig), p.DomainPattern, p.Severity,
	)
	return err
}

func (s *PostgresStore) DeletePolicy(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM public.policies WHERE id = $1", id)
	return err
}

// ── Audit Logs ──────────────────────────────────────────

func (s *PostgresStore) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	query := `
		INSERT INTO public.audit_logs (action, entity_type, entity_id, actor_id, actor_email, details, ip_address)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at
	`
	var detailsJSON []byte
	if log.Details != "" {
		detailsJSON = []byte(log.Details)
	}
	return s.pool.QueryRow(ctx, query,
		log.Action, log.EntityType, log.EntityID, log.ActorID, log.ActorEmail, detailsJSON, log.IPAddress,
	).Scan(&log.ID, &log.CreatedAt)
}

func (s *PostgresStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]*AuditLog, int64, error) {
	var total int64
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM public.audit_logs").Scan(&total); err != nil {
		return nil, 0, err
	}

	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT id, action, entity_type, entity_id, actor_id, actor_email, details, ip_address, created_at
		FROM public.audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2
	`
	rows, err := s.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		l := &AuditLog{}
		var detailsJSON []byte
		if err := rows.Scan(&l.ID, &l.Action, &l.EntityType, &l.EntityID, &l.ActorID, &l.ActorEmail, &detailsJSON, &l.IPAddress, &l.CreatedAt); err != nil {
			return nil, 0, err
		}
		l.Details = string(detailsJSON)
		logs = append(logs, l)
	}
	return logs, total, nil
}

// ── Dashboard Stats ─────────────────────────────────────

func (s *PostgresStore) GetDashboardStats(ctx context.Context) (*DashboardStats, error) {
	stats := &DashboardStats{}

	// Cert stats
	err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'ISSUED' AND days_remaining > 30),
			COUNT(*) FILTER (WHERE status = 'EXPIRING' OR (status = 'ISSUED' AND days_remaining <= 30 AND days_remaining > 0)),
			COUNT(*) FILTER (WHERE status = 'EXPIRED' OR days_remaining = 0)
		FROM public.certificates
	`).Scan(&stats.TotalCertificates, &stats.HealthyCerts, &stats.ExpiringSoonCerts, &stats.ExpiredCerts)
	if err != nil {
		return nil, err
	}

	// CA stats
	err = s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'HEALTHY'),
			COUNT(*) FILTER (WHERE status = 'WARNING'),
			COUNT(*) FILTER (WHERE status = 'CRITICAL' OR status = 'EXPIRED')
		FROM public.ca_authorities
	`).Scan(&stats.TotalCAs, &stats.HealthyCAs, &stats.WarningCAs, &stats.CriticalCAs)
	if err != nil {
		return nil, err
	}

	// Scans count
	_ = s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM public.discovery_scans").Scan(&stats.TotalScans)

	return stats, nil
}
