package store

import (
	"context"
	"encoding/json"
	"errors"
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
			certificate_pem = $21, chain_pem = $22, environment = $23, team = $24, tags = $25,
			private_key_encrypted = COALESCE($26::text, private_key_encrypted), updated_at = now()
		WHERE id = $1
	`
	// COALESCE, because both directions were wrong before.
	//
	// The column was absent from this statement entirely, so renewal — which
	// rotates the key, seals it, and sets it on the record — silently discarded
	// the new key and left the old one paired with the new certificate. Anyone
	// who then exported the key and deployed the pair would have got a
	// handshake failure, from a record the dashboard showed as healthy.
	//
	// Assigning it unconditionally would be the opposite mistake: no read path
	// populates this field, so every ordinary update would erase the key.
	// COALESCE writes a key when the caller supplies one and preserves the
	// stored one when it does not.
	_, err := s.pool.Exec(ctx, query,
		cert.ID, cert.FingerprintSHA256, cert.CommonName, sansJSON, cert.SerialNumber, cert.IssuerDN,
		cert.NotBefore, cert.NotAfter, cert.DaysRemaining, cert.KeyType, cert.KeySize, cert.Status,
		cert.AutoRenew, cert.RenewalLeadDays, cert.LastRenewalAttempt, cert.RenewalError,
		cert.RenewalCount, cert.CAAccountID, cert.CAAuthorityID, cert.DeploymentTargetID,
		cert.CertificatePEM, cert.ChainPEM, cert.Environment, cert.Team, tagsJSON,
		cert.PrivateKeyEncrypted,
	)
	return err
}

// GetCertificatePrivateKey reads the sealed key for exactly one certificate.
func (s *PostgresStore) GetCertificatePrivateKey(ctx context.Context, id string) (string, error) {
	var sealed *string
	err := s.pool.QueryRow(ctx,
		"SELECT private_key_encrypted FROM public.certificates WHERE id = $1", id).Scan(&sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("certificate %s not found", id)
	}
	if err != nil {
		return "", err
	}
	if sealed == nil {
		return "", nil
	}
	return *sealed, nil
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

// caColumns builds the CA authority select list.
//
// The PEM is substituted with an empty literal rather than omitted, so the
// column count and scan order stay identical either way — a select list that
// changes shape with a flag is how a scan target ends up one column out of
// alignment and a fingerprint gets written into a status field.
func caColumns(includePEM bool) string {
	pem := `''::text`
	if includePEM {
		pem = `certificate_pem`
	}
	return `id, name, ca_type, subject_dn, issuer_dn, serial_number,
		not_before, not_after, days_remaining, key_type, key_size,
		fingerprint_sha256, ` + pem + `, parent_ca_id, crl_distribution_url,
		ocsp_responder_url, is_crl_fresh, crl_last_checked, is_ocsp_responsive,
		ocsp_last_checked, certificates_issued_count, alert_thresholds,
		last_alert_sent_at, last_alert_threshold, status, ca_account_id,
		tags, notes, created_at, updated_at`
}

func scanCAAuthority(row pgx.Row) (*CAAuthority, error) {
	ca := &CAAuthority{}
	var alertsJSON, tagsJSON []byte
	err := row.Scan(
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
	return ca, nil
}

func (s *PostgresStore) ListCAAuthorities(ctx context.Context, filter CAFilter) ([]*CAAuthority, error) {
	where := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if filter.Status != "" {
		where = append(where, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, filter.Status)
		argIdx++
	}
	if filter.ExpiringWithinDays > 0 {
		// Against not_after, not the cached days_remaining — see CAFilter.
		where = append(where, fmt.Sprintf("not_after <= now() + ($%d || ' days')::interval", argIdx))
		args = append(args, filter.ExpiringWithinDays)
		argIdx++
	}
	if filter.ExcludeExpired {
		where = append(where, "not_after > now()")
	}

	order := "name ASC"
	if filter.Sort == CASortUrgency {
		order = "not_after ASC, name ASC"
	}

	query := fmt.Sprintf("SELECT %s FROM public.ca_authorities WHERE %s ORDER BY %s",
		caColumns(filter.IncludePEM), strings.Join(where, " AND "), order)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cas []*CAAuthority
	for rows.Next() {
		ca, err := scanCAAuthority(rows)
		if err != nil {
			return nil, err
		}
		cas = append(cas, ca)
	}
	return cas, rows.Err()
}

func (s *PostgresStore) GetCAAuthority(ctx context.Context, id string) (*CAAuthority, error) {
	// A detail read includes the PEM: it is the one place someone is looking at
	// a single CA and may want the certificate itself.
	ca, err := scanCAAuthority(s.pool.QueryRow(ctx,
		"SELECT "+caColumns(true)+" FROM public.ca_authorities WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("CA authority %s not found", id)
	}
	if err != nil {
		return nil, err
	}
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

	// certificate_pem is deliberately absent from this statement.
	//
	// A CA's certificate is written once, at registration, and no code path
	// replaces it. Leaving it in the update made the read path dangerous: the
	// health sweep reads a CA, mutates it, and writes it back, so any caller
	// that listed without CAFilter.IncludePEM and then updated would have
	// silently blanked the column — and the next sweep would have had nothing
	// to parse, reporting the CA as UNKNOWN rather than expiring. Dropping the
	// column here removes the trap rather than relying on every caller to
	// remember it.
	query := `
		UPDATE public.ca_authorities SET
			name = $2, ca_type = $3, subject_dn = $4, issuer_dn = $5, serial_number = $6,
			not_before = $7, not_after = $8, days_remaining = $9, key_type = $10, key_size = $11,
			fingerprint_sha256 = $12, parent_ca_id = $13,
			crl_distribution_url = $14, ocsp_responder_url = $15, is_crl_fresh = $16,
			crl_last_checked = $17, is_ocsp_responsive = $18, ocsp_last_checked = $19,
			certificates_issued_count = $20, alert_thresholds = $21,
			last_alert_sent_at = $22, last_alert_threshold = $23,
			status = $24, ca_account_id = $25, tags = $26, notes = $27, updated_at = now()
		WHERE id = $1
	`
	_, err := s.pool.Exec(ctx, query,
		ca.ID, ca.Name, ca.CAType, ca.SubjectDN, ca.IssuerDN, ca.SerialNumber,
		ca.NotBefore, ca.NotAfter, ca.DaysRemaining, ca.KeyType, ca.KeySize,
		ca.FingerprintSHA256, ca.ParentCAID,
		ca.CRLDistributionURL, ca.OCSPResponderURL, ca.IsCRLFresh,
		ca.CRLLastChecked, ca.IsOCSPResponsive, ca.OCSPLastChecked,
		ca.CertificatesIssuedCount, jsonbOrNil(ca.AlertThresholds),
		ca.LastAlertSentAt, ca.LastAlertThreshold,
		ca.Status, ca.CAAccountID, jsonbOrNil(ca.Tags), ca.Notes,
	)
	return err
}

// jsonbOrNil renders a string field destined for a jsonb column.
//
// These are held as strings on the model and read back as "" when the column is
// NULL. Handing that empty string straight to Postgres is a syntax error on
// jsonb, which would have turned "this CA has no tags" into a failed health
// sweep.
func jsonbOrNil(s string) []byte {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return []byte(s)
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
		SELECT ` + caColumns(true) + `
		FROM ca_chain ORDER BY depth ASC
	`
	rows, err := s.pool.Query(ctx, query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var chain []*CAAuthority
	for rows.Next() {
		// Via the shared scanner, which also populates AlertThresholds and
		// Tags. The hand-written scan this replaced read both columns and then
		// dropped them on the floor, so every CA in a chain response reported
		// no configured thresholds regardless of what was stored.
		ca, err := scanCAAuthority(rows)
		if err != nil {
			return nil, err
		}
		chain = append(chain, ca)
	}
	return chain, rows.Err()
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
		FROM public.ca_accounts WHERE id::text = $1 OR name = $1
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

// ── Display Tokens ──────────────────────────────────────

const displayTokenColumns = `id, name, token_hash, expires_at, last_seen_at,
	host(last_seen_ip), revoked_at, revoked_by, created_by, created_at`

func scanDisplayToken(row pgx.Row) (*DisplayToken, error) {
	t := &DisplayToken{}
	err := row.Scan(&t.ID, &t.Name, &t.TokenHash, &t.ExpiresAt, &t.LastSeenAt,
		&t.LastSeenIP, &t.RevokedAt, &t.RevokedBy, &t.CreatedBy, &t.CreatedAt)
	return t, err
}

func (s *PostgresStore) ListDisplayTokens(ctx context.Context) ([]*DisplayToken, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+displayTokenColumns+" FROM public.display_tokens ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tokens := make([]*DisplayToken, 0)
	for rows.Next() {
		t, err := scanDisplayToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// GetDisplayTokenByHash resolves a presented token.
//
// The equality is on the hash rather than on the secret, so the query plan
// leaks nothing an attacker can steer: to influence the comparison they would
// already need a preimage of a 256-bit CSPRNG output.
func (s *PostgresStore) GetDisplayTokenByHash(ctx context.Context, tokenHash string) (*DisplayToken, error) {
	t, err := scanDisplayToken(s.pool.QueryRow(ctx,
		"SELECT "+displayTokenColumns+" FROM public.display_tokens WHERE token_hash = $1", tokenHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("display token not found")
	}
	return t, err
}

func (s *PostgresStore) CreateDisplayToken(ctx context.Context, t *DisplayToken) error {
	query := `
		INSERT INTO public.display_tokens (name, token_hash, expires_at, created_by)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at
	`
	return s.pool.QueryRow(ctx, query, t.Name, t.TokenHash, t.ExpiresAt, t.CreatedBy).
		Scan(&t.ID, &t.CreatedAt)
}

func (s *PostgresStore) RevokeDisplayToken(ctx context.Context, id string, revokedBy *string) error {
	// `revoked_at is null` keeps the original revocation time and actor: who
	// first pulled the credential is the answer an incident review needs, not
	// whoever clicked the button again afterwards.
	tag, err := s.pool.Exec(ctx,
		"UPDATE public.display_tokens SET revoked_at = now(), revoked_by = $2 WHERE id = $1 AND revoked_at is null",
		id, revokedBy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Either it does not exist or it was already revoked. Confirm which,
		// so a caller revoking a token that is already dead is not told it
		// failed.
		var exists bool
		if err := s.pool.QueryRow(ctx,
			"SELECT true FROM public.display_tokens WHERE id = $1", id).Scan(&exists); err != nil {
			return fmt.Errorf("display token %s not found", id)
		}
	}
	return nil
}

func (s *PostgresStore) TouchDisplayToken(ctx context.Context, id string, seenAt time.Time, ip string) error {
	var addr *string
	if ip != "" {
		addr = &ip
	}
	_, err := s.pool.Exec(ctx,
		"UPDATE public.display_tokens SET last_seen_at = $2, last_seen_ip = coalesce($3::inet, last_seen_ip) WHERE id = $1",
		id, seenAt, addr)
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

func (s *PostgresStore) ListAuditLogs(ctx context.Context, filter AuditLogFilter) ([]*AuditLog, int64, error) {
	where := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if len(filter.Actions) > 0 {
		// = ANY($n) rather than an IN list built by string concatenation: the
		// actions arrive from a query parameter, and this keeps them a bound
		// parameter instead of something spliced into SQL.
		where = append(where, fmt.Sprintf("action = ANY($%d)", argIdx))
		args = append(args, filter.Actions)
		argIdx++
	}
	if filter.EntityType != "" {
		where = append(where, fmt.Sprintf("entity_type = $%d", argIdx))
		args = append(args, filter.EntityType)
		argIdx++
	}
	if filter.EntityID != "" {
		where = append(where, fmt.Sprintf("entity_id = $%d", argIdx))
		args = append(args, filter.EntityID)
		argIdx++
	}
	if !filter.Since.IsZero() {
		where = append(where, fmt.Sprintf("created_at >= $%d", argIdx))
		args = append(args, filter.Since)
		argIdx++
	}
	whereClause := strings.Join(where, " AND ")

	// The count is of the filtered set, not the table. A total that ignored the
	// filter would tell a caller paging through CA alerts that there are
	// forty thousand of them.
	var total int64
	if err := s.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM public.audit_logs WHERE "+whereClause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := 50
	if filter.Limit > 0 {
		limit = filter.Limit
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
		SELECT id, action, entity_type, entity_id, actor_id, actor_email, details, ip_address, created_at
		FROM public.audit_logs WHERE %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	logs := make([]*AuditLog, 0)
	for rows.Next() {
		l := &AuditLog{}
		var detailsJSON []byte
		if err := rows.Scan(&l.ID, &l.Action, &l.EntityType, &l.EntityID, &l.ActorID, &l.ActorEmail, &detailsJSON, &l.IPAddress, &l.CreatedAt); err != nil {
			return nil, 0, err
		}
		l.Details = string(detailsJSON)
		logs = append(logs, l)
	}
	return logs, total, rows.Err()
}

// ── Notification Channels ───────────────────────────────

const notificationChannelColumns = `id, name, channel_type, config_encrypted,
	is_enabled, severity_threshold, topics, last_sent_at, created_by, created_at, updated_at`

func scanNotificationChannel(row pgx.Row) (*NotificationChannel, error) {
	ch := &NotificationChannel{}
	var topicsJSON []byte
	err := row.Scan(&ch.ID, &ch.Name, &ch.ChannelType, &ch.ConfigEncrypted,
		&ch.IsEnabled, &ch.SeverityThreshold, &topicsJSON, &ch.LastSentAt,
		&ch.CreatedBy, &ch.CreatedAt, &ch.UpdatedAt)
	if err != nil {
		return nil, err
	}
	ch.Topics = []string{}
	if len(topicsJSON) > 0 {
		_ = json.Unmarshal(topicsJSON, &ch.Topics)
	}
	return ch, nil
}

func (s *PostgresStore) ListNotificationChannels(ctx context.Context) ([]*NotificationChannel, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+notificationChannelColumns+" FROM public.notification_channels ORDER BY name ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	channels := make([]*NotificationChannel, 0)
	for rows.Next() {
		ch, err := scanNotificationChannel(rows)
		if err != nil {
			return nil, err
		}
		channels = append(channels, ch)
	}
	return channels, rows.Err()
}

func (s *PostgresStore) GetNotificationChannel(ctx context.Context, id string) (*NotificationChannel, error) {
	ch, err := scanNotificationChannel(s.pool.QueryRow(ctx,
		"SELECT "+notificationChannelColumns+" FROM public.notification_channels WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("notification channel %s not found", id)
	}
	return ch, err
}

func (s *PostgresStore) CreateNotificationChannel(ctx context.Context, ch *NotificationChannel) error {
	topicsJSON, err := json.Marshal(normalizeTopics(ch.Topics))
	if err != nil {
		return err
	}
	query := `
		INSERT INTO public.notification_channels
			(name, channel_type, config_encrypted, is_enabled, severity_threshold, topics, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at
	`
	return s.pool.QueryRow(ctx, query, ch.Name, ch.ChannelType, ch.ConfigEncrypted,
		ch.IsEnabled, ch.SeverityThreshold, topicsJSON, ch.CreatedBy).
		Scan(&ch.ID, &ch.CreatedAt, &ch.UpdatedAt)
}

func (s *PostgresStore) UpdateNotificationChannel(ctx context.Context, ch *NotificationChannel) error {
	topicsJSON, err := json.Marshal(normalizeTopics(ch.Topics))
	if err != nil {
		return err
	}
	// last_sent_at is not written here — that is MarkNotificationChannelSent's
	// job, so an operator saving an edit cannot rewind the delivery record.
	query := `
		UPDATE public.notification_channels SET
			name = $2, channel_type = $3, config_encrypted = $4, is_enabled = $5,
			severity_threshold = $6, topics = $7, updated_at = now()
		WHERE id = $1
	`
	tag, err := s.pool.Exec(ctx, query, ch.ID, ch.Name, ch.ChannelType,
		ch.ConfigEncrypted, ch.IsEnabled, ch.SeverityThreshold, topicsJSON)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("notification channel %s not found", ch.ID)
	}
	return nil
}

func (s *PostgresStore) DeleteNotificationChannel(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM public.notification_channels WHERE id = $1", id)
	return err
}

func (s *PostgresStore) MarkNotificationChannelSent(ctx context.Context, id string, sentAt time.Time) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE public.notification_channels SET last_sent_at = $2 WHERE id = $1", id, sentAt)
	return err
}

// normalizeTopics guarantees a JSON array rather than null.
//
// A nil slice marshals to `null`, which fails the jsonb array constraint and
// would read back as "no topics" — indistinguishable from "every topic" on the
// way in and the opposite of it on the way out.
func normalizeTopics(topics []string) []string {
	if topics == nil {
		return []string{}
	}
	return topics
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

	// CA stats. Each status gets its own bucket and anything unrecognised falls
	// into UnknownCAs, so the four buckets always sum to the total — see
	// DashboardStats. EXPIRED is split out from CRITICAL because they call for
	// different actions: a critical CA can still be replaced in an orderly way,
	// an expired one is already an outage.
	err = s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'HEALTHY'),
			COUNT(*) FILTER (WHERE status = 'WARNING'),
			COUNT(*) FILTER (WHERE status = 'CRITICAL'),
			COUNT(*) FILTER (WHERE status = 'EXPIRED'),
			COUNT(*) FILTER (WHERE status NOT IN ('HEALTHY', 'WARNING', 'CRITICAL', 'EXPIRED')
			                    OR status IS NULL)
		FROM public.ca_authorities
	`).Scan(&stats.TotalCAs, &stats.HealthyCAs, &stats.WarningCAs, &stats.CriticalCAs,
		&stats.ExpiredCAs, &stats.UnknownCAs)
	if err != nil {
		return nil, err
	}

	// Scans count
	_ = s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM public.discovery_scans").Scan(&stats.TotalScans)

	return stats, nil
}
