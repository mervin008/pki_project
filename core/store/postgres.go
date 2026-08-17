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
		pool.Close()
		return nil, fmt.Errorf("failed to ping postgres: %w", err)
	}

	// A reachable database is not the same as a usable one. Preflight refuses
	// an unmigrated schema, and refuses a connection that row-level security
	// would silently filter to nothing — which would otherwise present as a
	// perfectly healthy, perfectly empty estate.
	if err := Preflight(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}

	slog.Info("connected to PostgreSQL/Supabase database")
	return &PostgresStore{pool: pool}, nil
}

// Close terminates all pool connections.
func (s *PostgresStore) Close() {
	s.pool.Close()
}

// ── Certificates ────────────────────────────────────────

// certificateColumns is the read projection for public.certificates, in the
// order scanCertificate expects.
//
// One definition rather than the four identical copies that were here before.
// They had already drifted once: private_key_encrypted was missing from all of
// them, so key export answered "no private key is stored" for every certificate
// while the column held one.
//
// The COALESCEs are load-bearing, not decoration. Several of these columns are
// nullable in the schema but map to non-pointer Go fields — days_remaining and
// key_size to int, auto_renew to bool, environment and team to string. pgx
// cannot scan NULL into those, and it fails the whole query rather than the one
// row, so a single hand-inserted or bulk-imported row with a NULL would take
// out the entire certificate list. For an inventory product people import into,
// that is a matter of when.
const certificateColumns = `id, fingerprint_sha256, common_name,
		coalesce(sans, '[]'::jsonb), coalesce(serial_number, ''), coalesce(issuer_dn, ''),
		not_before, not_after, coalesce(days_remaining, 0),
		coalesce(key_type, ''), coalesce(key_size, 0), status,
		coalesce(auto_renew, false), coalesce(renewal_lead_days, 0),
		last_renewal_attempt, renewal_error, coalesce(renewal_count, 0),
		ca_account_id, ca_authority_id, deployment_target_id, certificate_pem, chain_pem,
		coalesce(discovered_via, 'MANUAL'), coalesce(environment, ''), coalesce(team, ''),
		coalesce(tags, '[]'::jsonb), created_by, created_at, updated_at`

// scanCertificate reads one row of certificateColumns.
func scanCertificate(row pgx.Row) (*Certificate, error) {
	cert := &Certificate{}
	var sansJSON, tagsJSON []byte
	err := row.Scan(
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
	return cert, nil
}

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
		SELECT `+certificateColumns+`
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

	certs := []*Certificate{}
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, 0, err
		}
		certs = append(certs, cert)
	}

	return certs, total, nil
}

func (s *PostgresStore) GetCertificate(ctx context.Context, id string) (*Certificate, error) {
	query := `
		SELECT ` + certificateColumns + `
		FROM public.certificates WHERE id = $1
	`
	cert, err := scanCertificate(s.pool.QueryRow(ctx, query, id))
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("certificate %s not found", id)
	}
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (s *PostgresStore) GetCertificateByFingerprint(ctx context.Context, fingerprint string) (*Certificate, error) {
	query := `
		SELECT ` + certificateColumns + `
		FROM public.certificates WHERE fingerprint_sha256 = $1
	`
	cert, err := scanCertificate(s.pool.QueryRow(ctx, query, fingerprint))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
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
		cert.DiscoveredVia, nullIfEmpty(cert.Environment), cert.Team, tagsJSON, cert.CreatedBy,
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
		cert.CertificatePEM, cert.ChainPEM, nullIfEmpty(cert.Environment), cert.Team, tagsJSON,
		cert.PrivateKeyEncrypted,
	)
	return err
}

// nullIfEmpty maps Go's zero value for a string to SQL NULL.
//
// Needed because several nullable columns carry a CHECK constraint —
// certificates.environment is `check (environment in ('production', 'staging',
// 'development'))`. A CHECK passes on NULL and fails on ”, so a field the
// caller simply did not set is rejected by the database while an absent one is
// accepted. Issuing a certificate without naming an environment is the ordinary
// case, and before this it failed outright on PostgreSQL with a constraint
// violation naming a column the request never mentioned.
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
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
		SELECT ` + certificateColumns + `
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

	certs := []*Certificate{}
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, err
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
	// COALESCE for the same reason as certificateColumns: these columns are
	// nullable in the schema but scan into non-pointer Go fields, and pgx fails
	// the whole query on a NULL rather than the single row. A CA list that
	// 500s because one row has a null CRL URL is a blank monitoring screen.
	return `id, name, ca_type, subject_dn, issuer_dn, coalesce(serial_number, ''),
		not_before, not_after, coalesce(days_remaining, 0), key_type, key_size,
		fingerprint_sha256, ` + pem + `, parent_ca_id, coalesce(crl_distribution_url, ''),
		coalesce(ocsp_responder_url, ''), coalesce(is_crl_fresh, false), crl_last_checked,
		coalesce(is_ocsp_responsive, false),
		ocsp_last_checked, coalesce(certificates_issued_count, 0),
		coalesce(alert_thresholds, '[]'::jsonb),
		last_alert_sent_at, last_alert_threshold, status, ca_account_id,
		owner_team, owner_email,
		coalesce(tags, '[]'::jsonb), coalesce(notes, ''), created_at, updated_at`
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
		&ca.OwnerTeam, &ca.OwnerEmail,
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
		//
		// make_interval rather than ($n || ' days')::interval. In the string
		// form both sides of `||` are untyped, so PostgreSQL resolves the
		// operator as text || text and reports the parameter as text — and the
		// driver, holding an int, fails to encode it. The query is not wrong so
		// much as untypable, and it fails at bind time on every call.
		where = append(where, fmt.Sprintf("not_after <= now() + make_interval(days => $%d)", argIdx))
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

	cas := []*CAAuthority{}
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
			status, notes, owner_team, owner_email
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		RETURNING id, created_at, updated_at
	`
	return s.pool.QueryRow(ctx, query,
		ca.Name, ca.CAType, ca.SubjectDN, ca.IssuerDN, ca.SerialNumber, ca.NotBefore, ca.NotAfter,
		ca.DaysRemaining, ca.KeyType, ca.KeySize, ca.FingerprintSHA256, ca.CertificatePEM,
		ca.ParentCAID, ca.CRLDistributionURL, ca.OCSPResponderURL, ca.CAAccountID,
		ca.Status, ca.Notes, ca.OwnerTeam, ca.OwnerEmail,
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
			status = $24, ca_account_id = $25, tags = $26, notes = $27,
			owner_team = $28, owner_email = $29, updated_at = now()
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
		ca.OwnerTeam, ca.OwnerEmail,
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

	chain := []*CAAuthority{}
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

	accounts := []*CAAccount{}
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

	targets := []*DeploymentTarget{}
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

	policies := []*Policy{}
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
		-- host(ip_address), not ip_address. The column is inet and AuditLog.IPAddress
		-- is a *string, which pgx cannot scan an inet into — it fails the whole
		-- query, so one entry recorded with a client IP took out the entire
		-- activity feed. Writing works either way, which is why this only showed
		-- up on reading back what the API itself had written. host() renders the
		-- address without any netmask suffix; display_tokens already does the
		-- same for last_seen_ip.
		SELECT id, action, entity_type, entity_id, actor_id, actor_email, details, host(ip_address), created_at
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

// ── Alert Acknowledgements ──────────────────────────────

const acknowledgementColumns = `id, entity_type, entity_id, threshold,
	acknowledged_by, acknowledged_by_email, acknowledged_at, coalesce(note, ''),
	silence_until, revoked_at, revoked_by, created_at`

func scanAcknowledgement(row pgx.Row) (*AlertAcknowledgement, error) {
	a := &AlertAcknowledgement{}
	err := row.Scan(&a.ID, &a.EntityType, &a.EntityID, &a.Threshold,
		&a.AcknowledgedBy, &a.AcknowledgedByEmail, &a.AcknowledgedAt, &a.Note,
		&a.SilenceUntil, &a.RevokedAt, &a.RevokedBy, &a.CreatedAt)
	return a, err
}

func (s *PostgresStore) CreateAcknowledgement(ctx context.Context, ack *AlertAcknowledgement) error {
	query := `
		INSERT INTO public.alert_acknowledgements
			(entity_type, entity_id, threshold, acknowledged_by, acknowledged_by_email,
			 note, silence_until)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, acknowledged_at, created_at
	`
	return s.pool.QueryRow(ctx, query,
		ack.EntityType, ack.EntityID, ack.Threshold, ack.AcknowledgedBy,
		ack.AcknowledgedByEmail, nullIfEmpty(strings.TrimSpace(ack.Note)), ack.SilenceUntil,
	).Scan(&ack.ID, &ack.AcknowledgedAt, &ack.CreatedAt)
}

func (s *PostgresStore) GetActiveAcknowledgement(ctx context.Context, entityType, entityID string) (*AlertAcknowledgement, error) {
	a, err := scanAcknowledgement(s.pool.QueryRow(ctx,
		"SELECT "+acknowledgementColumns+` FROM public.alert_acknowledgements
		 WHERE entity_type = $1 AND entity_id = $2 AND revoked_at IS NULL
		 ORDER BY acknowledged_at DESC LIMIT 1`, entityType, entityID))
	if errors.Is(err, pgx.ErrNoRows) {
		// Not an error. "Nobody has acknowledged this" is the normal answer,
		// and making callers distinguish it from a failure invites them to
		// treat a real failure as "not acknowledged" and alert anyway.
		return nil, nil
	}
	return a, err
}

func (s *PostgresStore) ListAcknowledgements(ctx context.Context, entityType, entityID string) ([]*AlertAcknowledgement, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+acknowledgementColumns+` FROM public.alert_acknowledgements
		 WHERE entity_type = $1 AND entity_id = $2
		 ORDER BY acknowledged_at DESC`, entityType, entityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*AlertAcknowledgement, 0)
	for rows.Next() {
		a, err := scanAcknowledgement(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetActiveAcknowledgements resolves many entities in one round trip.
//
// DISTINCT ON rather than a correlated subquery per row: the CA list calls this
// once for the whole estate, and the per-row form is how a dashboard ends up
// issuing one query per CA on every refresh.
func (s *PostgresStore) GetActiveAcknowledgements(ctx context.Context, entityType string, entityIDs []string) (map[string]*AlertAcknowledgement, error) {
	out := make(map[string]*AlertAcknowledgement, len(entityIDs))
	if len(entityIDs) == 0 {
		return out, nil
	}

	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT ON (entity_id) `+acknowledgementColumns+`
		 FROM public.alert_acknowledgements
		 WHERE entity_type = $1 AND entity_id = ANY($2) AND revoked_at IS NULL
		 ORDER BY entity_id, acknowledged_at DESC`, entityType, entityIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		a, err := scanAcknowledgement(rows)
		if err != nil {
			return nil, err
		}
		out[a.EntityID] = a
	}
	return out, rows.Err()
}

func (s *PostgresStore) RevokeAcknowledgement(ctx context.Context, id string, revokedBy *string) error {
	// `revoked_at IS NULL` keeps the first withdrawal's time and actor, for the
	// same reason as RevokeDisplayToken: who first pulled it is what a review
	// needs, not whoever clicked again afterwards.
	tag, err := s.pool.Exec(ctx,
		`UPDATE public.alert_acknowledgements SET revoked_at = now(), revoked_by = $2
		 WHERE id = $1 AND revoked_at IS NULL`, id, revokedBy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err := s.pool.QueryRow(ctx,
			"SELECT true FROM public.alert_acknowledgements WHERE id = $1", id).Scan(&exists); err != nil {
			return fmt.Errorf("acknowledgement %s not found", id)
		}
	}
	return nil
}

// ── Discovery ───────────────────────────────────────────

const discoveryScanColumns = `id, scan_type, coalesce(targets, '[]'::jsonb), status,
		coalesce(target_count, 0), coalesce(results_count, 0),
		coalesce(unmanaged_count, 0), coalesce(managed_count, 0),
		coalesce(unreachable_count, 0), started_at, completed_at, coalesce(error, ''),
		triggered_by, actor_email, created_at`

func scanDiscoveryScan(row pgx.Row) (*DiscoveryScan, error) {
	scan := &DiscoveryScan{}
	var targetsJSON []byte
	err := row.Scan(
		&scan.ID, &scan.ScanType, &targetsJSON, &scan.Status,
		&scan.TargetCount, &scan.ResultsCount, &scan.UnmanagedCount, &scan.ManagedCount,
		&scan.UnreachableCount, &scan.StartedAt, &scan.CompletedAt, &scan.Error,
		&scan.TriggeredBy, &scan.ActorEmail, &scan.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(targetsJSON) > 0 {
		_ = json.Unmarshal(targetsJSON, &scan.Targets)
	}
	// Never nil: a nil slice serializes as `null`, and a dashboard calling
	// .map() on that crashes rather than rendering an empty run.
	if scan.Targets == nil {
		scan.Targets = []string{}
	}
	return scan, nil
}

func (s *PostgresStore) CreateDiscoveryScan(ctx context.Context, scan *DiscoveryScan) error {
	targetsJSON, err := json.Marshal(scan.Targets)
	if err != nil {
		return err
	}
	if scan.Status == "" {
		scan.Status = ScanPending
	}
	return s.pool.QueryRow(ctx, `
		INSERT INTO public.discovery_scans
			(scan_type, targets, target_count, status, started_at, triggered_by, actor_email)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at`,
		scan.ScanType, targetsJSON, scan.TargetCount, scan.Status, scan.StartedAt,
		scan.TriggeredBy, scan.ActorEmail).
		Scan(&scan.ID, &scan.CreatedAt)
}

func (s *PostgresStore) UpdateDiscoveryScan(ctx context.Context, scan *DiscoveryScan) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.discovery_scans SET
			status = $2, results_count = $3, unmanaged_count = $4, managed_count = $5,
			unreachable_count = $6, started_at = $7, completed_at = $8, error = $9
		WHERE id = $1`,
		scan.ID, scan.Status, scan.ResultsCount, scan.UnmanagedCount, scan.ManagedCount,
		scan.UnreachableCount, scan.StartedAt, scan.CompletedAt, nullIfEmpty(scan.Error))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("discovery scan %s not found", scan.ID)
	}
	return nil
}

func (s *PostgresStore) GetDiscoveryScan(ctx context.Context, id string) (*DiscoveryScan, error) {
	scan, err := scanDiscoveryScan(s.pool.QueryRow(ctx,
		"SELECT "+discoveryScanColumns+" FROM public.discovery_scans WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("discovery scan %s not found", id)
	}
	return scan, err
}

func (s *PostgresStore) ListDiscoveryScans(ctx context.Context, limit, offset int) ([]*DiscoveryScan, int64, error) {
	if limit <= 0 {
		limit = 50
	}

	var total int64
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM public.discovery_scans").Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.pool.Query(ctx,
		"SELECT "+discoveryScanColumns+` FROM public.discovery_scans
		 ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	scans := make([]*DiscoveryScan, 0)
	for rows.Next() {
		scan, err := scanDiscoveryScan(rows)
		if err != nil {
			return nil, 0, err
		}
		scans = append(scans, scan)
	}
	return scans, total, rows.Err()
}

const discoveryResultColumns = `id, scan_id, host, port, coalesce(reachable, true), coalesce(error, ''),
		coalesce(management_state, 'UNMANAGED'), coalesce(trust_state, 'UNKNOWN'), matched_certificate_id,
		coalesce(common_name, ''), coalesce(subject_dn, ''), coalesce(sans, '[]'::jsonb),
		coalesce(issuer_dn, ''), coalesce(serial_number, ''), not_before, not_after,
		coalesce(key_type, ''), coalesce(key_size, 0), coalesce(is_ca, false),
		coalesce(fingerprint_sha256, ''), coalesce(certificate_pem, ''), coalesce(chain_pem, ''),
		coalesce(chain_length, 0), coalesce(tls_version, ''), coalesce(cipher_suite, ''),
		coalesce(key_exchange, ''), coalesce(alpn, ''), coalesce(findings, '[]'::jsonb),
		coalesce(is_imported, false), imported_certificate_id, coalesce(scanned_at, created_at), created_at`

// scanDiscoveryResult reads one row of discoveryResultColumns.
//
// Every nullable column is COALESCEd. A single NULL scanning into a non-pointer
// Go field fails the whole query rather than the row, so one hand-inserted
// result would otherwise blank an entire scan's findings — the defect the first
// live PostgreSQL run turned up on the certificate list.
func scanDiscoveryResult(row pgx.Row) (*DiscoveryResult, error) {
	r := &DiscoveryResult{}
	var sansJSON, findingsJSON []byte
	err := row.Scan(
		&r.ID, &r.ScanID, &r.Host, &r.Port, &r.Reachable, &r.Error,
		&r.ManagementState, &r.TrustState, &r.MatchedCertificateID,
		&r.CommonName, &r.SubjectDN, &sansJSON,
		&r.IssuerDN, &r.SerialNumber, &r.NotBefore, &r.NotAfter,
		&r.KeyType, &r.KeySize, &r.IsCA,
		&r.FingerprintSHA256, &r.CertificatePEM, &r.ChainPEM,
		&r.ChainLength, &r.TLSVersion, &r.CipherSuite,
		&r.KeyExchange, &r.ALPN, &findingsJSON,
		&r.IsImported, &r.ImportedCertificateID, &r.ScannedAt, &r.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(sansJSON) > 0 {
		_ = json.Unmarshal(sansJSON, &r.SANs)
	}
	if len(findingsJSON) > 0 {
		_ = json.Unmarshal(findingsJSON, &r.Findings)
	}
	if r.SANs == nil {
		r.SANs = []string{}
	}
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	return r, nil
}

func (s *PostgresStore) CreateDiscoveryResults(ctx context.Context, results []*DiscoveryResult) error {
	if len(results) == 0 {
		return nil
	}

	// One transaction for the whole batch. A scan's results are a single
	// observation of the estate; half of them landing would make the counts on
	// the scan record disagree with the rows behind it.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, r := range results {
		sansJSON, err := json.Marshal(r.SANs)
		if err != nil {
			return err
		}
		findings := r.Findings
		if findings == nil {
			findings = []Finding{}
		}
		findingsJSON, err := json.Marshal(findings)
		if err != nil {
			return err
		}
		if r.ScannedAt.IsZero() {
			r.ScannedAt = time.Now()
		}

		err = tx.QueryRow(ctx, `
			INSERT INTO public.discovery_results
				(scan_id, host, port, reachable, error, management_state, trust_state,
				 matched_certificate_id, common_name, subject_dn, sans, issuer_dn, serial_number,
				 not_before, not_after, key_type, key_size, is_ca, fingerprint_sha256,
				 certificate_pem, chain_pem, chain_length, tls_version, cipher_suite,
				 key_exchange, alpn, findings, scanned_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
			        $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)
			RETURNING id, created_at`,
			r.ScanID, r.Host, r.Port, r.Reachable, nullIfEmpty(r.Error), r.ManagementState, r.TrustState,
			r.MatchedCertificateID, nullIfEmpty(r.CommonName), nullIfEmpty(r.SubjectDN), sansJSON,
			nullIfEmpty(r.IssuerDN), nullIfEmpty(r.SerialNumber), r.NotBefore, r.NotAfter,
			nullIfEmpty(r.KeyType), r.KeySize, r.IsCA, nullIfEmpty(r.FingerprintSHA256),
			nullIfEmpty(r.CertificatePEM), nullIfEmpty(r.ChainPEM), r.ChainLength,
			nullIfEmpty(r.TLSVersion), nullIfEmpty(r.CipherSuite), nullIfEmpty(r.KeyExchange),
			nullIfEmpty(r.ALPN), findingsJSON, r.ScannedAt).
			Scan(&r.ID, &r.CreatedAt)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) ListDiscoveryResults(ctx context.Context, filter DiscoveryResultFilter) ([]*DiscoveryResult, int64, error) {
	where := []string{"1=1"}
	args := []any{}
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}

	if filter.ScanID != "" {
		add("scan_id = $%d", filter.ScanID)
	}
	if filter.ManagementState != "" {
		add("management_state = $%d", filter.ManagementState)
	}
	if filter.TrustState != "" {
		add("trust_state = $%d", filter.TrustState)
	}
	if filter.Host != "" {
		add("host = $%d", filter.Host)
	}
	if filter.UnimportedOnly {
		where = append(where, "coalesce(is_imported, false) = false")
	}
	clause := strings.Join(where, " AND ")

	var total int64
	if err := s.pool.QueryRow(ctx,
		"SELECT count(*) FROM public.discovery_results WHERE "+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}
	args = append(args, limit, filter.Offset)
	query := "SELECT " + discoveryResultColumns + " FROM public.discovery_results WHERE " + clause +
		fmt.Sprintf(" ORDER BY created_at DESC, host ASC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]*DiscoveryResult, 0)
	for rows.Next() {
		r, err := scanDiscoveryResult(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func (s *PostgresStore) GetDiscoveryResult(ctx context.Context, id string) (*DiscoveryResult, error) {
	r, err := scanDiscoveryResult(s.pool.QueryRow(ctx,
		"SELECT "+discoveryResultColumns+" FROM public.discovery_results WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("discovery result %s not found", id)
	}
	return r, err
}

func (s *PostgresStore) MarkDiscoveryResultImported(ctx context.Context, id, certificateID string) error {
	// management_state moves with it: adopting a result settles the question it
	// was raised about, and a list that still called it unmanaged would keep
	// asking for work already done.
	tag, err := s.pool.Exec(ctx, `
		UPDATE public.discovery_results
		SET is_imported = true, imported_certificate_id = $2,
		    matched_certificate_id = $2, management_state = 'MANAGED'
		WHERE id = $1`, id, certificateID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("discovery result %s not found", id)
	}
	return nil
}
