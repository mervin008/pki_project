package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/engine/discovery"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/x509util"
	"github.com/gin-gonic/gin"
)

// maxTargetsPerScan bounds one request.
//
// A scan is an outbound connection to somebody's infrastructure, made on behalf
// of whoever called this endpoint. Without a cap, a single request with a
// generated list is a port scanner with CertPilot's return address on it. The
// limit is deliberately low enough that reaching it is a prompt to think about
// what is being scanned rather than an obstacle to a legitimate run.
const maxTargetsPerScan = 256

// DiscoveryHandler handles network TLS scanning and certificate discovery.
type DiscoveryHandler struct {
	store   store.Store
	scanner *discovery.Scanner
	broker  *events.Broker
}

// NewDiscoveryHandler creates a new DiscoveryHandler.
func NewDiscoveryHandler(s store.Store, sc *discovery.Scanner, broker *events.Broker) *DiscoveryHandler {
	return &DiscoveryHandler{store: s, scanner: sc, broker: broker}
}

// ScanEndpointInput defines the payload to scan one or more endpoints.
type ScanEndpointInput struct {
	// Targets accepts "host", "host:port", or "[v6]:port".
	Targets []string `json:"targets"`
	// Host is the single-target form, kept because it is what the existing
	// dashboard sends.
	Host string `json:"host"`
	// Port applies to any target that does not name its own.
	Port int `json:"port"`
}

// Scan handles POST /api/v1/discovery/scan.
//
// Synchronous: the caller waits for the result. That holds while a scan is a
// list of endpoints someone typed. It stops holding for a CIDR range, which is
// why the scan record exists as a first-class row rather than as a wrapper
// around the response — the same run becomes a background job without the
// stored shape changing.
func (h *DiscoveryHandler) Scan(c *gin.Context) {
	var input ScanEndpointInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	raw := append([]string{}, input.Targets...)
	if strings.TrimSpace(input.Host) != "" {
		raw = append(raw, input.Host)
	}
	if len(raw) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "give at least one target, as `targets: [\"host\"]` or `host: \"…\"`",
		})
		return
	}
	if len(raw) > maxTargetsPerScan {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("a single scan is limited to %d targets; %d were given", maxTargetsPerScan, len(raw)),
		})
		return
	}

	// Every target is parsed before any is scanned. A run that scanned nine
	// hosts and then rejected the tenth would leave the operator unable to say
	// which part of their list was actually looked at.
	targets := make([]discovery.Target, 0, len(raw))
	for _, r := range raw {
		target, err := discovery.ParseTarget(r, input.Port)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		targets = append(targets, target)
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	req := discovery.ScanRequest{Targets: targets}
	if actorID != "" {
		req.TriggeredBy = &actorID
	}
	if actorEmail != "" {
		req.ActorEmail = &actorEmail
	}

	scan, results, err := h.scanner.Scan(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.auditScan(c, scan)
	h.announce(scan, results)

	c.JSON(http.StatusOK, gin.H{
		"scan":    scan,
		"data":    results,
		"total":   len(results),
		"summary": summarize(scan),
	})
}

// summarize states the outcome in a sentence, because the counts alone are
// ambiguous in the one direction that matters: zero unmanaged certificates and
// zero reachable endpoints look identical on a tile and mean opposite things.
func summarize(scan *store.DiscoveryScan) string {
	switch {
	case scan.ResultsCount == 0:
		return "Nothing was scanned."
	case scan.UnreachableCount == scan.ResultsCount:
		return fmt.Sprintf("None of the %d endpoints answered, so nothing was learned about them.", scan.ResultsCount)
	case scan.UnmanagedCount == 0:
		return fmt.Sprintf("Every certificate found is already managed (%d of %d endpoints answered).",
			scan.ResultsCount-scan.UnreachableCount, scan.ResultsCount)
	default:
		return fmt.Sprintf("%d certificate(s) are being served that CertPilot does not manage. Nothing renews them.",
			scan.UnmanagedCount)
	}
}

// announce puts unmanaged findings on the event stream, so they reach the
// channels a team already configured instead of waiting to be noticed on a
// screen nobody has open.
func (h *DiscoveryHandler) announce(scan *store.DiscoveryScan, results []*store.DiscoveryResult) {
	if h.broker == nil || scan.UnmanagedCount == 0 {
		return
	}

	hosts := make([]string, 0, scan.UnmanagedCount)
	for _, r := range results {
		if r.ManagementState == store.DiscoveryUnmanaged {
			hosts = append(hosts, fmt.Sprintf("%s:%d", r.Host, r.Port))
		}
		if len(hosts) == 10 {
			break
		}
	}

	h.broker.Publish(events.Event{
		Topic:    events.TopicDiscoveryUnmanaged,
		Severity: events.SeverityWarning,
		EntityID: scan.ID,
		Payload: map[string]any{
			"scan_id":         scan.ID,
			"unmanaged_count": scan.UnmanagedCount,
			"scanned_count":   scan.ResultsCount,
			"hosts":           hosts,
		},
	})
}

// ListScans handles GET /api/v1/discovery/scans.
func (h *DiscoveryHandler) ListScans(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	scans, total, err := h.store.ListDiscoveryScans(c.Request.Context(), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": scans, "total": total})
}

// GetScan handles GET /api/v1/discovery/scans/:id, returning the run and its
// results.
func (h *DiscoveryHandler) GetScan(c *gin.Context) {
	scan, err := h.store.GetDiscoveryScan(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	results, total, err := h.store.ListDiscoveryResults(c.Request.Context(), store.DiscoveryResultFilter{
		ScanID:          scan.ID,
		ManagementState: strings.ToUpper(c.Query("management_state")),
		TrustState:      strings.ToUpper(c.Query("trust_state")),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scan":    scan,
		"data":    results,
		"total":   total,
		"summary": summarize(scan),
	})
}

// ListResults handles GET /api/v1/discovery/results — findings across every
// scan, which is how "everything we have ever found and not adopted" is asked.
func (h *DiscoveryHandler) ListResults(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	filter := store.DiscoveryResultFilter{
		ScanID:          c.Query("scan_id"),
		ManagementState: strings.ToUpper(c.Query("management_state")),
		TrustState:      strings.ToUpper(c.Query("trust_state")),
		Host:            c.Query("host"),
		UnimportedOnly:  c.Query("unimported") == "true",
		Limit:           limit,
		Offset:          offset,
	}

	results, total, err := h.store.ListDiscoveryResults(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": results, "total": total})
}

// ImportDiscoveredInput adopts a discovered certificate into managed inventory.
type ImportDiscoveredInput struct {
	// ResultID adopts something a scan found, which is the normal path — it
	// carries the chain and the endpoint it was seen on.
	ResultID string `json:"result_id"`
	// CertificatePEM adopts a certificate someone has in hand instead.
	CertificatePEM  string `json:"certificate_pem"`
	CAAccountID     string `json:"ca_account_id"`
	AutoRenew       bool   `json:"auto_renew"`
	RenewalLeadDays int    `json:"renewal_lead_days"`
	Environment     string `json:"environment"`
	Team            string `json:"team"`
}

// Import handles POST /api/v1/discovery/import.
//
// What this does *not* do is give the certificate a renewal path. CertPilot
// holds no private key for something it merely observed, so an imported
// certificate is watched and reported on, and renewing it still means issuing a
// new one. Saying so in the response matters: `auto_renew` on a record with no
// key is a promise the system cannot keep, and finding that out at expiry is
// worse than never having imported it.
func (h *DiscoveryHandler) Import(c *gin.Context) {
	var input ImportDiscoveredInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var result *store.DiscoveryResult
	certPEM := strings.TrimSpace(input.CertificatePEM)

	switch {
	case input.ResultID != "":
		var err error
		result, err = h.store.GetDiscoveryResult(c.Request.Context(), input.ResultID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		if result.CertificatePEM == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "that result holds no certificate — the endpoint did not complete a handshake",
			})
			return
		}
		certPEM = result.CertificatePEM
	case certPEM == "":
		c.JSON(http.StatusBadRequest, gin.H{"error": "give either result_id or certificate_pem"})
		return
	}

	info, err := x509util.ParseCertificatePEM([]byte(certPEM))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("that is not a readable certificate: %v", err)})
		return
	}

	// Already-managed is a success, not a conflict. Two people adopting the
	// same finding should converge on one record rather than one of them
	// getting an error they have to interpret.
	if existing, err := h.store.GetCertificateByFingerprint(c.Request.Context(), info.FingerprintSHA256); err == nil && existing != nil {
		if result != nil {
			_ = h.store.MarkDiscoveryResultImported(c.Request.Context(), result.ID, existing.ID)
		}
		c.JSON(http.StatusOK, gin.H{
			"data":    existing,
			"message": fmt.Sprintf("This certificate was already managed as %q; the discovery result now points at it.", existing.CommonName),
		})
		return
	}

	notBefore, notAfter := info.NotBefore, info.NotAfter
	pemCopy := certPEM
	actorID := c.GetString(middleware.ContextUserID)
	var createdBy *string
	if actorID != "" {
		createdBy = &actorID
	}

	cert := &store.Certificate{
		FingerprintSHA256: info.FingerprintSHA256,
		CommonName:        info.CommonName,
		SANs:              info.SANs,
		SerialNumber:      info.SerialNumber,
		IssuerDN:          info.IssuerDN,
		NotBefore:         &notBefore,
		NotAfter:          &notAfter,
		DaysRemaining:     info.DaysRemaining,
		KeyType:           info.KeyType,
		KeySize:           info.KeySize,
		Status:            importedStatus(info.NotAfter, time.Now()),
		// Never true on import, whatever was asked for. Renewal needs a private
		// key and a CA account; an observed certificate has neither, and a
		// record that claims it will renew itself is the failure mode this
		// whole product exists to prevent.
		AutoRenew:       false,
		RenewalLeadDays: input.RenewalLeadDays,
		CertificatePEM:  &pemCopy,
		DiscoveredVia:   "SCAN",
		Environment:     input.Environment,
		Team:            input.Team,
		CreatedBy:       createdBy,
	}
	if result != nil && result.ChainPEM != "" {
		chain := result.ChainPEM
		cert.ChainPEM = &chain
	}
	if input.CAAccountID != "" {
		cert.CAAccountID = &input.CAAccountID
	}

	if err := h.store.CreateCertificate(c.Request.Context(), cert); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if result != nil {
		if err := h.store.MarkDiscoveryResultImported(c.Request.Context(), result.ID, cert.ID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("the certificate was imported as %s but the discovery result could not be linked to it: %v", cert.ID, err),
			})
			return
		}
	}

	actorEmail := c.GetString(middleware.ContextUserEmail)
	ip := c.ClientIP()
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "discovery.imported",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		ActorID:    createdBy,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		Details: fmt.Sprintf(`{"cn":%q,"fingerprint":%q,"not_after":%q,"source":%q}`,
			cert.CommonName, cert.FingerprintSHA256, notAfter.Format(time.RFC3339), importSource(result)),
	})

	c.JSON(http.StatusCreated, gin.H{
		"data": cert,
		"message": "Imported and now watched for expiry. CertPilot holds no private key for it, " +
			"so it cannot be renewed automatically — replacing it means issuing a new certificate.",
	})
}

// importedStatus reports where an observed certificate sits in its life, which
// is not always ISSUED: plenty of what a first scan finds is already expired.
func importedStatus(notAfter, now time.Time) string {
	switch {
	case now.After(notAfter):
		return "EXPIRED"
	case notAfter.Sub(now) <= 30*24*time.Hour:
		return "EXPIRING"
	default:
		return "ISSUED"
	}
}

func importSource(result *store.DiscoveryResult) string {
	if result == nil {
		return "pasted"
	}
	return fmt.Sprintf("%s:%d", result.Host, result.Port)
}

func (h *DiscoveryHandler) auditScan(c *gin.Context, scan *store.DiscoveryScan) {
	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	ip := c.ClientIP()
	id := scan.ID

	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "discovery.scan",
		EntityType: "discovery_scan",
		EntityID:   &id,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		// The targets are the point of this entry. Scanning is an outbound act
		// against third-party infrastructure, and "who asked us to connect to
		// that" has to be answerable afterwards.
		Details: fmt.Sprintf(`{"targets":%s,"results":%d,"unmanaged":%d,"unreachable":%d}`,
			jsonStringArray(scan.Targets), scan.ResultsCount, scan.UnmanagedCount, scan.UnreachableCount),
	})
}

func jsonStringArray(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, strconv.Quote(v))
	}
	return "[" + strings.Join(quoted, ",") + "]"
}
