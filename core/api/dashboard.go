package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// DashboardHandler handles overview statistics and activity feeds.
type DashboardHandler struct {
	store store.Store
}

// NewDashboardHandler creates a new DashboardHandler.
func NewDashboardHandler(s store.Store) *DashboardHandler {
	return &DashboardHandler{store: s}
}

// Stats handles GET /api/v1/dashboard/stats.
func (h *DashboardHandler) Stats(c *gin.Context) {
	stats, err := h.store.GetDashboardStats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// Expiring handles GET /api/v1/dashboard/expiring (certs expiring soon).
func (h *DashboardHandler) Expiring(c *gin.Context) {
	certs, err := h.store.GetCertificatesDueForRenewal(c.Request.Context(), 30)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": certs, "total": len(certs)})
}

// maxActivityLimit caps how many audit entries one request may take. Generous
// enough for a day of alerts, small enough that a bad `limit` cannot be used to
// pull the whole audit table into memory in a single call.
const maxActivityLimit = 500

// Activity handles GET /api/v1/dashboard/activity (recent audit logs).
//
// Supports `action` (repeatable, or comma-separated), `entity_type`,
// `entity_id`, `since` (RFC 3339), `limit`, and `offset`.
//
// Filtering is the point of this endpoint rather than a refinement of it.
// Without it the feed was the newest twenty rows of a table that also carries
// every issuance, so on a busy day a CA expiry alert was pushed off the
// dashboard within minutes of being raised — recorded, and never seen.
func (h *DashboardHandler) Activity(c *gin.Context) {
	filter := store.AuditLogFilter{
		EntityType: c.Query("entity_type"),
		Limit:      20,
	}

	// audit_logs.entity_id is a uuid column, so PostgreSQL rejects a malformed
	// value with a type error rather than an empty result. Caught here it is a
	// 400 describing the problem; left to the driver it is a 500 that reads
	// like the server is broken.
	if raw := c.Query("entity_id"); raw != "" {
		if !isUUID(raw) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "entity_id must be a UUID"})
			return
		}
		filter.EntityID = raw
	}

	// Both `?action=a&action=b` and `?action=a,b` — the first is what an HTTP
	// client builds naturally, the second is what someone types by hand.
	for _, raw := range c.QueryArray("action") {
		for _, action := range strings.Split(raw, ",") {
			if action = strings.TrimSpace(action); action != "" {
				filter.Actions = append(filter.Actions, action)
			}
		}
	}

	if raw := c.Query("since"); raw != "" {
		since, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "since must be an RFC 3339 timestamp, for example 2026-08-16T09:00:00Z",
			})
			return
		}
		filter.Since = since
	}

	if raw := c.Query("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > maxActivityLimit {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("limit must be a whole number between 1 and %d", maxActivityLimit),
			})
			return
		}
		filter.Limit = limit
	}

	if raw := c.Query("offset"); raw != "" {
		offset, err := strconv.Atoi(raw)
		if err != nil || offset < 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "offset must be a non-negative whole number",
			})
			return
		}
		filter.Offset = offset
	}

	logs, total, err := h.store.ListAuditLogs(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// total counts the filtered set, so a client paging through CA alerts is
	// told how many alerts there are rather than how large the audit table is.
	c.JSON(http.StatusOK, gin.H{"data": logs, "total": total})
}

// isUUID reports whether s is a canonical 8-4-4-4-12 hex UUID.
//
// Hand-written rather than pulling in a UUID dependency for one format check:
// nothing here needs to parse, generate, or compare versions, only to reject a
// value PostgreSQL would refuse.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}
