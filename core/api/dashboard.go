package api

import (
	"net/http"

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

// Activity handles GET /api/v1/dashboard/activity (recent audit logs).
func (h *DashboardHandler) Activity(c *gin.Context) {
	logs, total, err := h.store.ListAuditLogs(c.Request.Context(), 20, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": logs, "total": total})
}
