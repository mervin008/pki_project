package api

import (
	"fmt"
	"net/http"

	"github.com/certpilot/certpilot/core/engine/discovery"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// DiscoveryHandler handles network TLS scanning and certificate discovery.
type DiscoveryHandler struct {
	store   store.Store
	scanner *discovery.Scanner
}

// NewDiscoveryHandler creates a new DiscoveryHandler.
func NewDiscoveryHandler(s store.Store, sc *discovery.Scanner) *DiscoveryHandler {
	return &DiscoveryHandler{
		store:   s,
		scanner: sc,
	}
}

// ScanEndpointInput defines the payload to scan a host/port.
type ScanEndpointInput struct {
	Host string `json:"host" binding:"required"`
	Port int    `json:"port"`
}

// ScanEndpoint handles POST /api/v1/discovery/scan.
func (h *DiscoveryHandler) ScanEndpoint(c *gin.Context) {
	var input ScanEndpointInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.scanner.ScanEndpoint(c.Request.Context(), input.Host, input.Port)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// ImportDiscoveredInput defines importing a discovered certificate into managed inventory.
type ImportDiscoveredInput struct {
	CertificatePEM  string `json:"certificate_pem" binding:"required"`
	CAAccountID     string `json:"ca_account_id"`
	AutoRenew       bool   `json:"auto_renew"`
	RenewalLeadDays int    `json:"renewal_lead_days"`
	Environment     string `json:"environment"`
	Team            string `json:"team"`
}

// Import handles POST /api/v1/discovery/import.
func (h *DiscoveryHandler) Import(c *gin.Context) {
	var input ImportDiscoveredInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cHandler := &CertificateHandler{store: h.store}
	_ = cHandler // Can reuse or insert directly
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Import feature ready")})
}
