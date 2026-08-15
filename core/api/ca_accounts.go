package api

import (
	"fmt"
	"net/http"

	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/store"
	providerv1 "github.com/certpilot/certpilot/pkg/pb/provider/v1"
	"github.com/gin-gonic/gin"
)

// CAAccountHandler handles CA account configurations and gateway plugin inspections.
type CAAccountHandler struct {
	store     store.Store
	pluginMgr *pluginmgr.Manager
}

// NewCAAccountHandler creates a new CAAccountHandler.
func NewCAAccountHandler(s store.Store, pm *pluginmgr.Manager) *CAAccountHandler {
	return &CAAccountHandler{
		store:     s,
		pluginMgr: pm,
	}
}

// List handles GET /api/v1/ca-accounts.
func (h *CAAccountHandler) List(c *gin.Context) {
	accounts, err := h.store.ListCAAccounts(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": accounts, "total": len(accounts)})
}

// ListGateways handles GET /api/v1/gateways (active connected plugin binaries).
func (h *CAAccountHandler) ListGateways(c *gin.Context) {
	gws := h.pluginMgr.ListGateways()
	type GatewaySummary struct {
		Name         string      `json:"name"`
		Addr         string      `json:"addr"`
		Type         string      `json:"type"`
		IsConnected  bool        `json:"is_connected"`
		Capabilities interface{} `json:"capabilities"`
		LastChecked  string      `json:"last_checked"`
	}

	summaries := make([]GatewaySummary, 0, len(gws))
	for _, gw := range gws {
		summaries = append(summaries, GatewaySummary{
			Name:         gw.Name,
			Addr:         gw.Addr,
			Type:         gw.Type,
			IsConnected:  gw.IsConnected,
			Capabilities: gw.Capabilities,
			LastChecked:  gw.LastChecked.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	c.JSON(http.StatusOK, gin.H{"data": summaries, "total": len(summaries)})
}

// Create handles POST /api/v1/ca-accounts.
func (h *CAAccountHandler) Create(c *gin.Context) {
	var acc store.CAAccount
	if err := c.ShouldBindJSON(&acc); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	acc.Status = "DISCONNECTED"

	// Check if we can connect to the gateway address
	if acc.GatewayAddr != "" {
		gw, err := h.pluginMgr.RegisterGateway(c.Request.Context(), acc.Name, acc.GatewayAddr, acc.ProviderType)
		if err == nil && gw.IsConnected {
			acc.Status = "CONNECTED"
		}
	}

	if err := h.store.CreateCAAccount(c.Request.Context(), &acc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, acc)
}

// HealthCheck handles POST /api/v1/ca-accounts/:id/health.
func (h *CAAccountHandler) HealthCheck(c *gin.Context) {
	id := c.Param("id")
	acc, err := h.store.GetCAAccount(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	gw, err := h.pluginMgr.GetGateway(acc.Name)
	if err != nil {
		// Try to register/reconnect
		gw, err = h.pluginMgr.RegisterGateway(c.Request.Context(), acc.Name, acc.GatewayAddr, acc.ProviderType)
		if err != nil {
			acc.Status = "ERROR"
			_ = h.store.UpdateCAAccount(c.Request.Context(), acc)
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": fmt.Sprintf("failed to reach gateway: %v", err)})
			return
		}
	}

	resp, err := gw.Client.HealthCheck(c.Request.Context(), &providerv1.HealthCheckRequest{})
	if err != nil {
		acc.Status = "ERROR"
		_ = h.store.UpdateCAAccount(c.Request.Context(), acc)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": fmt.Sprintf("gateway health check failed: %v", err)})
		return
	}

	acc.Status = "CONNECTED"
	_ = h.store.UpdateCAAccount(c.Request.Context(), acc)

	c.JSON(http.StatusOK, gin.H{
		"status":     resp.Status.String(),
		"message":    resp.Message,
		"latency_ms": resp.LatencyMs,
	})
}

// Delete handles DELETE /api/v1/ca-accounts/:id.
func (h *CAAccountHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.DeleteCAAccount(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "CA account removed"})
}
