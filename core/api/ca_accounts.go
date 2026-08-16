package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	providerv1 "github.com/certpilot/certpilot/pkg/pb/provider/v1"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
)

// CAAccountHandler handles CA account configurations and gateway plugin inspections.
type CAAccountHandler struct {
	store     store.Store
	pluginMgr *pluginmgr.Manager
	keyring   *secrets.Keyring
}

// NewCAAccountHandler creates a new CAAccountHandler.
func NewCAAccountHandler(s store.Store, pm *pluginmgr.Manager, kr *secrets.Keyring) *CAAccountHandler {
	return &CAAccountHandler{
		store:     s,
		pluginMgr: pm,
		keyring:   kr,
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

// CreateCAAccountInput is the payload for registering a CA account.
type CreateCAAccountInput struct {
	Name         string `json:"name" binding:"required"`
	ProviderType string `json:"provider_type" binding:"required"`
	GatewayAddr  string `json:"gateway_addr" binding:"required"`
	// ServerName overrides the name expected in the gateway's TLS certificate.
	ServerName string `json:"server_name"`
	// Config carries provider-specific settings — directory URLs, API tokens,
	// DNS credentials. It is validated by the gateway and then sealed before
	// it reaches the database; it is never returned by any endpoint.
	Config    map[string]any `json:"config"`
	IsDefault bool           `json:"is_default"`
}

// Create handles POST /api/v1/ca-accounts.
func (h *CAAccountHandler) Create(c *gin.Context) {
	var input CreateCAAccountInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	configJSON := ""
	if len(input.Config) > 0 {
		encoded, err := json.Marshal(input.Config)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("config is not serializable: %v", err)})
			return
		}
		configJSON = string(encoded)
	}

	acc := &store.CAAccount{
		Name:         input.Name,
		ProviderType: input.ProviderType,
		GatewayAddr:  input.GatewayAddr,
		IsDefault:    input.IsDefault,
		Status:       "DISCONNECTED",
	}

	// Connect first, so the gateway can vet the configuration before it is
	// stored. Discovering that a DNS token is wrong at configuration time is
	// far cheaper than discovering it during a renewal.
	var warnings []string
	gw, err := h.pluginMgr.RegisterGateway(c.Request.Context(), input.Name, input.GatewayAddr, input.ProviderType, input.ServerName)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"error": fmt.Sprintf("could not connect to the gateway at %s: %v", input.GatewayAddr, err),
		})
		return
	}
	acc.Status = "CONNECTED"

	validation, err := gw.Client.ValidateConfig(c.Request.Context(), &providerv1.ValidateConfigRequest{ConfigJson: configJSON})
	switch {
	case err != nil:
		warnings = append(warnings, fmt.Sprintf("gateway could not validate the configuration: %v", err))
	case !validation.Valid:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":            "the gateway rejected this configuration",
			"validation_error": validation.Errors,
			"warnings":         validation.Warnings,
		})
		return
	default:
		warnings = append(warnings, validation.Warnings...)
	}

	if configJSON != "" {
		sealed, err := h.keyring.EncryptString(configJSON, secrets.ContextCAAccountConfig)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("failed to encrypt the CA credentials; refusing to store them in the clear: %v", err),
			})
			return
		}
		acc.ConfigEncrypted = sealed
	}

	if err := h.store.CreateCAAccount(c.Request.Context(), acc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "ca_account.created",
		EntityType: "ca_account",
		EntityID:   &acc.ID,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		Details:    fmt.Sprintf(`{"name": %q, "provider_type": %q}`, acc.Name, acc.ProviderType),
	})

	c.JSON(http.StatusCreated, gin.H{"data": acc, "warnings": warnings})
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
		gw, err = h.pluginMgr.RegisterGateway(c.Request.Context(), acc.Name, acc.GatewayAddr, acc.ProviderType, "")
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
