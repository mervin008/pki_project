package api

import (
	"github.com/certpilot/certpilot/core/engine/discovery"
	"github.com/certpilot/certpilot/core/engine/pki"
	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/engine/renewal"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/config"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
)

// RouterDeps carries everything the API layer needs.
//
// This is a struct rather than a long parameter list because the previous
// signature had reached nine positional arguments, two of which were a string
// and a bool sitting next to each other — the shape where a call site silently
// swaps them.
type RouterDeps struct {
	Store         store.Store
	PluginMgr     *pluginmgr.Manager
	CAMonitor     *pki.CAMonitor
	ChainResolver *pki.ChainResolver
	RenewalExec   *renewal.Executor
	PolicyEngine  *policy.Engine
	Scanner       *discovery.Scanner
	Keyring       *secrets.Keyring
	Broker        *events.Broker
	Auth          *middleware.Authenticator
	Config        *config.CoreConfig
}

// SetupRouter configures all REST API routes and attaches middleware.
func SetupRouter(engine *gin.Engine, deps RouterDeps) {
	engine.Use(gin.Recovery())
	engine.Use(middleware.SecurityHeaders())
	engine.Use(middleware.CORS(deps.Config.Server.AllowedOrigins))

	// Health endpoint (public, and deliberately says nothing about internals).
	engine.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "service": "certpilot-core"})
	})

	certHandler := NewCertificateHandler(deps.Store, deps.PluginMgr, deps.RenewalExec, deps.PolicyEngine, deps.Keyring, deps.Broker)
	caHandler := NewCAHandler(deps.Store, deps.CAMonitor, deps.ChainResolver)
	caAccHandler := NewCAAccountHandler(deps.Store, deps.PluginMgr, deps.Keyring)
	dashHandler := NewDashboardHandler(deps.Store)
	discHandler := NewDiscoveryHandler(deps.Store, deps.Scanner)
	policyHandler := NewPolicyHandler(deps.Store)

	v1 := engine.Group("/api/v1")
	v1.Use(deps.Auth.Middleware())
	{
		// ── Dashboard ──
		v1.GET("/dashboard/stats", dashHandler.Stats)
		v1.GET("/dashboard/expiring", dashHandler.Expiring)
		v1.GET("/dashboard/activity", dashHandler.Activity)

		// ── Certificates ──
		v1.GET("/certificates", certHandler.List)
		v1.POST("/certificates", middleware.RequireRole(middleware.RoleOperator), certHandler.Create)
		v1.GET("/certificates/:id", certHandler.Get)
		v1.POST("/certificates/:id/renew", middleware.RequireRole(middleware.RoleOperator), certHandler.Renew)
		// Exporting a private key is admin-only and audited: it is the one
		// operation that removes a secret from the system's custody.
		v1.GET("/certificates/:id/private-key", middleware.RequireRole(middleware.RoleAdmin), certHandler.PrivateKey)
		v1.DELETE("/certificates/:id", middleware.RequireRole(middleware.RoleAdmin), certHandler.Delete)

		// ── PKI / CA Management ──
		v1.GET("/pki/authorities", caHandler.List)
		v1.POST("/pki/authorities", middleware.RequireRole(middleware.RoleOperator), caHandler.Create)
		v1.GET("/pki/authorities/:id", caHandler.Get)
		v1.GET("/pki/authorities/:id/chain", caHandler.Chain)
		v1.POST("/pki/authorities/:id/check", middleware.RequireRole(middleware.RoleOperator), caHandler.CheckHealth)
		v1.DELETE("/pki/authorities/:id", middleware.RequireRole(middleware.RoleAdmin), caHandler.Delete)
		v1.GET("/pki/tree", caHandler.HierarchyTree)

		// ── CA Accounts & Gateways ──
		v1.GET("/ca-accounts", caAccHandler.List)
		v1.POST("/ca-accounts", middleware.RequireRole(middleware.RoleOperator), caAccHandler.Create)
		v1.POST("/ca-accounts/:id/health", middleware.RequireRole(middleware.RoleOperator), caAccHandler.HealthCheck)
		v1.DELETE("/ca-accounts/:id", middleware.RequireRole(middleware.RoleAdmin), caAccHandler.Delete)
		v1.GET("/gateways", caAccHandler.ListGateways)

		// ── Discovery ──
		v1.POST("/discovery/scan", middleware.RequireRole(middleware.RoleOperator), discHandler.ScanEndpoint)
		v1.POST("/discovery/import", middleware.RequireRole(middleware.RoleOperator), discHandler.Import)

		// ── Policies ──
		v1.GET("/policies", policyHandler.List)
		v1.GET("/policies/:id", policyHandler.Get)
		v1.POST("/policies", middleware.RequireRole(middleware.RoleOperator), policyHandler.Create)
		v1.PUT("/policies/:id", middleware.RequireRole(middleware.RoleOperator), policyHandler.Update)
		v1.DELETE("/policies/:id", middleware.RequireRole(middleware.RoleAdmin), policyHandler.Delete)
	}
}
