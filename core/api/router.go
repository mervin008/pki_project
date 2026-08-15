package api

import (
	"github.com/certpilot/certpilot/core/engine/discovery"
	"github.com/certpilot/certpilot/core/engine/pki"
	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/engine/renewal"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// SetupRouter configures all REST API routes and attaches middleware.
func SetupRouter(
	engine *gin.Engine,
	store store.Store,
	pluginMgr *pluginmgr.Manager,
	caMonitor *pki.CAMonitor,
	chainResolver *pki.ChainResolver,
	renewalExec *renewal.Executor,
	policyEng *policy.Engine,
	scanner *discovery.Scanner,
	jwtSecret string,
	devMode bool,
) {
	// Global middleware
	engine.Use(middleware.CORS())
	engine.Use(gin.Recovery())

	// Health endpoint (public)
	engine.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "service": "certpilot-core"})
	})

	// Handlers
	certHandler := NewCertificateHandler(store, pluginMgr, renewalExec, policyEng)
	caHandler := NewCAHandler(store, caMonitor, chainResolver)
	caAccHandler := NewCAAccountHandler(store, pluginMgr)
	dashHandler := NewDashboardHandler(store)
	discHandler := NewDiscoveryHandler(store, scanner)
	policyHandler := NewPolicyHandler(store)

	v1 := engine.Group("/api/v1")
	v1.Use(middleware.AuthMiddleware(jwtSecret, devMode))
	{
		// ── Dashboard ──
		v1.GET("/dashboard/stats", dashHandler.Stats)
		v1.GET("/dashboard/expiring", dashHandler.Expiring)
		v1.GET("/dashboard/activity", dashHandler.Activity)

		// ── Certificates ──
		v1.GET("/certificates", certHandler.List)
		v1.POST("/certificates", middleware.RequireRole("admin", "operator"), certHandler.Create)
		v1.GET("/certificates/:id", certHandler.Get)
		v1.POST("/certificates/:id/renew", middleware.RequireRole("admin", "operator"), certHandler.Renew)
		v1.DELETE("/certificates/:id", middleware.RequireRole("admin"), certHandler.Delete)

		// ── PKI / CA Management ──
		v1.GET("/pki/authorities", caHandler.List)
		v1.POST("/pki/authorities", middleware.RequireRole("admin", "operator"), caHandler.Create)
		v1.GET("/pki/authorities/:id", caHandler.Get)
		v1.GET("/pki/authorities/:id/chain", caHandler.Chain)
		v1.POST("/pki/authorities/:id/check", middleware.RequireRole("admin", "operator"), caHandler.CheckHealth)
		v1.DELETE("/pki/authorities/:id", middleware.RequireRole("admin"), caHandler.Delete)
		v1.GET("/pki/tree", caHandler.HierarchyTree)

		// ── CA Accounts & Gateways ──
		v1.GET("/ca-accounts", caAccHandler.List)
		v1.POST("/ca-accounts", middleware.RequireRole("admin", "operator"), caAccHandler.Create)
		v1.POST("/ca-accounts/:id/health", middleware.RequireRole("admin", "operator"), caAccHandler.HealthCheck)
		v1.DELETE("/ca-accounts/:id", middleware.RequireRole("admin"), caAccHandler.Delete)
		v1.GET("/gateways", caAccHandler.ListGateways)

		// ── Discovery ──
		v1.POST("/discovery/scan", middleware.RequireRole("admin", "operator"), discHandler.ScanEndpoint)
		v1.POST("/discovery/import", middleware.RequireRole("admin", "operator"), discHandler.Import)

		// ── Policies ──
		v1.GET("/policies", policyHandler.List)
		v1.GET("/policies/:id", policyHandler.Get)
		v1.POST("/policies", middleware.RequireRole("admin", "operator"), policyHandler.Create)
		v1.PUT("/policies/:id", middleware.RequireRole("admin", "operator"), policyHandler.Update)
		v1.DELETE("/policies/:id", middleware.RequireRole("admin"), policyHandler.Delete)
	}
}
