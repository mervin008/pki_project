package api

import (
	"github.com/certpilot/certpilot/core/engine/cloudsync"
	"github.com/certpilot/certpilot/core/engine/ctlog"
	"github.com/certpilot/certpilot/core/engine/discovery"
	"github.com/certpilot/certpilot/core/engine/notifications"
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
	RenewalSched  *renewal.Scheduler
	RenewalQueue  *renewal.Queue
	ARIPoller     *renewal.ARIPoller
	Verifier      *renewal.Verifier
	PolicyEngine  *policy.Engine
	Scanner       *discovery.Scanner
	CTMonitor     *ctlog.Monitor
	CloudEngine   *cloudsync.Engine
	Keyring       *secrets.Keyring
	Broker        *events.Broker
	Dispatcher    *notifications.Dispatcher
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

	certHandler := NewCertificateHandler(deps.Store, deps.PluginMgr, deps.RenewalExec, deps.RenewalSched, deps.PolicyEngine, deps.Keyring, deps.Broker)
	renewalHandler := NewRenewalHandler(deps.Store, deps.RenewalSched, deps.ARIPoller, deps.Verifier)
	caHandler := NewCAHandler(deps.Store, deps.CAMonitor, deps.ChainResolver)
	caAccHandler := NewCAAccountHandler(deps.Store, deps.PluginMgr, deps.Keyring)
	dashHandler := NewDashboardHandler(deps.Store)
	discHandler := NewDiscoveryHandler(deps.Store, deps.Scanner)
	policyHandler := NewPolicyHandler(deps.Store)
	eventsHandler := NewEventsHandler(deps.Store, deps.Broker)
	displayHandler := NewDisplayTokenHandler(deps.Store)
	notifHandler := NewNotificationHandler(deps.Store, deps.Keyring, deps.Dispatcher)
	ackHandler := NewAcknowledgementHandler(deps.Store)
	ctHandler := NewCTHandler(deps.Store, deps.CTMonitor)
	cloudHandler := NewCloudHandler(deps.Store, deps.CloudEngine, deps.Keyring)

	v1 := engine.Group("/api/v1")
	// Display tokens are resolved first, and only take effect when no
	// Authorization header was sent. The middleware itself refuses anything
	// that is not a GET and refuses the sensitive read paths outright, so the
	// read-only property does not depend on every route below getting its role
	// gate right.
	v1.Use(middleware.DisplayTokenAuth(deps.Store))
	v1.Use(deps.Auth.Middleware())
	{
		// ── Live event stream ──
		// Any authenticated reader may watch; the stream carries CA and
		// certificate state, never secrets or actor identity.
		v1.GET("/events", eventsHandler.Stream)

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
		// Acknowledgement is an operator action: it is a statement that a
		// human has looked, and it needs a human's name against it.
		v1.POST("/pki/authorities/:id/acknowledge", middleware.RequireRole(middleware.RoleOperator), ackHandler.Acknowledge)
		v1.DELETE("/pki/authorities/:id/acknowledge", middleware.RequireRole(middleware.RoleOperator), ackHandler.Withdraw)
		v1.GET("/pki/authorities/:id/acknowledgements", ackHandler.History)
		v1.PUT("/pki/authorities/:id/owner", middleware.RequireRole(middleware.RoleOperator), ackHandler.SetOwner)

		// ── CA Accounts & Gateways ──
		v1.GET("/ca-accounts", caAccHandler.List)
		v1.POST("/ca-accounts", middleware.RequireRole(middleware.RoleOperator), caAccHandler.Create)
		v1.POST("/ca-accounts/:id/health", middleware.RequireRole(middleware.RoleOperator), caAccHandler.HealthCheck)
		v1.DELETE("/ca-accounts/:id", middleware.RequireRole(middleware.RoleAdmin), caAccHandler.Delete)
		// Narrow on purpose: the only field on a CA account that can change
		// without re-validating the configuration through the gateway.
		v1.PUT("/ca-accounts/:id/rate-limit", middleware.RequireRole(middleware.RoleOperator), caAccHandler.SetRateLimit)
		v1.GET("/gateways", caAccHandler.ListGateways)

		// ── Discovery ──
		// Scanning is operator, not viewer: it opens connections to third-party
		// infrastructure from CertPilot's address, which is an action taken in
		// the organisation's name rather than a read of its own state.
		v1.POST("/discovery/scan", middleware.RequireRole(middleware.RoleOperator), discHandler.Scan)
		v1.POST("/discovery/import", middleware.RequireRole(middleware.RoleOperator), discHandler.Import)
		// Reading what past scans found is open to any authenticated user. It
		// is estate state, the same as the CA list.
		v1.GET("/discovery/scans", discHandler.ListScans)
		v1.GET("/discovery/scans/:id", discHandler.GetScan)
		// Stopping a scan is an operator action for the same reason starting one
		// is: it changes what CertPilot is doing to somebody else's network.
		v1.POST("/discovery/scans/:id/cancel", middleware.RequireRole(middleware.RoleOperator), discHandler.CancelScan)
		v1.GET("/discovery/results", discHandler.ListResults)
		// Schedules. Reading is open to any authenticated user; writing is
		// operator, because a schedule is a standing instruction to connect to
		// somebody else's network on a timer.
		v1.GET("/discovery/schedules", discHandler.ListSchedules)
		v1.POST("/discovery/schedules", middleware.RequireRole(middleware.RoleOperator), discHandler.CreateSchedule)
		v1.PUT("/discovery/schedules/:id", middleware.RequireRole(middleware.RoleOperator), discHandler.UpdateSchedule)
		v1.DELETE("/discovery/schedules/:id", middleware.RequireRole(middleware.RoleAdmin), discHandler.DeleteSchedule)
		v1.POST("/discovery/schedules/:id/run", middleware.RequireRole(middleware.RoleOperator), discHandler.RunSchedule)

		// ── Certificate Transparency ──
		// The half of discovery a network scan cannot reach: what has been
		// issued in your name, whether or not it was ever deployed.
		v1.GET("/ct/monitors", ctHandler.ListMonitors)
		v1.POST("/ct/monitors", middleware.RequireRole(middleware.RoleOperator), ctHandler.CreateMonitor)
		v1.PUT("/ct/monitors/:id", middleware.RequireRole(middleware.RoleOperator), ctHandler.UpdateMonitor)
		v1.DELETE("/ct/monitors/:id", middleware.RequireRole(middleware.RoleAdmin), ctHandler.DeleteMonitor)
		v1.POST("/ct/monitors/:id/check", middleware.RequireRole(middleware.RoleOperator), ctHandler.CheckMonitor)
		v1.GET("/ct/certificates", ctHandler.ListCertificates)

		// ── Cloud inventory ──
		// The third place certificates hide: stored rather than served, in an
		// account a scan has no address for. Reading is open to any
		// authenticated user — the list never carries the sealed credentials.
		v1.GET("/cloud/connections", cloudHandler.ListConnections)
		v1.POST("/cloud/connections", middleware.RequireRole(middleware.RoleOperator), cloudHandler.CreateConnection)
		v1.PUT("/cloud/connections/:id", middleware.RequireRole(middleware.RoleOperator), cloudHandler.UpdateConnection)
		v1.DELETE("/cloud/connections/:id", middleware.RequireRole(middleware.RoleAdmin), cloudHandler.DeleteConnection)
		// Reaching out to somebody else's account with stored credentials is an
		// action, not a read, which is why it is a POST and gated at operator.
		v1.POST("/cloud/connections/:id/sync", middleware.RequireRole(middleware.RoleOperator), cloudHandler.SyncConnection)
		v1.GET("/cloud/certificates", cloudHandler.ListCertificates)
		v1.POST("/cloud/import", middleware.RequireRole(middleware.RoleOperator), cloudHandler.ImportCertificate)

		// ── Renewal queue ──
		// Renewal is the only part of this system that changes the world, so
		// what it is about to do is readable rather than inferred from logs.
		v1.GET("/renewals", renewalHandler.List)
		v1.GET("/renewals/:id", renewalHandler.Get)
		// Cancelling stops a renewal somebody asked for. Admin, because the
		// certificate then goes back to expiring on its own with nothing
		// scheduled to stop it.
		v1.DELETE("/renewals/:id", middleware.RequireRole(middleware.RoleAdmin), renewalHandler.Cancel)
		// Ask the CA now what it thinks about one certificate. Reaching out to
		// somebody else's CA is an action, not a read.
		v1.POST("/certificates/:id/renewal-info", middleware.RequireRole(middleware.RoleOperator), renewalHandler.RefreshRenewalInfo)
		// Check now whether a renewal actually reached the servers it was for.
		v1.POST("/certificates/:id/verify", middleware.RequireRole(middleware.RoleOperator), renewalHandler.Verify)

		// ── Display Tokens ──
		// Admin-only throughout: minting a credential that authenticates to
		// the API is an administrative act even though what it grants is
		// read-only.
		v1.GET("/display-tokens", middleware.RequireRole(middleware.RoleAdmin), displayHandler.List)
		v1.POST("/display-tokens", middleware.RequireRole(middleware.RoleAdmin), displayHandler.Create)
		v1.DELETE("/display-tokens/:id", middleware.RequireRole(middleware.RoleAdmin), displayHandler.Revoke)

		// ── Notification channels ──
		// Reading is open to any authenticated user: the list carries names,
		// types, and thresholds, never the sealed credentials. Writing is
		// operator, deletion admin — removing a channel silently stops alerts
		// reaching whoever depended on it.
		v1.GET("/notification-channels", notifHandler.List)
		v1.POST("/notification-channels", middleware.RequireRole(middleware.RoleOperator), notifHandler.Create)
		v1.PUT("/notification-channels/:id", middleware.RequireRole(middleware.RoleOperator), notifHandler.Update)
		v1.DELETE("/notification-channels/:id", middleware.RequireRole(middleware.RoleAdmin), notifHandler.Delete)
		// Sending a real alert to a real destination is an action, not a read,
		// which is why it is a POST and gated at operator.
		v1.POST("/notification-channels/:id/test", middleware.RequireRole(middleware.RoleOperator), notifHandler.Test)

		// ── Policies ──
		v1.GET("/policies", policyHandler.List)
		v1.GET("/policies/:id", policyHandler.Get)
		v1.POST("/policies", middleware.RequireRole(middleware.RoleOperator), policyHandler.Create)
		v1.PUT("/policies/:id", middleware.RequireRole(middleware.RoleOperator), policyHandler.Update)
		v1.DELETE("/policies/:id", middleware.RequireRole(middleware.RoleAdmin), policyHandler.Delete)
	}
}
