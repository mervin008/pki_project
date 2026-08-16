package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/certpilot/certpilot/core/api"
	"github.com/certpilot/certpilot/core/engine/discovery"
	"github.com/certpilot/certpilot/core/engine/pki"
	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/engine/renewal"
	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/config"
	"github.com/certpilot/certpilot/pkg/grpckit"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
)

// Server encapsulates the HTTP API server and background engines.
type Server struct {
	httpServer   *http.Server
	store        store.Store
	pluginMgr    *pluginmgr.Manager
	caMonitor    *pki.CAMonitor
	broker       *events.Broker
	renewalSched *renewal.Scheduler
	cfg          *config.CoreConfig
}

// NewServer initializes the store, keyring, plugin manager, background engines,
// and HTTP routes.
func NewServer(ctx context.Context, cfg *config.CoreConfig, dbConnStr string) (*Server, error) {
	if cfg.Server.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}

	// 1. Store. A failed database connection is fatal when one was configured:
	// silently falling back to an in-memory store would let a production
	// deployment come up healthy and lose every certificate it issued.
	var st store.Store
	usingMemoryStore := false
	if dbConnStr != "" {
		pgStore, err := store.NewPostgresStore(ctx, dbConnStr)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to the database: %w", err)
		}
		st = pgStore
	} else {
		if cfg.Server.IsProduction() {
			return nil, fmt.Errorf("no database connection string configured; production mode requires a database")
		}
		slog.Warn("no database configured; using the in-memory store with sample data. Nothing is persisted")
		st = store.NewMemoryStore()
		usingMemoryStore = true
	}

	// 2. Keyring. Certificate private keys and CA credentials are sealed before
	// they reach the store, so a keyring is required whenever the store is.
	keyring, err := loadKeyring(usingMemoryStore)
	if err != nil {
		st.Close()
		return nil, err
	}

	// 3. Plugin manager.
	gwTLS := grpckit.TLSConfig{
		CertFile: cfg.Plugins.TLS.CertFile,
		KeyFile:  cfg.Plugins.TLS.KeyFile,
		CAFile:   cfg.Plugins.TLS.CAFile,
		Insecure: cfg.Plugins.TLS.Insecure,
	}
	if err := gwTLS.Validate(); err != nil {
		st.Close()
		return nil, fmt.Errorf("gateway TLS configuration is invalid: %w (generate development material with: make dev-certs)", err)
	}
	pm := pluginmgr.NewManager(gwTLS)

	for _, gw := range cfg.Plugins.Gateways {
		if gw.Addr == "" {
			continue
		}
		if _, err := pm.RegisterGateway(ctx, gw.Name, gw.Addr, gw.Type, gw.ServerName); err != nil {
			// A gateway that is down at startup is expected — it may simply
			// not be running yet — so this is a warning, and reconnection
			// happens on demand.
			slog.Warn("could not connect to configured gateway at startup",
				"name", gw.Name, "addr", gw.Addr, "error", err)
		}
	}

	// 4. Engines.
	//
	// The broker fans changes out to the dashboard stream and the notification
	// dispatcher. Nothing in the publish path can be blocked by a consumer, so
	// a stalled screen cannot stall the CA health sweep.
	broker := events.NewBroker()

	caMonitor := pki.NewCAMonitor(st, broker)
	chainResolver := pki.NewChainResolver(st)
	renewalExec := renewal.NewExecutor(st, pm, keyring, broker)
	renewalSched := renewal.NewScheduler(st, renewalExec, cfg.Renewal.DefaultLeadDays)
	policyEng := policy.NewEngine(st)
	scanner := discovery.NewScanner(st)

	// 5. Authentication.
	authenticator, err := middleware.NewAuthenticator(ctx, cfg.Auth)
	if err != nil {
		st.Close()
		return nil, err
	}

	// 6. HTTP router.
	engine := gin.New()
	// Not gin.Logger(): it writes the full request target, and display tokens
	// travel in the query string because EventSource cannot set a header.
	engine.Use(middleware.RequestLogger())

	api.SetupRouter(engine, api.RouterDeps{
		Store:         st,
		PluginMgr:     pm,
		CAMonitor:     caMonitor,
		ChainResolver: chainResolver,
		RenewalExec:   renewalExec,
		PolicyEngine:  policyEng,
		Scanner:       scanner,
		Keyring:       keyring,
		Broker:        broker,
		Auth:          authenticator,
		Config:        cfg,
	})

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return &Server{
		httpServer:   httpSrv,
		store:        st,
		pluginMgr:    pm,
		caMonitor:    caMonitor,
		broker:       broker,
		renewalSched: renewalSched,
		cfg:          cfg,
	}, nil
}

// loadKeyring resolves the key encryption key.
//
// An ephemeral key is acceptable only alongside the in-memory store, where
// nothing outlives the process anyway. Against a real database it would render
// every stored secret unreadable on restart, so it is refused.
func loadKeyring(usingMemoryStore bool) (*secrets.Keyring, error) {
	keyring, err := secrets.LoadKeyring()
	if err == nil {
		slog.Info("loaded secret encryption keyring", "key_id", keyring.PrimaryKeyID())
		return keyring, nil
	}

	if !errors.Is(err, secrets.ErrNoKey) {
		return nil, err
	}

	if !usingMemoryStore {
		return nil, fmt.Errorf(
			"CERTPILOT_KEK is not set. CertPilot stores certificate private keys and CA credentials " +
				"encrypted at rest and will not start without a key. Generate one with: make generate-kek")
	}

	keyring, err = secrets.NewEphemeralKeyring()
	if err != nil {
		return nil, err
	}
	slog.Warn("CERTPILOT_KEK is not set; using an ephemeral key alongside the in-memory store. " +
		"Set CERTPILOT_KEK before configuring a database")
	return keyring, nil
}

// Start begins the HTTP server and background schedulers.
func (s *Server) Start() error {
	scanInterval := time.Duration(s.cfg.Renewal.ScanInterval) * time.Minute
	if scanInterval <= 0 {
		scanInterval = time.Hour
	}
	s.renewalSched.Start(scanInterval)

	// An expiring CA takes down everything it signs, so this sweep has to run
	// on a timer rather than waiting for someone to open the dashboard.
	caInterval := time.Duration(s.cfg.PKI.CAHealthCheckInterval) * time.Minute
	if caInterval <= 0 {
		caInterval = 6 * time.Hour
	}
	s.caMonitor.Start(caInterval)

	slog.Info("CertPilot Core HTTP API listening", "addr", s.httpServer.Addr, "mode", s.cfg.Server.Mode)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server, background schedulers, and store pool.
func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("shutting down CertPilot Core")
	s.renewalSched.Stop()
	s.caMonitor.Stop()
	// Before the HTTP shutdown, so in-flight event-stream handlers wake and
	// return rather than holding the grace period open for its full duration.
	s.broker.Stop()
	s.pluginMgr.Close()
	s.store.Close()
	return s.httpServer.Shutdown(ctx)
}
