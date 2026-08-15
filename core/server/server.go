package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/certpilot/certpilot/core/api"
	"github.com/certpilot/certpilot/core/engine/discovery"
	"github.com/certpilot/certpilot/core/engine/pki"
	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/engine/renewal"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/config"
	"github.com/gin-gonic/gin"
)

// Server encapsulates the HTTP API server and background engines.
type Server struct {
	httpServer    *http.Server
	store         store.Store
	pluginMgr     *pluginmgr.Manager
	caMonitor     *pki.CAMonitor
	renewalSched  *renewal.Scheduler
	cfg           *config.CoreConfig
}

// NewServer initializes the database, plugin manager, background engines, and HTTP routes.
func NewServer(ctx context.Context, cfg *config.CoreConfig, dbConnStr string) (*Server, error) {
	if cfg.Server.Mode == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// 1. Connect Store
	st, err := store.NewPostgresStore(ctx, dbConnStr)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// 2. Plugin Manager
	pm := pluginmgr.NewManager()

	// Register any static gateways from config
	for _, gw := range cfg.Plugins.Gateways {
		if gw.Addr != "" {
			_, err := pm.RegisterGateway(ctx, gw.Name, gw.Addr, gw.Type)
			if err != nil {
				slog.Warn("could not connect to static gateway on startup", "name", gw.Name, "addr", gw.Addr, "error", err)
			}
		}
	}

	// 3. Engines
	caMonitor := pki.NewCAMonitor(st)
	chainResolver := pki.NewChainResolver(st)
	renewalExec := renewal.NewExecutor(st, pm)
	renewalSched := renewal.NewScheduler(st, renewalExec, cfg.Renewal.DefaultLeadDays)
	policyEng := policy.NewEngine(st)
	scanner := discovery.NewScanner(st)

	// 4. HTTP Router
	engine := gin.New()
	engine.Use(gin.Logger())

	devMode := (cfg.Server.Mode != "production")
	api.SetupRouter(
		engine,
		st,
		pm,
		caMonitor,
		chainResolver,
		renewalExec,
		policyEng,
		scanner,
		cfg.Supabase.JWTSecret,
		devMode,
	)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	httpSrv := &http.Server{
		Addr:         addr,
		Handler:      engine,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return &Server{
		httpServer:   httpSrv,
		store:        st,
		pluginMgr:    pm,
		caMonitor:    caMonitor,
		renewalSched: renewalSched,
		cfg:          cfg,
	}, nil
}

// Start begins the HTTP server and background schedulers.
func (s *Server) Start() error {
	// Start background renewal scheduler
	scanInterval := time.Duration(s.cfg.Renewal.ScanInterval) * time.Minute
	if scanInterval <= 0 {
		scanInterval = 1 * time.Hour
	}
	s.renewalSched.Start(scanInterval)

	slog.Info("CertPilot Core HTTP API listening", "addr", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server, background schedulers, and store pool.
func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("shutting down CertPilot Core...")
	s.renewalSched.Stop()
	s.pluginMgr.Close()
	s.store.Close()
	return s.httpServer.Shutdown(ctx)
}
