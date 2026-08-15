// CertPilot Core Platform
//
// The central control plane for PKI management, automated certificate renewal,
// gateway plugin orchestration, and team collaboration.
//
// Usage:
//   go run ./core/cmd/ --config=config.dev.yaml
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/certpilot/certpilot/core/server"
	"github.com/certpilot/certpilot/pkg/config"
)

func main() {
	configPath := flag.String("config", "config.dev.yaml", "path to configuration YAML file")
	dbURLFlag := flag.String("db", "", "PostgreSQL database connection URL (or CERTPILOT_DB_URL env var)")
	flag.Parse()

	// Setup logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	slog.Info("initializing CertPilot Core", "config_file", *configPath)

	// Load configuration
	cfg, err := config.LoadCoreConfig(*configPath)
	if err != nil {
		slog.Warn("could not load config file, using environment/defaults", "error", err)
		cfg = &config.CoreConfig{
			Server: config.ServerConfig{Host: "0.0.0.0", Port: 8080, Mode: "development"},
			Renewal: config.RenewalConfig{ScanInterval: 60, DefaultLeadDays: 30},
			Plugins: config.PluginsConfig{
				Gateways: []config.GatewayConfig{
					{Name: "selfsigned", Addr: "localhost:9091", Type: "selfsigned"},
				},
			},
		}
	}

	// Determine Database URL
	dbConnStr := *dbURLFlag
	if dbConnStr == "" {
		dbConnStr = os.Getenv("CERTPILOT_DB_URL")
	}
	if dbConnStr == "" {
		dbConnStr = os.Getenv("DATABASE_URL")
	}

	if dbConnStr == "" {
		slog.Error("no database connection string provided. Set CERTPILOT_DB_URL or DATABASE_URL or pass --db")
		fmt.Println("\nTo connect to your Supabase PostgreSQL database, provide the connection string:")
		fmt.Println("  export CERTPILOT_DB_URL=\"postgresql://postgres.[ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres\"")
		fmt.Println("  or pass --db=\"...\"")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := server.NewServer(ctx, cfg, dbConnStr)
	if err != nil {
		slog.Error("failed to initialize server", "error", err)
		os.Exit(1)
	}

	// Graceful shutdown handling
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Info("received termination signal, initiating graceful shutdown", "signal", sig)

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("error during server shutdown", "error", err)
		}
		cancel()
	}()

	if err := srv.Start(); err != nil && err != http.ErrServerClosed {
		slog.Error("server encountered fatal error", "error", err)
		os.Exit(1)
	}

	slog.Info("CertPilot Core shutdown complete")
}
