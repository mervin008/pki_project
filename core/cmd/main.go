// CertPilot Core Platform
//
// The central control plane for PKI management, automated certificate renewal,
// gateway plugin orchestration, and team collaboration.
//
// Usage:
//
//	go run ./core/cmd/ --config=config.dev.yaml
package main

import (
	"context"
	"errors"
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
	"github.com/certpilot/certpilot/pkg/grpckit"
	"github.com/certpilot/certpilot/pkg/secrets"
)

func main() {
	configPath := flag.String("config", "config.dev.yaml", "path to configuration YAML file")
	dbURLFlag := flag.String("db", "", "PostgreSQL database connection URL (or CERTPILOT_DB_URL env var)")
	generateKEK := flag.Bool("generate-kek", false,
		"print a new base64 key encryption key for CERTPILOT_KEK and exit")
	generateDevCerts := flag.String("generate-dev-certs", "",
		"write development mTLS material for the core-to-gateway channel into this directory and exit")
	flag.Parse()

	// Setup subcommands run before anything else is initialized, so they work
	// on a machine with no config and no database.
	if *generateKEK {
		key, err := secrets.GenerateKEK()
		if err != nil {
			slog.Error("failed to generate key", "error", err)
			os.Exit(1)
		}
		fmt.Printf("CERTPILOT_KEK=%s\n", key)
		fmt.Fprintln(os.Stderr,
			"\nStore this in your secret manager. Certificate private keys and CA credentials\n"+
				"are encrypted with it; losing it makes every stored secret unrecoverable.")
		return
	}

	if *generateDevCerts != "" {
		paths, err := grpckit.GenerateDevPKI(*generateDevCerts, []string{"localhost", "127.0.0.1", "::1"})
		if err != nil {
			slog.Error("failed to generate development certificates", "error", err)
			os.Exit(1)
		}
		fmt.Printf("Wrote development mTLS material to %s\n\n", *generateDevCerts)
		fmt.Printf("  core:     %s / %s\n", paths.ClientCert, paths.ClientKey)
		fmt.Printf("  gateway:  %s / %s\n", paths.ServerCert, paths.ServerKey)
		fmt.Printf("  CA:       %s\n\n", paths.CACert)
		fmt.Fprintln(os.Stderr, "Development use only — the CA key is stored beside the certificates it signs.")
		return
	}

	// Setup logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	slog.Info("initializing CertPilot Core", "config_file", *configPath)

	// Load configuration.
	cfg, err := config.LoadCoreConfig(*configPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			// A config file that exists but is malformed or unsafe must not be
			// silently replaced by permissive defaults.
			slog.Error("configuration is invalid", "path", *configPath, "error", err)
			os.Exit(1)
		}

		slog.Warn("no configuration file found; starting with local development defaults",
			"path", *configPath)
		cfg = &config.CoreConfig{
			Server: config.ServerConfig{
				Host:           "127.0.0.1",
				Port:           8080,
				Mode:           "development",
				AllowedOrigins: []string{"http://localhost:5173"},
			},
			Auth:    config.AuthConfig{AllowAnonymous: true, RoleClaim: "certpilot_role"},
			Renewal: config.RenewalConfig{ScanInterval: 60, DefaultLeadDays: 30},
			Plugins: config.PluginsConfig{
				TLS: config.GatewayTLSConfig{Insecure: true},
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
		slog.Info("no database connection string provided; using in-memory store with sample seed data")
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
