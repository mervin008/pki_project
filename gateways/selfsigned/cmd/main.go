// CertPilot Self-Signed Gateway
//
// A gateway plugin that generates self-signed certificates.
// Used for development and testing.
//
// Usage:
//   go run ./gateways/selfsigned/cmd/ --port=9091
package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/certpilot/certpilot/gateways/selfsigned"
	"github.com/certpilot/certpilot/pkg/grpckit"
	providerv1 "github.com/certpilot/certpilot/pkg/pb/provider/v1"
)

func main() {
	port := flag.Int("port", 9091, "gRPC server port")
	flag.Parse()

	// Setup structured logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	slog.Info("starting CertPilot Self-Signed Gateway", "port", *port)

	// Create the gRPC server
	opts := grpckit.DefaultServerOptions()
	opts.Port = *port
	server := grpckit.NewServer(opts)

	// Register the self-signed provider
	provider := selfsigned.NewProvider()
	providerv1.RegisterCertificateProviderServiceServer(server, provider)

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Info("received shutdown signal", "signal", sig)
		server.GracefulStop()
	}()

	// Start serving
	if err := grpckit.Serve(server, *port); err != nil {
		slog.Error("gateway server failed", "error", err)
		os.Exit(1)
	}
}
