// CertPilot ACME Gateway
//
// A gateway plugin that implements RFC 8555 ACME for automated certificate
// management with Let's Encrypt, ZeroSSL, BuyPass, Google Trust Services, or Smallstep.
//
// Usage:
//   go run ./gateways/acme/cmd/ --port=9092 --directory="https://acme-staging-v02.api.letsencrypt.org/directory"
package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/certpilot/certpilot/gateways/acme"
	"github.com/certpilot/certpilot/pkg/grpckit"
	providerv1 "github.com/certpilot/certpilot/pkg/pb/provider/v1"
)

func main() {
	port := flag.Int("port", 9092, "gRPC server port")
	directoryURL := flag.String("directory", "https://acme-staging-v02.api.letsencrypt.org/directory", "Default ACME directory URL")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	slog.Info("starting CertPilot ACME Gateway", "port", *port, "default_directory", *directoryURL)

	opts := grpckit.DefaultServerOptions()
	opts.Port = *port
	server := grpckit.NewServer(opts)

	provider := acme.NewProvider(*directoryURL)
	providerv1.RegisterCertificateProviderServiceServer(server, provider)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Info("received shutdown signal", "signal", sig)
		server.GracefulStop()
	}()

	if err := grpckit.Serve(server, *port); err != nil {
		slog.Error("ACME gateway server failed", "error", err)
		os.Exit(1)
	}
}
