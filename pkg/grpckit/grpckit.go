// Package grpckit provides gRPC helpers for CertPilot core and gateway plugins.
package grpckit

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

// ServerOptions configures a gRPC server.
type ServerOptions struct {
	Port            int
	MaxRecvMsgSize  int
	EnableReflection bool
}

// DefaultServerOptions returns sensible defaults for a gRPC server.
func DefaultServerOptions() ServerOptions {
	return ServerOptions{
		Port:            9090,
		MaxRecvMsgSize:  10 * 1024 * 1024, // 10MB
		EnableReflection: true,
	}
}

// NewServer creates a new gRPC server with standard configuration.
func NewServer(opts ServerOptions) *grpc.Server {
	serverOpts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(opts.MaxRecvMsgSize),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              2 * time.Minute,
			Timeout:           20 * time.Second,
		}),
	}

	server := grpc.NewServer(serverOpts...)

	// Register health check service
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(server, healthServer)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	// Enable reflection for debugging with grpcurl
	if opts.EnableReflection {
		reflection.Register(server)
	}

	return server
}

// Serve starts the gRPC server on the specified port.
func Serve(server *grpc.Server, port int) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", port, err)
	}

	slog.Info("gRPC server starting", "port", port)
	return server.Serve(lis)
}

// DialOptions returns standard client dial options.
func DialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}
}

// Dial connects to a gRPC server at the given address.
func Dial(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	conn, err := grpc.DialContext(ctx, addr, DialOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", addr, err)
	}
	return conn, nil
}
