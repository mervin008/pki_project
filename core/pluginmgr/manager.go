// Package pluginmgr manages active gateway plugin gRPC connections and registries.
package pluginmgr

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	commonv1 "github.com/certpilot/certpilot/pkg/pb/common/v1"
	providerv1 "github.com/certpilot/certpilot/pkg/pb/provider/v1"
	"github.com/certpilot/certpilot/pkg/grpckit"
	"google.golang.org/grpc"
)

// GatewayClient wraps a gRPC connection to a gateway plugin.
type GatewayClient struct {
	Name         string
	Addr         string
	Type         string
	Conn         *grpc.ClientConn
	Client       providerv1.CertificateProviderServiceClient
	Capabilities *commonv1.ProviderCapabilities
	LastHealth   *providerv1.HealthCheckResponse
	LastChecked  time.Time
	IsConnected  bool
}

// Manager manages connections to all configured gateway plugins.
type Manager struct {
	mu       sync.RWMutex
	gateways map[string]*GatewayClient
}

// NewManager creates a new plugin manager.
func NewManager() *Manager {
	return &Manager{
		gateways: make(map[string]*GatewayClient),
	}
}

// RegisterGateway connects to a gateway plugin and retrieves its capabilities.
func (m *Manager) RegisterGateway(ctx context.Context, name, addr, gwType string) (*GatewayClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already registered
	if existing, ok := m.gateways[name]; ok && existing.IsConnected {
		return existing, nil
	}

	slog.Info("connecting to gateway plugin", "name", name, "addr", addr, "type", gwType)

	conn, err := grpckit.Dial(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial gateway %s at %s: %w", name, addr, err)
	}

	client := providerv1.NewCertificateProviderServiceClient(conn)

	// Fetch capabilities
	capResp, err := client.GetCapabilities(ctx, &providerv1.GetCapabilitiesRequest{})
	if err != nil {
		slog.Warn("failed to fetch gateway capabilities, using defaults", "name", name, "error", err)
	}

	var caps *commonv1.ProviderCapabilities
	if capResp != nil {
		caps = capResp.Capabilities
	}

	gw := &GatewayClient{
		Name:         name,
		Addr:         addr,
		Type:         gwType,
		Conn:         conn,
		Client:       client,
		Capabilities: caps,
		LastChecked:  time.Now(),
		IsConnected:  true,
	}

	m.gateways[name] = gw
	slog.Info("gateway registered successfully", "name", name, "type", gwType)
	return gw, nil
}

// GetGateway returns a registered gateway by name.
func (m *Manager) GetGateway(name string) (*GatewayClient, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	gw, ok := m.gateways[name]
	if !ok || !gw.IsConnected {
		return nil, fmt.Errorf("gateway %s not found or disconnected", name)
	}
	return gw, nil
}

// ListGateways returns a summary of all registered gateways.
func (m *Manager) ListGateways() []*GatewayClient {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]*GatewayClient, 0, len(m.gateways))
	for _, gw := range m.gateways {
		list = append(list, gw)
	}
	return list
}

// HealthCheckAll checks the health of all registered gateways.
func (m *Manager) HealthCheckAll(ctx context.Context) map[string]*providerv1.HealthCheckResponse {
	m.mu.RLock()
	defer m.mu.RUnlock()

	results := make(map[string]*providerv1.HealthCheckResponse)
	for name, gw := range m.gateways {
		if !gw.IsConnected {
			continue
		}
		resp, err := gw.Client.HealthCheck(ctx, &providerv1.HealthCheckRequest{})
		if err != nil {
			slog.Warn("gateway health check failed", "name", name, "error", err)
			gw.IsConnected = false
			continue
		}
		gw.LastHealth = resp
		gw.LastChecked = time.Now()
		results[name] = resp
	}
	return results
}

// Close closes all gateway connections.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, gw := range m.gateways {
		if gw.Conn != nil {
			slog.Info("closing gateway connection", "name", name)
			gw.Conn.Close()
		}
	}
	m.gateways = make(map[string]*GatewayClient)
}
