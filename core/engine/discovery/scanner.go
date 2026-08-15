// Package discovery provides network TLS scanning and certificate discovery tools.
package discovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/x509util"
)

// ScanResult holds discovered certificate information from a target endpoint.
type ScanResult struct {
	Host        string             `json:"host"`
	Port        int                `json:"port"`
	Certificate *x509util.CertInfo `json:"certificate"`
	Error       string             `json:"error,omitempty"`
}

// Scanner performs TLS handshakes to extract certificates from network endpoints.
type Scanner struct {
	store store.Store
}

// NewScanner creates a new TLS endpoint scanner.
func NewScanner(s store.Store) *Scanner {
	return &Scanner{store: s}
}

// ScanEndpoint connects to host:port, completes a TLS handshake, and extracts the certificate.
func (s *Scanner) ScanEndpoint(ctx context.Context, host string, port int) (*ScanResult, error) {
	if port <= 0 {
		port = 443
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	// Connect with InsecureSkipVerify so we can inspect expired or self-signed certs too
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err != nil {
		return &ScanResult{
			Host:  host,
			Port:  port,
			Error: err.Error(),
		}, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return &ScanResult{
			Host:  host,
			Port:  port,
			Error: "no peer certificates presented in TLS handshake",
		}, nil
	}

	leaf := state.PeerCertificates[0]
	certInfo := x509util.CertInfoFromX509(leaf)

	return &ScanResult{
		Host:        host,
		Port:        port,
		Certificate: certInfo,
	}, nil
}
