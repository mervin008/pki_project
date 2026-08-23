package solver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HTTP01 answers http-01 challenges from a small dedicated listener.
//
// The CA fetches http://<domain>/.well-known/acme-challenge/<token> on port 80.
// Binding port 80 directly works for a host that owns it; more often the
// gateway listens on a high port and an existing reverse proxy forwards the
// well-known path to it. Both are the same server, so the bind address is
// configurable and nothing else changes.
type HTTP01 struct {
	mu       sync.RWMutex
	tokens   map[string]string // token -> key authorization
	server   *http.Server
	listener net.Listener
	started  bool
}

// ChallengePathPrefix is the well-known path RFC 8555 reserves for http-01.
const ChallengePathPrefix = "/.well-known/acme-challenge/"

// NewHTTP01 starts a challenge listener on bindAddr (for example ":80" or
// "127.0.0.1:5002").
func NewHTTP01(bindAddr string) (*HTTP01, error) {
	if bindAddr == "" {
		bindAddr = ":80"
	}

	s := &HTTP01{tokens: make(map[string]string)}

	mux := http.NewServeMux()
	mux.HandleFunc(ChallengePathPrefix, s.handle)
	// A plain 404 elsewhere keeps the listener from looking like an open proxy.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("http-01: failed to bind %s: %w", bindAddr, err)
	}

	s.listener = ln
	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	s.started = true

	go func() {
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("http-01 challenge server stopped", "error", err)
		}
	}()

	slog.Info("http-01 challenge server listening", "addr", ln.Addr().String())
	return s, nil
}

// Addr reports the address the challenge server is listening on, which is
// useful when bindAddr requested port 0.
func (s *HTTP01) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Type implements Solver.
func (s *HTTP01) Type() string { return TypeHTTP01 }

// Present registers the key authorization for a token.
func (s *HTTP01) Present(_ context.Context, ch Challenge) error {
	if ch.Token == "" {
		return fmt.Errorf("http-01: empty challenge token")
	}
	s.mu.Lock()
	s.tokens[ch.Token] = ch.Value
	s.mu.Unlock()

	slog.Debug("http-01 challenge presented", "domain", ch.Domain, "path", ChallengePathPrefix+ch.Token)
	return nil
}

// CleanUp removes the token. It is safe to call for a token never presented.
func (s *HTTP01) CleanUp(_ context.Context, ch Challenge) error {
	s.mu.Lock()
	delete(s.tokens, ch.Token)
	s.mu.Unlock()
	return nil
}

// Close shuts the listener down.
func (s *HTTP01) Close() error {
	if !s.started {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *HTTP01) handle(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, ChallengePathPrefix)
	if token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}

	s.mu.RLock()
	keyAuth, ok := s.tokens[token]
	s.mu.RUnlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(keyAuth))
}
