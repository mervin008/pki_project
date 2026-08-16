package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/acme"
)

// accountStore resolves the ACME account key for a CA account.
//
// Account keys must be stable. Generating one per request — as the previous
// implementation did — registers a fresh account on every issuance and hits the
// CA's account-creation rate limit almost immediately. The key comes from the
// CA account configuration when the operator supplies one; otherwise the
// gateway keeps a key on disk, scoped to the directory URL and contact address,
// and reuses it for the life of the deployment.
type accountStore struct {
	dir string

	mu    sync.Mutex
	cache map[string]crypto.Signer
}

func newAccountStore(dir string) *accountStore {
	return &accountStore{dir: dir, cache: make(map[string]crypto.Signer)}
}

// keyFor returns the account key for a configuration, creating and persisting
// one if this is the first time the gateway has seen this directory and contact.
func (s *accountStore) keyFor(cfg *Config) (crypto.Signer, error) {
	// An explicitly configured key always wins; the core is the source of
	// truth when it has one.
	if strings.TrimSpace(cfg.AccountKeyPEM) != "" {
		key, err := parsePrivateKeyPEM([]byte(cfg.AccountKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("account_key_pem is not a usable private key: %w", err)
		}
		return key, nil
	}

	id := accountID(cfg)

	s.mu.Lock()
	defer s.mu.Unlock()

	if key, ok := s.cache[id]; ok {
		return key, nil
	}

	if s.dir == "" {
		// No state directory: fall back to a process-lifetime key and say so,
		// because the operator will otherwise be surprised by a new ACME
		// account after every restart.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		slog.Warn("no ACME account key configured and no state directory set; using an ephemeral account key. "+
			"Set --state-dir or account_key_pem to keep a stable ACME account across restarts",
			"directory", cfg.DirectoryURL)
		s.cache[id] = key
		return key, nil
	}

	path := filepath.Join(s.dir, "account-"+id+".pem")

	if data, err := os.ReadFile(path); err == nil {
		key, err := parsePrivateKeyPEM(data)
		if err != nil {
			return nil, fmt.Errorf("stored account key %s is corrupt: %w", path, err)
		}
		s.cache[id] = key
		slog.Debug("loaded ACME account key from state directory", "path", path)
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to read account key %s: %w", path, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate account key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create state directory %s: %w", s.dir, err)
	}
	// 0600: the account key authenticates every request to the CA.
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return nil, fmt.Errorf("failed to persist account key %s: %w", path, err)
	}

	s.cache[id] = key
	slog.Info("generated and stored a new ACME account key", "path", path, "directory", cfg.DirectoryURL)
	return key, nil
}

// accountID derives a stable filesystem-safe identifier from the directory URL
// and contact address, so distinct CA accounts never share a key.
func accountID(cfg *Config) string {
	sum := sha256.Sum256([]byte(cfg.DirectoryURL + "\x00" + cfg.Email))
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

// newClient builds an ACME client and ensures the account is registered.
func (p *Provider) newClient(ctx context.Context, cfg *Config) (*acme.Client, error) {
	key, err := p.accounts.keyFor(cfg)
	if err != nil {
		return nil, err
	}

	client := &acme.Client{
		Key:          key,
		DirectoryURL: cfg.DirectoryURL,
		HTTPClient:   p.httpClient,
		UserAgent:    "certpilot-gateway-acme/" + Version,
	}

	if err := registerAccount(ctx, client, cfg); err != nil {
		return nil, err
	}

	return client, nil
}

// registerAccount registers the account, treating an existing registration as
// success. RFC 8555 servers respond to a repeat registration with the existing
// account, but the error surface varies enough between CAs that the string
// checks below are still worth keeping.
func registerAccount(ctx context.Context, client *acme.Client, cfg *Config) error {
	account := &acme.Account{}
	if cfg.Email != "" {
		account.Contact = []string{"mailto:" + strings.TrimPrefix(cfg.Email, "mailto:")}
	}

	if cfg.EABKeyID != "" {
		hmacKey, err := decodeEABKey(cfg.EABHMACKey)
		if err != nil {
			return fmt.Errorf("eab_hmac_key is not valid base64: %w", err)
		}
		account.ExternalAccountBinding = &acme.ExternalAccountBinding{
			KID: cfg.EABKeyID,
			Key: hmacKey,
		}
	}

	_, err := client.Register(ctx, account, acme.AcceptTOS)
	if err == nil {
		return nil
	}
	if errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil
	}
	// Some CAs report a pre-existing account as a generic problem document.
	msg := strings.ToLower(err.Error())
	for _, benign := range []string{"already registered", "account exists", "accountdoesnotexist not"} {
		if strings.Contains(msg, benign) {
			return nil
		}
	}

	return fmt.Errorf("ACME account registration failed: %w", err)
}

// decodeEABKey accepts the base64url form CAs hand out, with or without padding.
func decodeEABKey(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if key, err := base64.RawURLEncoding.DecodeString(encoded); err == nil {
		return key, nil
	}
	if key, err := base64.URLEncoding.DecodeString(encoded); err == nil {
		return key, nil
	}
	return base64.StdEncoding.DecodeString(encoded)
}

// parsePrivateKeyPEM accepts PKCS#8, SEC 1, and PKCS#1 private keys.
func parsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("key of type %T cannot sign", key)
		}
		return signer, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("unsupported private key encoding in %q block", block.Type)
}
