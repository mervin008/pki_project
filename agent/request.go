package agent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Where a certificate this host holds is kept.
const (
	certsDir      = "certificates"
	certFileName  = "cert.pem"
	keyFileName   = "key.pem"
	chainFileName = "chain.pem"
	metaFileName  = "meta.json"
)

// Held is what this host knows about one certificate it holds.
//
// The private key is on disk beside this file and is not described here beyond
// the fact that it exists. Nothing in this struct is ever sent anywhere.
type Held struct {
	CertificateID string    `json:"certificate_id"`
	Names         []string  `json:"names"`
	NotAfter      time.Time `json:"not_after"`
	// RenewAfter is when the core said this host may ask for a replacement.
	// Decided by the grant rather than by this agent, so a fleet cannot decide
	// to renew itself hourly.
	RenewAfter time.Time `json:"renew_after"`
	IssuedAt   time.Time `json:"issued_at"`
	Directory  string    `json:"-"`
}

// Issued is the core's answer to a request.
type Issued struct {
	CertificateID  string    `json:"certificate_id"`
	CommonName     string    `json:"common_name"`
	SANs           []string  `json:"sans"`
	CertificatePEM string    `json:"certificate_pem"`
	ChainPEM       string    `json:"chain_pem"`
	NotAfter       time.Time `json:"not_after"`
	RenewAfter     time.Time `json:"renew_after"`
}

// RequestOptions is what to ask for.
type RequestOptions struct {
	Names   []string
	KeyType string
	KeySize int
}

// Request obtains a certificate for this host.
//
// The key is generated here and written here. It is not in the request, there
// is no field it could travel in, and the core has no way to obtain it — which
// is the difference between this and every other way a certificate management
// system hands out material.
//
// The order matters: the key and certificate are written together, after the
// core has answered, so a failed request leaves no orphaned key on disk and a
// successful one never leaves a certificate whose key was lost between the two
// writes.
func (r *Runner) Request(ctx context.Context, opts RequestOptions) (*Held, error) {
	names := normalizeNames(opts.Names)
	if len(names) == 0 {
		return nil, fmt.Errorf("at least one name is required")
	}

	key, err := generateKey(opts.KeyType, opts.KeySize)
	if err != nil {
		return nil, err
	}
	csrPEM, err := buildCSR(key, names)
	if err != nil {
		return nil, err
	}

	dir := filepath.Join(r.stateDir, certsDir, slugOf(names[0]))
	// The core wraps every successful response in `data`, as it does across the
	// whole API. Decoding straight into Issued silently produced a zero value
	// and a certificate on disk with no expiry — written, valid, and reported
	// as expiring in year one.
	var envelope struct {
		Data Issued `json:"data"`
	}
	err = r.client.post(ctx, "/api/v1/agent/certificates", map[string]any{
		"csr_pem":      string(csrPEM),
		"install_path": dir,
	}, &envelope)
	if err != nil {
		// The key is discarded rather than kept for a retry. A key that exists
		// without a certificate is a secret nobody is tracking, and generating
		// another one costs microseconds.
		return nil, err
	}

	issued := envelope.Data
	if issued.CertificatePEM == "" {
		return nil, fmt.Errorf("the core accepted the request and returned no certificate")
	}

	held, err := r.save(dir, key, issued)
	if err != nil {
		return nil, err
	}
	slog.Info("obtained a certificate",
		"common_name", issued.CommonName, "expires", issued.NotAfter.Format(time.RFC3339),
		"directory", dir, "private_key", "generated here, never sent")
	return held, nil
}

// save writes the material this host now holds.
func (r *Runner) save(dir string, key crypto.Signer, issued Issued) (*Held, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("could not create %s: %w", dir, err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// The key first and at 0600. If anything fails after this the host has a
	// key it cannot use, which is inert; the other order would leave a
	// certificate whose key never landed, which looks like a working
	// deployment until something restarts.
	if err := os.WriteFile(filepath.Join(dir, keyFileName), keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("could not write the private key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, certFileName), []byte(issued.CertificatePEM), 0o644); err != nil {
		return nil, fmt.Errorf("could not write the certificate: %w", err)
	}
	if issued.ChainPEM != "" {
		if err := os.WriteFile(filepath.Join(dir, chainFileName), []byte(issued.ChainPEM), 0o644); err != nil {
			return nil, fmt.Errorf("could not write the chain: %w", err)
		}
	}

	held := &Held{
		CertificateID: issued.CertificateID,
		Names:         issued.SANs,
		NotAfter:      issued.NotAfter,
		RenewAfter:    issued.RenewAfter,
		IssuedAt:      time.Now(),
		Directory:     dir,
	}
	if len(held.Names) == 0 {
		held.Names = []string{issued.CommonName}
	}
	body, err := json.MarshalIndent(held, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, metaFileName), append(body, '\n'), 0o600); err != nil {
		return nil, fmt.Errorf("could not write the certificate record: %w", err)
	}
	return held, nil
}

// HeldCertificates lists what this host is holding.
func (r *Runner) HeldCertificates() []*Held { return HeldIn(r.stateDir) }

// HeldIn lists what a state directory is holding, without an identity.
//
// Separate from the method so that installing works on a host whose credential
// has been revoked or whose core is unreachable. Putting a certificate this
// machine already holds where its own server reads it needs permission from
// nobody.
func HeldIn(stateDir string) []*Held {
	root := filepath.Join(stateDir, certsDir)
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}

	out := []*Held{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		body, err := os.ReadFile(filepath.Join(dir, metaFileName))
		if err != nil {
			continue
		}
		var held Held
		if err := json.Unmarshal(body, &held); err != nil {
			continue
		}
		held.Directory = dir
		out = append(out, &held)
	}
	return out
}

// RenewDue asks for a replacement for anything close enough to expiry, and
// reports how many it replaced.
//
// The agent renews its own certificates because it is the only thing that can:
// rotating means generating a new key, and the core does not have one and must
// not. The core's renewal sweep skips these for exactly that reason.
//
// When to renew is the core's decision, carried in RenewAfter. A host that
// picked its own moment would be a host that could decide to renew hourly, and
// four hundred of them would be a denial of service against the CA.
func (r *Runner) RenewDue(ctx context.Context) int {
	renewed := 0
	for _, held := range r.HeldCertificates() {
		if time.Now().Before(held.RenewAfter) {
			continue
		}
		slog.Info("renewing a certificate this host holds",
			"names", held.Names, "expires", held.NotAfter.Format(time.RFC3339))

		if _, err := r.Request(ctx, RequestOptions{Names: held.Names}); err != nil {
			// Not fatal, and not retried tightly. The next cycle tries again,
			// and RenewAfter leaves room for a great many cycles before the
			// certificate actually expires.
			slog.Warn("could not renew a certificate this host holds",
				"names", held.Names, "expires", held.NotAfter.Format(time.RFC3339), "error", err)
			continue
		}
		renewed++
	}
	return renewed
}

// generateKey creates the private key that will never leave this host.
func generateKey(keyType string, keySize int) (crypto.Signer, error) {
	switch strings.ToUpper(strings.TrimSpace(keyType)) {
	case "", "ECDSA":
		curve := elliptic.P256()
		switch keySize {
		case 0, 256:
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("ECDSA key size %d is not supported; use 256, 384, or 521", keySize)
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case "RSA":
		if keySize == 0 {
			keySize = 2048
		}
		if keySize < 2048 {
			return nil, fmt.Errorf("an RSA key smaller than 2048 bits is not worth generating")
		}
		return rsa.GenerateKey(rand.Reader, keySize)
	case "ED25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	}
	return nil, fmt.Errorf("key type %q is not supported; use ECDSA, RSA, or Ed25519", keyType)
}

// buildCSR builds the request.
//
// Names only. No basic constraints, no key usage, no requested extensions of
// any kind: a CSR is a request and the CA builds its own template, so anything
// else here would at best be ignored and at worst be honoured by a CA that
// should not have.
func buildCSR(key crypto.Signer, names []string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: names[0]},
		DNSNames: names,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("could not build the certificate request: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func normalizeNames(names []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, name := range names {
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// slugOf turns a hostname into a directory name.
func slugOf(name string) string {
	slug := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		}
		return '_'
	}, name)
	return strings.TrimPrefix(slug, "_.")
}
