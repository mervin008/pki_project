package vault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testCA is a small certificate authority for the fake Vault to sign with.
type testCA struct {
	cert    *x509.Certificate
	certPEM string
	key     *ecdsa.PrivateKey
}

// newTestCA builds a CA that expires when the test says it does, which is the
// only way to exercise the refusal this gateway exists to explain.
func newTestCA(t *testing.T, commonName string, expiresIn time.Duration, parent *testCA) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a CA key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generating a serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(expiresIn),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("creating the CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the CA certificate: %v", err)
	}

	return &testCA{
		cert:    cert,
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		key:     key,
	}
}

// signLeaf issues a leaf, refusing exactly as Vault does when the certificate
// would outlive its issuer.
func (ca *testCA) signLeaf(t *testing.T, names []string, ttl time.Duration, pub any) (string, string, error) {
	t.Helper()

	notAfter := time.Now().Add(ttl)
	if notAfter.After(ca.cert.NotAfter) {
		return "", "", fmt.Errorf(
			"cannot satisfy request, as TTL would result in notAfter %s that is beyond the expiration of the CA certificate at %s",
			notAfter.UTC().Format(time.RFC3339), ca.cert.NotAfter.UTC().Format(time.RFC3339))
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatalf("generating a serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatalf("signing a leaf: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return certPEM, vaultSerial(serial.Text(16)), nil
}

// fakeVault is enough of Vault's HTTP API to hold this gateway to its promises.
//
// It implements the behaviour rather than the responses: a certificate that
// would outlive the CA is refused with Vault's own message, a revoked serial
// stays revoked, and a token this server did not issue is rejected. A stub
// that returned canned JSON would pass while the gateway did the wrong thing
// to a real Vault.
type fakeVault struct {
	t      *testing.T
	server *httptest.Server
	mount  string

	root      *testCA
	issuing   *testCA
	role      map[string]any
	tokenTTL  int
	renewable bool

	mu       sync.Mutex
	logins   int
	signs    int
	issued   map[string]string
	revoked  map[string]int64
	tokens   map[string]bool
	rejectN  int
	noIssuer bool
}

func newFakeVault(t *testing.T, issuingExpiresIn time.Duration) *fakeVault {
	t.Helper()

	root := newTestCA(t, "CertPilot Test Root", 10*365*24*time.Hour, nil)
	fake := &fakeVault{
		t:         t,
		mount:     "pki",
		root:      root,
		issuing:   newTestCA(t, "CertPilot Test Issuing", issuingExpiresIn, root),
		tokenTTL:  3600,
		renewable: true,
		issued:    map[string]string{},
		revoked:   map[string]int64{},
		tokens:    map[string]bool{},
		role: map[string]any{
			"ttl":                 2592000,
			"max_ttl":             7776000,
			"key_type":            "ec",
			"key_bits":            256,
			"use_csr_common_name": true,
			"use_csr_sans":        true,
			"allowed_domains":     []string{"example.com"},
			"allow_subdomains":    true,
			"no_store":            false,
		},
	}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.route))
	t.Cleanup(fake.server.Close)
	return fake
}

// config returns a provider configuration pointing at this fake.
func (f *fakeVault) config() string { return f.configFor("web") }

func (f *fakeVault) configFor(role string) string {
	return fmt.Sprintf(
		`{"address":%q,"mount":%q,"role":%q,"auth_method":"approle","role_id":"rid","secret_id":"sid","issuer_ref":"issuing"}`,
		f.server.URL, f.mount, role)
}

func (f *fakeVault) counts() (logins, signs int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logins, f.signs
}

func (f *fakeVault) route(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/v1/sys/health" {
		// Top level, not wrapped in `data`. Vault reports on itself here
		// rather than returning the contents of a path, and wrapping it in
		// the fake is what let a decode bug reach a real Vault.
		f.writeRaw(w, map[string]any{
			"initialized": true, "sealed": false, "standby": false, "version": "2.0.3",
		})
		return
	}
	if path == "/v1/auth/approle/login" {
		f.mu.Lock()
		f.logins++
		token := fmt.Sprintf("s.token-%d", f.logins)
		f.tokens[token] = true
		f.mu.Unlock()
		f.writeRaw(w, map[string]any{"auth": map[string]any{
			"client_token": token, "lease_duration": f.tokenTTL, "renewable": f.renewable,
		}})
		return
	}

	// Everything below needs a token this server issued.
	token := r.Header.Get("X-Vault-Token")
	f.mu.Lock()
	known := f.tokens[token]
	reject := f.rejectN > 0
	if reject {
		f.rejectN--
	}
	f.mu.Unlock()
	if !known || reject {
		f.fail(w, http.StatusForbidden, "permission denied")
		return
	}

	switch {
	case path == "/v1/auth/token/lookup-self":
		f.write(w, map[string]any{"ttl": f.tokenTTL, "renewable": f.renewable, "period": 0})
	case path == "/v1/auth/token/renew-self":
		f.writeRaw(w, map[string]any{"auth": map[string]any{
			"client_token": token, "lease_duration": f.tokenTTL, "renewable": f.renewable,
		}})
	case path == "/v1/"+f.mount+"/roles/web":
		f.write(w, f.role)
	case strings.HasPrefix(path, "/v1/"+f.mount+"/roles/"):
		f.fail(w, http.StatusNotFound, "")
	case path == "/v1/"+f.mount+"/issuers":
		if f.noIssuer {
			f.fail(w, http.StatusForbidden, "permission denied")
			return
		}
		f.write(w, map[string]any{"keys": []string{"root", "issuing"}})
	case strings.HasSuffix(path, "/json") && strings.HasPrefix(path, "/v1/"+f.mount+"/issuer/"):
		f.readIssuer(w, strings.TrimSuffix(strings.TrimPrefix(path, "/v1/"+f.mount+"/issuer/"), "/json"))
	case path == "/v1/"+f.mount+"/cert/ca":
		f.write(w, map[string]any{"certificate": f.issuing.certPEM, "ca_chain": []string{f.root.certPEM}})
	case strings.HasPrefix(path, "/v1/"+f.mount+"/cert/"):
		f.readCert(w, strings.TrimPrefix(path, "/v1/"+f.mount+"/cert/"))
	case path == "/v1/"+f.mount+"/revoke":
		f.revoke(w, r)
	case strings.Contains(path, "/sign/"):
		f.sign(w, r, false)
	case strings.Contains(path, "/issue/"):
		f.sign(w, r, true)
	default:
		f.fail(w, http.StatusNotFound, "unsupported path")
	}
}

func (f *fakeVault) readIssuer(w http.ResponseWriter, ref string) {
	ca := f.issuing
	if ref == "root" {
		ca = f.root
	}
	f.write(w, map[string]any{
		"certificate": ca.certPEM,
		"ca_chain":    []string{ca.certPEM, f.root.certPEM},
		"issuer_name": ref,
		"issuer_id":   ref,
	})
}

func (f *fakeVault) readCert(w http.ResponseWriter, serial string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	certPEM, ok := f.issued[serial]
	if !ok {
		f.fail(w, http.StatusNotFound, "")
		return
	}
	f.write(w, map[string]any{"certificate": certPEM, "revocation_time": f.revoked[serial]})
}

func (f *fakeVault) revoke(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SerialNumber string `json:"serial_number"`
		Certificate  string `json:"certificate"`
	}
	f.decode(r, &body)

	serial := body.SerialNumber
	supplied := ""
	if body.Certificate != "" {
		block, _ := pem.Decode([]byte(body.Certificate))
		if block == nil {
			f.fail(w, http.StatusBadRequest, "unable to parse certificate")
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			f.fail(w, http.StatusBadRequest, "unable to parse certificate")
			return
		}
		serial = vaultSerial(cert.SerialNumber.Text(16))
		supplied = body.Certificate
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.issued[serial]; !ok {
		if supplied == "" {
			// Only a serial, and no copy to find it by. This is the one case
			// where Vault genuinely cannot revoke.
			f.fail(w, http.StatusBadRequest, "certificate with serial "+serial+" not found.")
			return
		}
		// Given the certificate, Vault verifies it against the issuer and
		// revokes it whether or not it ever stored it — and stores it then,
		// because the CRL needs it.
		f.issued[serial] = supplied
	}
	if at, ok := f.revoked[serial]; ok && at > 0 {
		f.fail(w, http.StatusBadRequest, "certificate with serial "+serial+" is already revoked")
		return
	}
	f.revoked[serial] = time.Now().Unix()
	f.write(w, map[string]any{"revocation_time": f.revoked[serial]})
}

func (f *fakeVault) sign(w http.ResponseWriter, r *http.Request, generateKey bool) {
	var body struct {
		CSR        string `json:"csr"`
		CommonName string `json:"common_name"`
		AltNames   string `json:"alt_names"`
		TTL        string `json:"ttl"`
	}
	f.decode(r, &body)

	ttl := 30 * 24 * time.Hour
	if body.TTL != "" {
		parsed, err := time.ParseDuration(body.TTL)
		if err != nil {
			f.fail(w, http.StatusBadRequest, "invalid ttl")
			return
		}
		ttl = parsed
	}

	var (
		names  []string
		pub    any
		keyPEM string
	)
	if generateKey {
		names = append([]string{body.CommonName}, splitNames(body.AltNames)...)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			f.t.Fatalf("generating a key: %v", err)
		}
		pub = &key.PublicKey
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			f.t.Fatalf("encoding a key: %v", err)
		}
		keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	} else {
		block, _ := pem.Decode([]byte(body.CSR))
		if block == nil {
			f.fail(w, http.StatusBadRequest, "unable to parse CSR")
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			f.fail(w, http.StatusBadRequest, "unable to parse CSR")
			return
		}
		// use_csr_sans and use_csr_common_name are on by default, so the names
		// in the CSR are the names that get signed — which is the behaviour
		// the gateway refuses to paper over.
		names = append([]string{csr.Subject.CommonName}, csr.DNSNames...)
		pub = csr.PublicKey
	}

	certPEM, serial, err := f.issuing.signLeaf(f.t, dedupe(names), ttl, pub)
	if err != nil {
		f.fail(w, http.StatusBadRequest, err.Error())
		return
	}

	f.mu.Lock()
	f.signs++
	if noStore, _ := f.role["no_store"].(bool); !noStore {
		f.issued[serial] = certPEM
	}
	f.mu.Unlock()

	data := map[string]any{
		"certificate":   certPEM,
		"issuing_ca":    f.issuing.certPEM,
		"ca_chain":      []string{f.issuing.certPEM, f.root.certPEM},
		"serial_number": serial,
		"expiration":    time.Now().Add(ttl).Unix(),
	}
	if keyPEM != "" {
		data["private_key"] = keyPEM
		data["private_key_type"] = "ec"
	}
	f.write(w, data)
}

func (f *fakeVault) decode(r *http.Request, into any) {
	f.t.Helper()
	if err := json.NewDecoder(r.Body).Decode(into); err != nil {
		f.t.Fatalf("the gateway sent a body the fake Vault could not read: %v", err)
	}
}

func (f *fakeVault) write(w http.ResponseWriter, data map[string]any) {
	f.writeRaw(w, map[string]any{"data": data})
}

func (f *fakeVault) writeRaw(w http.ResponseWriter, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		f.t.Errorf("writing a fake Vault reply: %v", err)
	}
}

func (f *fakeVault) fail(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	body := map[string]any{"errors": []string{}}
	if message != "" {
		body["errors"] = []string{message}
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		f.t.Errorf("writing a fake Vault error: %v", err)
	}
}

func splitNames(alt string) []string {
	if strings.TrimSpace(alt) == "" {
		return nil
	}
	return strings.Split(alt, ",")
}

func dedupe(names []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, name := range names {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}
