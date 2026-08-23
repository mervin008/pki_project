package fleet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"strings"
	"testing"

	"github.com/certpilot/certpilot/core/store"
)

// csrFor builds a request the way the agent does, optionally with extensions it
// has no business asking for.
func csrFor(t *testing.T, commonName string, sans []string, extra []pkix.Extension) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: commonName},
		DNSNames:        sans,
		ExtraExtensions: extra,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// TestARequestMustBeSignedByTheKeyItContains.
//
// Without this, anybody who can reach the endpoint could obtain a certificate
// for a public key belonging to somebody else — which is a certificate issued
// to that somebody else, from an authority this organisation runs.
func TestARequestMustBeSignedByTheKeyItContains(t *testing.T) {
	valid := csrFor(t, "site.example.com", []string{"site.example.com"}, nil)

	block, _ := pem.Decode([]byte(valid))
	tampered := append([]byte{}, block.Bytes...)
	// Flip a bit in the subject, leaving the signature covering the original.
	tampered[len(tampered)/3] ^= 0x01
	broken := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered}))

	if _, err := parseCSR(valid); err != nil {
		t.Fatalf("a well-formed request should parse: %v", err)
	}
	if _, err := parseCSR(broken); err == nil {
		t.Fatal("a request whose signature does not cover its contents must be refused")
	}
	if _, err := parseCSR("not pem"); err == nil {
		t.Fatal("garbage must be refused")
	}
}

// TestARequestToBecomeAnAuthorityIsRefused.
//
// A correct CA ignores CSR extensions and builds its own template — which is
// what the gateways here do. But "the code downstream is careful" is a hope
// about code that may be a third-party gateway next year, not a control. So a
// request asking for CA:TRUE is refused rather than silently stripped.
func TestARequestToBecomeAnAuthorityIsRefused(t *testing.T) {
	basicConstraints, err := asn1.Marshal(struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}{IsCA: true, MaxPathLen: -1})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	csr := csrFor(t, "site.example.com", []string{"site.example.com"}, []pkix.Extension{
		{Id: oidBasicConstraints, Critical: true, Value: basicConstraints},
	})

	_, err = parseCSR(csr)
	if err == nil {
		t.Fatal("a request for a CA certificate must be refused")
	}
	if !strings.Contains(err.Error(), "never an authority") {
		t.Fatalf("the refusal should say why: %v", err)
	}

	// keyCertSign, which is the same ask by another route.
	usage, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x04}, BitLength: 6})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	csr = csrFor(t, "site.example.com", []string{"site.example.com"}, []pkix.Extension{
		{Id: oidKeyUsage, Critical: true, Value: usage},
	})
	if _, err := parseCSR(csr); err == nil {
		t.Fatal("a request for keyCertSign must be refused")
	}
}

// TestTheCommonNameIsAuthorisedToo.
//
// A request whose SANs are all permitted and whose CN is not would otherwise
// produce a certificate for a name nobody granted.
func TestTheCommonNameIsAuthorisedToo(t *testing.T) {
	csr, err := parseCSR(csrFor(t, "payroll.example.com", []string{"site.example.com"}, nil))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	names, err := requestedNames(csr)
	if err != nil {
		t.Fatalf("names: %v", err)
	}

	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	if !found["payroll.example.com"] || !found["site.example.com"] {
		t.Fatalf("both the CN and the SANs have to be authorised, got %v", names)
	}
}

// TestOnlyDNSNamesAreIssuedToAgents. IP, email, and URI names are validated
// differently, and a grant has no way to express them.
func TestOnlyDNSNamesAreIssuedToAgents(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "site.example.com"},
		DNSNames:    []string{"site.example.com"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
	}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := requestedNames(csr); err == nil {
		t.Fatal("an IP name must be refused")
	}
}

// TestAGrantCoversWhatItSays — wildcard semantics matching certificates', so a
// grant means what the person who wrote it thinks it means.
func TestAGrantCoversWhatItSays(t *testing.T) {
	grant := &store.AgentGrant{
		IsEnabled: true,
		Names:     []string{"exact.example.com", "*.web.example.com"},
	}

	cases := map[string]bool{
		"exact.example.com":      true,
		"EXACT.example.com":      true, // case-insensitive
		"exact.example.com.":     true, // trailing dot
		"a.web.example.com":      true,
		"a.b.web.example.com":    false, // wildcards match one level
		"web.example.com":        false, // and not the bare domain
		"other.example.com":      false,
		"exact.example.com.evil": false,
	}
	for name, want := range cases {
		if got := grant.Covers(name); got != want {
			t.Fatalf("%q: expected %v, got %v", name, want, got)
		}
	}
}

// TestAGrantOnlyAppliesToTheHostsItNames.
//
// Labels come from the enrolment token, not from the agent, which is what makes
// them worth trusting: a host cannot label itself into a grant somebody wrote
// for a different tier.
func TestAGrantOnlyAppliesToTheHostsItNames(t *testing.T) {
	id := "agent-1"
	web := &store.Agent{ID: "agent-1", Status: store.AgentActive, Labels: map[string]string{"tier": "web", "env": "prod"}}
	db := &store.Agent{ID: "agent-2", Status: store.AgentActive, Labels: map[string]string{"tier": "db", "env": "prod"}}

	byID := &store.AgentGrant{IsEnabled: true, AgentID: &id}
	if !byID.AppliesTo(web) || byID.AppliesTo(db) {
		t.Fatal("an agent-targeted grant applies to exactly that agent")
	}

	byLabel := &store.AgentGrant{IsEnabled: true, LabelSelector: map[string]string{"tier": "web", "env": "prod"}}
	if !byLabel.AppliesTo(web) || byLabel.AppliesTo(db) {
		t.Fatal("a label selector matches only agents carrying every label")
	}

	// Every key must match, not any.
	partial := &store.AgentGrant{IsEnabled: true, LabelSelector: map[string]string{"tier": "web", "env": "staging"}}
	if partial.AppliesTo(web) {
		t.Fatal("a selector with one wrong label must not match")
	}

	// And a revoked grant is not permission for anything.
	byID.IsEnabled = false
	if byID.AppliesTo(web) {
		t.Fatal("a disabled grant must apply to nothing")
	}
}

// TestAGrantEnforcesAKeyFloorWithinAnAlgorithm.
//
// Key sizes are not comparable across algorithms: P-256 is considerably
// stronger than RSA-2048 and the integer 256 is smaller than 2048. Comparing
// one number against both refuses the stronger key for being the smaller
// number, which is how this was first written.
func TestAGrantEnforcesAKeyFloorWithinAnAlgorithm(t *testing.T) {
	rsaOnly := &store.AgentGrant{
		IsEnabled: true, MinKeySize: 2048, AllowedKeyTypes: []string{"RSA"},
	}
	if ok, _ := rsaOnly.AllowsKey("RSA", 4096); !ok {
		t.Fatal("a 4096-bit RSA key should be allowed")
	}
	if ok, why := rsaOnly.AllowsKey("RSA", 1024); ok {
		t.Fatal("a 1024-bit RSA key must be refused")
	} else if !strings.Contains(why, "2048") {
		t.Fatalf("the refusal should name the floor: %s", why)
	}
	// Type is checked before size, so the reason given is the real one.
	if ok, why := rsaOnly.AllowsKey("ECDSA", 256); ok {
		t.Fatal("a key type this grant does not permit must be refused")
	} else if !strings.Contains(why, "permits RSA") {
		t.Fatalf("the refusal should name what is permitted: %s", why)
	}

	// The case that mattered: an RSA-shaped floor must not refuse a curve.
	both := &store.AgentGrant{
		IsEnabled: true, MinKeySize: 2048, AllowedKeyTypes: []string{"RSA", "ECDSA"},
	}
	if ok, why := both.AllowsKey("ECDSA", 256); !ok {
		t.Fatalf("P-256 is stronger than RSA-2048 and must not be refused for being 256: %s", why)
	}

	// And a grant cannot lower the RSA floor below what is worth signing.
	sloppy := &store.AgentGrant{IsEnabled: true, MinKeySize: 512, AllowedKeyTypes: []string{"RSA"}}
	if ok, _ := sloppy.AllowsKey("RSA", 1024); ok {
		t.Fatal("no grant may permit a 1024-bit RSA key")
	}
}
