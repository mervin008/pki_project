package posture

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func sampleBOM() BOM {
	return Build(ToolVersion,
		[]CertificateInput{
			{
				ID: "11111111-1111-1111-1111-111111111111", CommonName: "shop.example.com",
				SubjectDN: "CN=shop.example.com", IssuerDN: "CN=Example Issuing CA",
				NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:  time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
				KeyType:   "ECDSA", KeySize: 256, Curve: "P-256",
				SignatureAlgorithm: "ECDSA-SHA256", Verdict: VerdictClassical,
				Locations: []string{"lb.example.com:443"},
			},
			{
				ID: "22222222-2222-2222-2222-222222222222", CommonName: "legacy.example.com",
				KeyType: "RSA", KeySize: 1024, SignatureAlgorithm: "SHA1-RSA",
				Verdict: VerdictWeak,
			},
		},
		[]EndpointInput{
			{Host: "lb.example.com", Port: 443, TLSVersion: "TLS 1.3",
				CipherSuite: "TLS_AES_128_GCM_SHA256", KeyExchangeGroup: "X25519MLKEM768",
				Hybrid: true, Verdict: VerdictHybrid},
			{Host: "old.example.com", Port: 443, TLSVersion: "TLS 1.2",
				CipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", KeyExchangeGroup: "CurveP256",
				Verdict: VerdictExposed},
		},
		time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
}

// TestTheCBOMValidatesAgainstTheRealSchema.
//
// The point of emitting CycloneDX rather than a CertPilot-shaped JSON file is
// that something else reads it, so "it looks right" is not a standard this can
// be held to. Skipped rather than failed when the schema or a validator is not
// available, because a test that needs the network is not a test that should
// break somebody's build on a train.
func TestTheCBOMValidatesAgainstTheRealSchema(t *testing.T) {
	schema := os.Getenv("CDX_SCHEMA")
	if schema == "" {
		schema = "/tmp/cdx16.json"
	}
	if _, err := os.Stat(schema); err != nil {
		t.Skip("no CycloneDX schema available; set CDX_SCHEMA to the 1.6 JSON schema")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available to run the validator")
	}

	body, err := json.MarshalIndent(sampleBOM(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	doc := t.TempDir() + "/cbom.json"
	if err := os.WriteFile(doc, body, 0o600); err != nil {
		t.Fatal(err)
	}

	script := `
import json, sys
try:
    import jsonschema
except ImportError:
    print("SKIP no jsonschema"); sys.exit(0)
schema = json.load(open(sys.argv[1]))
doc = json.load(open(sys.argv[2]))
v = jsonschema.Draft7Validator(schema)
errors = sorted(v.iter_errors(doc), key=lambda e: e.path)
if errors:
    for e in errors[:10]:
        print("INVALID %s: %s" % (list(e.path), e.message))
    sys.exit(1)
print("VALID")
`
	out, err := exec.Command("python3", "-c", script, schema, doc).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if strings.HasPrefix(text, "SKIP") {
		t.Skip(text)
	}
	if err != nil || !strings.Contains(text, "VALID") {
		t.Fatalf("the CBOM does not validate against CycloneDX 1.6:\n%s", text)
	}
}

// TestAlgorithmsAreSharedRatherThanRepeated.
//
// The reason this document is worth producing. Four hundred RSA certificates
// must be four hundred references to one RSA component, or "what does moving
// off this algorithm touch" is a search instead of a graph query.
func TestAlgorithmsAreSharedRatherThanRepeated(t *testing.T) {
	bom := sampleBOM()

	refs := map[string]int{}
	for _, c := range bom.Components {
		refs[c.BomRef]++
		if c.Type != "cryptographic-asset" {
			t.Fatalf("every component in a CBOM is a cryptographic asset, got %q", c.Type)
		}
	}
	for ref, n := range refs {
		if n > 1 {
			t.Fatalf("%s appears %d times; algorithms are emitted once and referenced", ref, n)
		}
	}

	// Every certificate depends on the algorithms it is made of.
	byRef := map[string][]string{}
	for _, d := range bom.Dependencies {
		byRef[d.Ref] = d.DependsOn
	}
	deps := byRef["certificate:11111111-1111-1111-1111-111111111111"]
	if len(deps) != 2 {
		t.Fatalf("a certificate depends on its key algorithm and its signature algorithm, got %v", deps)
	}
	for _, ref := range deps {
		if refs[ref] == 0 {
			t.Fatalf("dependency %s does not resolve to a component", ref)
		}
	}
}

// TestTheQuantumLevelIsZeroRatherThanAbsentForClassicalAlgorithms.
//
// Zero is the entire point of the field: it makes "which of these does a
// quantum computer break" a filter rather than an essay. Omitting it for
// classical algorithms would leave a reader unable to tell "breakable" from
// "not assessed".
func TestTheQuantumLevelIsZeroRatherThanAbsentForClassicalAlgorithms(t *testing.T) {
	bom := sampleBOM()

	checked := 0
	for _, c := range bom.Components {
		props := c.CryptoProperties
		if props == nil || props.AssetType != "algorithm" || props.AlgorithmProperties == nil {
			continue
		}
		level := props.AlgorithmProperties.NISTQuantumSecurityLevel
		if level == nil {
			t.Fatalf("%s has no nistQuantumSecurityLevel; a reader cannot tell breakable from unassessed", c.Name)
		}
		checked++

		if strings.Contains(c.Name, "MLKEM") && *level == 0 {
			t.Fatalf("%s carries ML-KEM and should not be level 0", c.Name)
		}
		if c.Name == "ECDSA-P-256" && *level != 0 {
			t.Fatalf("a classical algorithm must be level 0, got %d", *level)
		}
	}
	if checked == 0 {
		t.Fatal("no algorithm components were produced at all")
	}
}

// TestEveryAlgorithmReportsAClassicalStrength.
//
// Caught by a live export: the lookup was given the family name — "ECDSA" — and
// P-256 and P-521 are the same word, so the strongest and weakest elliptic keys
// both reported nothing at all. A CBOM whose classical level is blank for the
// algorithms most certificates actually use is a CBOM with a hole in exactly
// the common case.
func TestEveryAlgorithmReportsAClassicalStrength(t *testing.T) {
	bom := Build(ToolVersion, []CertificateInput{
		{ID: "a", CommonName: "p256", KeyType: "ECDSA", KeySize: 256, Curve: "P-256",
			SignatureAlgorithm: "ECDSA-SHA256"},
		{ID: "b", CommonName: "p521", KeyType: "ECDSA", KeySize: 521, Curve: "P-521",
			SignatureAlgorithm: "ECDSA-SHA512"},
		{ID: "c", CommonName: "rsa", KeyType: "RSA", KeySize: 4096,
			SignatureAlgorithm: "SHA384-RSA"},
	}, nil, time.Now())

	want := map[string]int{"ECDSA-P-256": 128, "ECDSA-P-521": 256, "RSA-4096": 128}
	seen := map[string]int{}
	for _, c := range bom.Components {
		props := c.CryptoProperties
		if props == nil || props.AlgorithmProperties == nil {
			continue
		}
		if level := props.AlgorithmProperties.ClassicalSecurityLevel; level != nil {
			seen[c.Name] = *level
		}
	}
	for name, expected := range want {
		if seen[name] != expected {
			t.Fatalf("%s should report %d bits of classical security, got %d", name, expected, seen[name])
		}
	}
}

// TestTwoExportsOfAnUnchangedEstateAreIdentical.
//
// A random serial number on each export would make every diff show a change,
// which defeats the main use of keeping them: comparing last quarter to this
// one.
func TestTwoExportsOfAnUnchangedEstateAreIdentical(t *testing.T) {
	first, err := json.Marshal(sampleBOM())
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(sampleBOM())
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("two exports of the same estate differ, so a diff cannot mean anything")
	}
	if !strings.Contains(string(first), `"serialNumber":"urn:uuid:`) {
		t.Fatal("the serial number should be a urn:uuid")
	}
}
