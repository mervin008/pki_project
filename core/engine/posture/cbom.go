package posture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// CycloneDX 1.6 — a Cryptography Bill of Materials.
//
// The shape here is taken from the published JSON schema rather than from
// memory, because a standards export that is approximately right is wrong: the
// point of emitting CycloneDX rather than a CertPilot-shaped JSON file is that
// something else reads it.
//
// What a CBOM is *for* is worth stating, because it is not an inventory in a
// different format. It answers the question an inventory cannot: when an
// algorithm has to change, what has to change with it. A list of certificates
// tells you what you have. A CBOM tells you that the change to ML-DSA touches
// these four hundred things, of which these twelve are load balancers you do
// not control.
const (
	cbomFormat      = "CycloneDX"
	cbomSpecVersion = "1.6"
	cbomVersion     = 1
	// ToolVersion is what the CBOM reports as having produced it.
	//
	// A BOM's provenance is part of the document: somebody reading last
	// quarter's export needs to know which build made it, because the
	// assessment rules change. Kept beside the emitter rather than derived from
	// a build flag, so a binary built without ldflags does not claim to be
	// version "dev" in a compliance artefact.
	ToolVersion = "0.1.0"
)

// BOM is a CycloneDX 1.6 document.
type BOM struct {
	BomFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber,omitempty"`
	Version      int          `json:"version"`
	Metadata     *Metadata    `json:"metadata,omitempty"`
	Components   []Component  `json:"components,omitempty"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

// Metadata says who produced this and when.
type Metadata struct {
	Timestamp string `json:"timestamp"`
	Tools     []Tool `json:"tools,omitempty"`
}

// Tool is what produced the document.
type Tool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Component is one cryptographic asset.
type Component struct {
	Type             string            `json:"type"`
	BomRef           string            `json:"bom-ref,omitempty"`
	Name             string            `json:"name"`
	Description      string            `json:"description,omitempty"`
	CryptoProperties *CryptoProperties `json:"cryptoProperties,omitempty"`
	Evidence         *Evidence         `json:"evidence,omitempty"`
	Properties       []Property        `json:"properties,omitempty"`
}

// Property is a name/value pair, used for the things CycloneDX has no field
// for. CertPilot's own verdict is one of those and belongs here rather than
// invented into a standard field.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Evidence carries where an observation came from.
type Evidence struct {
	Occurrences []Occurrence `json:"occurrences,omitempty"`
}

// Occurrence is one place a cryptographic asset was seen.
type Occurrence struct {
	BomRef   string `json:"bom-ref,omitempty"`
	Location string `json:"location"`
}

// CryptoProperties is the CycloneDX 1.6 crypto extension.
type CryptoProperties struct {
	AssetType             string                 `json:"assetType"`
	AlgorithmProperties   *AlgorithmProperties   `json:"algorithmProperties,omitempty"`
	CertificateProperties *CertificateProperties `json:"certificateProperties,omitempty"`
	ProtocolProperties    *ProtocolProperties    `json:"protocolProperties,omitempty"`
	OID                   string                 `json:"oid,omitempty"`
}

// AlgorithmProperties describes one algorithm.
type AlgorithmProperties struct {
	Primitive              string   `json:"primitive,omitempty"`
	ParameterSetIdentifier string   `json:"parameterSetIdentifier,omitempty"`
	Curve                  string   `json:"curve,omitempty"`
	CryptoFunctions        []string `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel *int     `json:"classicalSecurityLevel,omitempty"`
	// NISTQuantumSecurityLevel is 0 for an algorithm a quantum computer breaks,
	// and 1-5 for the NIST post-quantum categories. Zero is meaningful here
	// rather than absent, which is why it is a pointer.
	NISTQuantumSecurityLevel *int `json:"nistQuantumSecurityLevel,omitempty"`
}

// CertificateProperties describes one certificate.
type CertificateProperties struct {
	SubjectName           string `json:"subjectName,omitempty"`
	IssuerName            string `json:"issuerName,omitempty"`
	NotValidBefore        string `json:"notValidBefore,omitempty"`
	NotValidAfter         string `json:"notValidAfter,omitempty"`
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty"`
	SubjectPublicKeyRef   string `json:"subjectPublicKeyRef,omitempty"`
	CertificateFormat     string `json:"certificateFormat,omitempty"`
	CertificateExtension  string `json:"certificateExtension,omitempty"`
}

// ProtocolProperties describes one observed protocol.
type ProtocolProperties struct {
	Type           string   `json:"type,omitempty"`
	Version        string   `json:"version,omitempty"`
	CipherSuites   []Cipher `json:"cipherSuites,omitempty"`
	CryptoRefArray []string `json:"cryptoRefArray,omitempty"`
}

// Cipher is one negotiated suite.
type Cipher struct {
	Name string `json:"name"`
}

// Dependency links a certificate to the algorithms it is made of.
//
// This is the part that makes the document worth producing. Without it a CBOM
// is a list; with it, "what does moving off SHA-256 touch" is a graph query
// somebody else's tool can answer.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// CertificateInput is one certificate to describe.
type CertificateInput struct {
	ID                 string
	CommonName         string
	SubjectDN          string
	IssuerDN           string
	NotBefore          time.Time
	NotAfter           time.Time
	KeyType            string
	KeySize            int
	Curve              string
	SignatureAlgorithm string
	Verdict            string
	// Locations are where this certificate has actually been observed —
	// endpoints, hosts, cloud stores. The difference between a certificate you
	// have and a certificate you have to go and change.
	Locations []string
}

// EndpointInput is one observed handshake.
type EndpointInput struct {
	Host             string
	Port             int
	TLSVersion       string
	CipherSuite      string
	KeyExchangeGroup string
	Hybrid           bool
	Verdict          string
}

// Build produces a CycloneDX 1.6 CBOM.
//
// Algorithms are emitted once and referenced, not repeated per certificate.
// Four hundred RSA certificates are four hundred references to one RSA
// component, which is what makes the dependency graph answer "what does this
// algorithm change touch".
func Build(toolVersion string, certs []CertificateInput, endpoints []EndpointInput, now time.Time) BOM {
	bom := BOM{
		BomFormat:   cbomFormat,
		SpecVersion: cbomSpecVersion,
		Version:     cbomVersion,
		Metadata: &Metadata{
			Timestamp: now.UTC().Format(time.RFC3339),
			Tools:     []Tool{{Vendor: "CertPilot", Name: "certpilot", Version: toolVersion}},
		},
	}

	algorithms := map[string]Component{}
	addAlgorithm := func(c Component) string {
		if c.BomRef == "" {
			return ""
		}
		if _, seen := algorithms[c.BomRef]; !seen {
			algorithms[c.BomRef] = c
		}
		return c.BomRef
	}

	for _, cert := range certs {
		keyRef := addAlgorithm(keyAlgorithmComponent(cert))
		sigRef := addAlgorithm(signatureAlgorithmComponent(cert))

		ref := "certificate:" + cert.ID
		component := Component{
			Type:   "cryptographic-asset",
			BomRef: ref,
			Name:   fallback(cert.CommonName, cert.SubjectDN),
			CryptoProperties: &CryptoProperties{
				AssetType: "certificate",
				CertificateProperties: &CertificateProperties{
					SubjectName:           fallback(cert.SubjectDN, cert.CommonName),
					IssuerName:            cert.IssuerDN,
					NotValidBefore:        rfc3339(cert.NotBefore),
					NotValidAfter:         rfc3339(cert.NotAfter),
					SignatureAlgorithmRef: sigRef,
					SubjectPublicKeyRef:   keyRef,
					CertificateFormat:     "X.509",
				},
			},
		}
		// CertPilot's own verdict is a property rather than a standard field,
		// because CycloneDX has no place for it and inventing one would produce
		// a document that validates and means something different to every
		// reader.
		if cert.Verdict != "" {
			component.Properties = []Property{
				{Name: "certpilot:posture", Value: cert.Verdict},
			}
		}
		if len(cert.Locations) > 0 {
			occurrences := make([]Occurrence, 0, len(cert.Locations))
			for _, location := range cert.Locations {
				occurrences = append(occurrences, Occurrence{Location: location})
			}
			component.Evidence = &Evidence{Occurrences: occurrences}
		}

		bom.Components = append(bom.Components, component)

		dependsOn := []string{}
		for _, r := range []string{keyRef, sigRef} {
			if r != "" {
				dependsOn = append(dependsOn, r)
			}
		}
		if len(dependsOn) > 0 {
			bom.Dependencies = append(bom.Dependencies, Dependency{Ref: ref, DependsOn: dependsOn})
		}
	}

	for _, endpoint := range endpoints {
		where := fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)
		ref := "protocol:" + where

		kexRef := ""
		if endpoint.KeyExchangeGroup != "" {
			kexRef = addAlgorithm(keyExchangeComponent(endpoint))
		}

		protocol := Component{
			Type:   "cryptographic-asset",
			BomRef: ref,
			Name:   where,
			CryptoProperties: &CryptoProperties{
				AssetType: "protocol",
				ProtocolProperties: &ProtocolProperties{
					Type:    "tls",
					Version: strings.TrimPrefix(endpoint.TLSVersion, "TLS "),
				},
			},
		}
		if endpoint.CipherSuite != "" {
			protocol.CryptoProperties.ProtocolProperties.CipherSuites =
				[]Cipher{{Name: endpoint.CipherSuite}}
		}
		if kexRef != "" {
			protocol.CryptoProperties.ProtocolProperties.CryptoRefArray = []string{kexRef}
		}
		if endpoint.Verdict != "" {
			protocol.Properties = []Property{{Name: "certpilot:posture", Value: endpoint.Verdict}}
		}

		bom.Components = append(bom.Components, protocol)
		if kexRef != "" {
			bom.Dependencies = append(bom.Dependencies, Dependency{Ref: ref, DependsOn: []string{kexRef}})
		}
	}

	bom.Components = append(bom.Components, sortedComponents(algorithms)...)
	bom.SerialNumber = serialFor(bom)
	return bom
}

// keyAlgorithmComponent describes the public key algorithm.
func keyAlgorithmComponent(cert CertificateInput) Component {
	name := cert.KeyType
	if name == "" {
		return Component{}
	}
	parameter := cert.Curve
	if parameter == "" && cert.KeySize > 0 {
		parameter = fmt.Sprintf("%d", cert.KeySize)
	}

	props := &AlgorithmProperties{
		Primitive:              primitiveFor(name),
		ParameterSetIdentifier: parameter,
		Curve:                  cert.Curve,
		CryptoFunctions:        []string{"keygen", "sign", "verify"},
	}
	// The parameter goes in, not just the family name. "ECDSA" on its own says
	// nothing about strength — P-256 and P-521 are the same word — and a first
	// version that looked up "ECDSA" reported no classical security level for
	// exactly the algorithms most certificates use.
	setSecurityLevels(props, displayName(name, parameter), cert.KeySize)

	ref := "algorithm:" + strings.ToLower(name)
	if parameter != "" {
		ref += "-" + strings.ToLower(parameter)
	}
	return Component{
		Type: "cryptographic-asset", BomRef: ref,
		Name:             displayName(name, parameter),
		CryptoProperties: &CryptoProperties{AssetType: "algorithm", AlgorithmProperties: props},
	}
}

// signatureAlgorithmComponent describes how the certificate was signed, which
// is a separate asset from its key and is very often the weaker of the two.
func signatureAlgorithmComponent(cert CertificateInput) Component {
	name := cert.SignatureAlgorithm
	if name == "" {
		return Component{}
	}
	props := &AlgorithmProperties{
		Primitive:       "signature",
		CryptoFunctions: []string{"sign", "verify"},
	}
	setSecurityLevels(props, name, 0)

	return Component{
		Type: "cryptographic-asset", BomRef: "algorithm:" + slug(name),
		Name:             name,
		CryptoProperties: &CryptoProperties{AssetType: "algorithm", AlgorithmProperties: props},
	}
}

// keyExchangeComponent describes a negotiated group.
func keyExchangeComponent(endpoint EndpointInput) Component {
	primitive := "key-agree"
	if endpoint.Hybrid {
		// A hybrid group is a combiner over a key agreement and a key
		// encapsulation, and CycloneDX has a word for exactly that.
		primitive = "combiner"
	}
	props := &AlgorithmProperties{
		Primitive:       primitive,
		CryptoFunctions: []string{"keyderive"},
	}
	setSecurityLevels(props, endpoint.KeyExchangeGroup, 0)
	if endpoint.Hybrid {
		// X25519MLKEM768 carries ML-KEM-768, which is NIST category 3. Named
		// here rather than left to the generic lookup, because the group's name
		// spells the parameter set differently from the algorithm's.
		level := 3
		props.NISTQuantumSecurityLevel = &level
	}

	return Component{
		Type: "cryptographic-asset", BomRef: "algorithm:" + slug(endpoint.KeyExchangeGroup),
		Name:             endpoint.KeyExchangeGroup,
		CryptoProperties: &CryptoProperties{AssetType: "algorithm", AlgorithmProperties: props},
	}
}

// setSecurityLevels fills in the two numbers a CBOM reader compares.
//
// nistQuantumSecurityLevel is zero for everything classical, and that zero is
// the entire point of the document: it is what makes "which of these does a
// quantum computer break" a filter rather than an essay.
func setSecurityLevels(props *AlgorithmProperties, name string, keySize int) {
	upper := strings.ToUpper(name)

	level := 0
	switch {
	case strings.Contains(upper, "ML-DSA-87"), strings.Contains(upper, "ML-KEM-1024"):
		level = 5
	case strings.Contains(upper, "ML-DSA-65"), strings.Contains(upper, "ML-KEM-768"):
		level = 3
	case strings.Contains(upper, "ML-DSA-44"), strings.Contains(upper, "ML-KEM-512"):
		level = 2
	case isPostQuantumSignature(upper):
		level = 1
	}
	props.NISTQuantumSecurityLevel = &level

	if classical := classicalLevelFor(upper, keySize); classical > 0 {
		props.ClassicalSecurityLevel = &classical
	}
}

// classicalLevelFor is the security level against an ordinary computer, in
// bits. Reported alongside the quantum level because they answer different
// questions and an RSA-2048 certificate is fine today.
func classicalLevelFor(name string, keySize int) int {
	// RSA first, and by modulus size rather than by name: the strength is
	// entirely in the number, and the NIST equivalences are not linear.
	if strings.Contains(name, "RSA") {
		switch {
		case keySize >= 15360:
			return 256
		case keySize >= 7680:
			return 192
		case keySize >= 3072:
			return 128
		case keySize >= 2048:
			return 112
		case keySize > 0:
			return 80
		}
		return 0
	}

	// Elliptic curves give half the field size, whether the curve arrives as a
	// name or as a bit count.
	switch {
	case strings.Contains(name, "521"), keySize == 521:
		return 256
	case strings.Contains(name, "384"), keySize == 384:
		return 192
	case strings.Contains(name, "25519"), strings.Contains(name, "256"), keySize == 256:
		return 128
	}
	return 0
}

func primitiveFor(keyType string) string {
	switch strings.ToUpper(keyType) {
	case "RSA", "ECDSA", "ED25519", "DSA":
		return "signature"
	}
	if isPostQuantumSignature(keyType) {
		return "signature"
	}
	return "unknown"
}

func displayName(name, parameter string) string {
	if parameter == "" {
		return name
	}
	return name + "-" + parameter
}

func slug(name string) string {
	return strings.ToLower(strings.NewReplacer(" ", "-", "/", "-", "_", "-").Replace(name))
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// sortedComponents gives the algorithm section a stable order, so two exports
// of an unchanged estate are byte-identical and a diff means something.
func sortedComponents(in map[string]Component) []Component {
	refs := make([]string, 0, len(in))
	for ref := range in {
		refs = append(refs, ref)
	}
	sortStrings(refs)

	out := make([]Component, 0, len(refs))
	for _, ref := range refs {
		out = append(out, in[ref])
	}
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// serialFor is a deterministic urn:uuid derived from the document's contents.
//
// Deterministic on purpose. A random serial on every export makes two exports
// of an unchanged estate differ, which defeats the main use of keeping them:
// diffing last quarter's against this one.
func serialFor(bom BOM) string {
	h := sha256.New()
	for _, c := range bom.Components {
		fmt.Fprintf(h, "%s|%s|", c.BomRef, c.Name)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s",
		sum[0:8], sum[8:12], sum[12:16], sum[16:20], sum[20:32])
}
