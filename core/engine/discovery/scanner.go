// Package discovery finds certificates nobody told CertPilot about.
//
// The distinction that shapes this package: a scan of a real estate returns
// mostly certificates the PKI team issued itself and already watches. Those
// rows are noise. The output that justifies running a scan at all is the
// endpoint serving something the inventory has never seen — because nothing
// will renew it, nobody is watching it expire, and no one can say who put it
// there. So every result carries a verdict, and the verdict is what the list is
// sorted, filtered, and alerted on.
package discovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/x509util"
)

const (
	// DefaultPort is assumed when a target names no port.
	DefaultPort = 443
	// defaultDialTimeout bounds one endpoint. Short on purpose: a scan waits
	// for its slowest host, and an unreachable address is the common case in a
	// range that was guessed at rather than inventoried.
	defaultDialTimeout = 6 * time.Second
	// defaultConcurrency caps simultaneous handshakes. High enough that a scan
	// of a rack finishes while someone is still looking at the screen, low
	// enough not to look like a SYN flood to whatever sits in front of it.
	defaultConcurrency = 12
)

// Target is one endpoint to ask.
type Target struct {
	Host string
	Port int
}

// String renders the target the way it was addressed.
func (t Target) String() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// ParseTarget reads "host", "host:port", or "[v6]:port".
//
// Rejects rather than guesses. A target that silently became something else —
// a stray scheme turning `https://example.com` into a hostname with slashes in
// it — produces a scan that reports an unreachable endpoint and looks like a
// finding about the estate rather than a mistake in the input.
func ParseTarget(raw string, defaultPort int) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, fmt.Errorf("empty target")
	}
	if strings.Contains(raw, "://") {
		return Target{}, fmt.Errorf("target %q looks like a URL; give a host or host:port", raw)
	}
	if strings.ContainsAny(raw, "/ \t") {
		return Target{}, fmt.Errorf("target %q contains a path or whitespace; give a host or host:port", raw)
	}
	if defaultPort <= 0 {
		defaultPort = DefaultPort
	}

	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		// No port, or a bare IPv6 address. Both are addressable as-is.
		host, portStr = strings.Trim(raw, "[]"), ""
	}
	if host == "" {
		return Target{}, fmt.Errorf("target %q has no host", raw)
	}

	port := defaultPort
	if portStr != "" {
		port, err = strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return Target{}, fmt.Errorf("target %q has an invalid port", raw)
		}
	}
	return Target{Host: host, Port: port}, nil
}

// Scanner performs TLS handshakes and judges what comes back against the
// certificates and CAs CertPilot already knows about.
type Scanner struct {
	store       store.Store
	dialTimeout time.Duration
	concurrency int
	now         func() time.Time
}

// NewScanner creates a scanner backed by the inventory in the given store.
func NewScanner(s store.Store) *Scanner {
	return &Scanner{
		store:       s,
		dialTimeout: defaultDialTimeout,
		concurrency: defaultConcurrency,
		now:         time.Now,
	}
}

// Probe is the raw observation of one endpoint, before any judgement.
type Probe struct {
	Target    Target
	ScannedAt time.Time
	// Err is set when no TLS handshake completed. The dialler's own words are
	// kept verbatim: "connection refused" and "no route to host" say different
	// things about an estate, and a scan that flattened both to "failed" would
	// hide which.
	Err error
	// Chain is what the server sent, in the order it sent it. Element zero is
	// the leaf.
	Chain       []*x509.Certificate
	Version     uint16
	CipherSuite uint16
	// CurveID is the negotiated key exchange group. Zero for a legacy RSA key
	// exchange, which is itself a finding.
	CurveID tls.CurveID
	ALPN    string
}

// Probe completes a TLS handshake and records everything it can about it.
//
// Verification is deliberately switched off here and done afterwards, in
// analyse. A scanner that refused to look at certificates it did not trust
// would be blind to exactly the endpoints worth finding: the expired ones, the
// self-signed appliance, the host chaining to a CA nobody registered.
func (s *Scanner) Probe(ctx context.Context, target Target) *Probe {
	probe := &Probe{Target: target, ScannedAt: s.now()}

	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // the point is to inspect untrusted certificates
		// SNI is a hostname. Sending an IP literal is not allowed and some
		// servers reject the handshake outright, so an IP target is asked
		// without it and gets whatever the default virtual host serves.
		ServerName: sniFor(target.Host),
		// Reach back to TLS 1.0 and offer the legacy suites. Not because they
		// are acceptable — because an appliance that only speaks them is
		// precisely what a discovery scan is for, and a scanner that could not
		// connect to it would report "unreachable" and leave it undiscovered.
		MinVersion:   tls.VersionTLS10,
		CipherSuites: allCipherSuites(),
		NextProtos:   []string{"h2", "http/1.1"},
	}

	dialer := &net.Dialer{Timeout: s.dialTimeout}
	conn, err := (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, "tcp", target.String())
	if err != nil {
		probe.Err = err
		return probe
	}
	defer func() { _ = conn.Close() }()

	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		probe.Err = fmt.Errorf("the handshake completed but the server presented no certificate")
		return probe
	}

	probe.Chain = state.PeerCertificates
	probe.Version = state.Version
	probe.CipherSuite = state.CipherSuite
	probe.CurveID = state.CurveID
	probe.ALPN = state.NegotiatedProtocol
	return probe
}

// ScanRequest is one run.
type ScanRequest struct {
	Targets []Target
	// TriggeredBy and ActorEmail attribute the run. Scanning is an outbound
	// action against someone else's infrastructure, so it is attributable by
	// construction rather than by whoever remembers to write an audit entry.
	TriggeredBy *string
	ActorEmail  *string
}

// Scan probes every target, judges each result against the inventory, and
// records the run.
//
// The scan record is written before any probing starts. A run that crashes
// halfway then leaves evidence that it was attempted, rather than looking like
// a scan nobody ever ran — which on this dashboard reads as "nothing to find".
func (s *Scanner) Scan(ctx context.Context, req ScanRequest) (*store.DiscoveryScan, []*store.DiscoveryResult, error) {
	if len(req.Targets) == 0 {
		return nil, nil, fmt.Errorf("a scan needs at least one target")
	}

	started := s.now()
	targets := make([]string, 0, len(req.Targets))
	for _, t := range req.Targets {
		targets = append(targets, t.String())
	}

	scan := &store.DiscoveryScan{
		ScanType:    store.ScanTypeNetwork,
		Targets:     targets,
		Status:      store.ScanRunning,
		StartedAt:   &started,
		TriggeredBy: req.TriggeredBy,
		ActorEmail:  req.ActorEmail,
	}
	if err := s.store.CreateDiscoveryScan(ctx, scan); err != nil {
		return nil, nil, fmt.Errorf("recording the scan: %w", err)
	}

	// Trust anchors are loaded once per run, not once per endpoint. A failure
	// here is not fatal: without the managed CAs an internally-issued
	// certificate reads as UNTRUSTED, which overstates the problem, and that is
	// the safer direction to be wrong in.
	anchors, err := s.loadTrustAnchors(ctx)
	if err != nil {
		slog.Warn("could not load CA authorities as trust anchors; internally-issued certificates will read as untrusted",
			"error", err)
	}

	results := s.probeAll(ctx, req.Targets, anchors)

	for _, result := range results {
		result.ScanID = scan.ID
		switch result.ManagementState {
		case store.DiscoveryUnreachable:
			scan.UnreachableCount++
		case store.DiscoveryManaged:
			scan.ManagedCount++
		default:
			scan.UnmanagedCount++
		}
	}

	scan.ResultsCount = len(results)
	completed := s.now()
	scan.CompletedAt = &completed
	scan.Status = store.ScanCompleted

	if err := s.store.CreateDiscoveryResults(ctx, results); err != nil {
		scan.Status = store.ScanFailed
		scan.Error = err.Error()
		_ = s.store.UpdateDiscoveryScan(ctx, scan)
		return scan, nil, fmt.Errorf("storing scan results: %w", err)
	}
	if err := s.store.UpdateDiscoveryScan(ctx, scan); err != nil {
		// The results are already stored, so this is a bookkeeping failure, not
		// a lost scan. Reported, not fatal.
		slog.Warn("scan results stored but the scan record could not be updated", "scan_id", scan.ID, "error", err)
	}

	return scan, results, nil
}

// probeAll runs the probes with bounded concurrency and returns results in the
// order the targets were given, so a scan of a range reads in address order
// rather than in whichever order the network answered.
func (s *Scanner) probeAll(ctx context.Context, targets []Target, anchors *TrustAnchors) []*store.DiscoveryResult {
	results := make([]*store.DiscoveryResult, len(targets))
	sem := make(chan struct{}, s.concurrency)
	var wg sync.WaitGroup

	for i, target := range targets {
		wg.Add(1)
		go func(i int, target Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			probe := s.Probe(ctx, target)
			results[i] = s.judge(ctx, probe, anchors)
		}(i, target)
	}
	wg.Wait()
	return results
}

// judge turns a probe into a result: the verdicts, the findings, and the
// evidence for both.
func (s *Scanner) judge(ctx context.Context, probe *Probe, anchors *TrustAnchors) *store.DiscoveryResult {
	result := &store.DiscoveryResult{
		Host:      probe.Target.Host,
		Port:      probe.Target.Port,
		ScannedAt: probe.ScannedAt,
		SANs:      []string{},
		Findings:  []store.Finding{},
	}

	if probe.Err != nil {
		result.Reachable = false
		result.Error = probe.Err.Error()
		result.ManagementState = store.DiscoveryUnreachable
		result.TrustState = store.TrustUnknown
		return result
	}

	result.Reachable = true
	result.ChainLength = len(probe.Chain)
	result.TLSVersion = tlsVersionName(probe.Version)
	result.CipherSuite = tls.CipherSuiteName(probe.CipherSuite)
	result.KeyExchange = keyExchangeName(probe.CurveID)
	result.ALPN = probe.ALPN

	leaf := probe.Chain[0]
	info := x509util.CertInfoFromX509(leaf)
	result.CommonName = info.CommonName
	result.SubjectDN = info.SubjectDN
	result.IssuerDN = info.IssuerDN
	result.SerialNumber = info.SerialNumber
	result.KeyType = info.KeyType
	result.KeySize = info.KeySize
	result.IsCA = info.IsCA
	result.FingerprintSHA256 = info.FingerprintSHA256
	result.SANs = allNames(leaf)
	notBefore, notAfter := leaf.NotBefore, leaf.NotAfter
	result.NotBefore = &notBefore
	result.NotAfter = &notAfter
	result.CertificatePEM = encodePEM(probe.Chain[:1])
	if len(probe.Chain) > 1 {
		result.ChainPEM = encodePEM(probe.Chain[1:])
	}

	// The verdict that matters. Fingerprint equality, not name matching: two
	// certificates for the same hostname are two different certificates, and
	// the one being served is the one that expires.
	result.ManagementState = store.DiscoveryUnmanaged
	if managed, err := s.store.GetCertificateByFingerprint(ctx, result.FingerprintSHA256); err != nil {
		// Fail towards "unmanaged". Reporting a certificate we cannot check as
		// already handled is how a lookup failure becomes an outage nobody saw
		// coming.
		slog.Warn("could not check a discovered certificate against inventory; reporting it as unmanaged",
			"host", result.Host, "error", err)
		result.Findings = append(result.Findings, store.Finding{
			Code:     "inventory_lookup_failed",
			Severity: "WARNING",
			Detail:   "This certificate could not be checked against the managed inventory, so it is reported as unmanaged. The lookup failed: " + err.Error(),
		})
	} else if managed != nil {
		result.ManagementState = store.DiscoveryManaged
		id := managed.ID
		result.MatchedCertificateID = &id
	}

	trust, findings := analyse(probe, anchors, s.now())
	result.TrustState = trust
	result.Findings = append(result.Findings, findings...)

	return result
}

// TrustAnchors is the set of CAs CertPilot manages, in the form x509
// verification wants.
type TrustAnchors struct {
	// Roots holds every managed CA, root or not.
	//
	// Putting an intermediate in the root pool looks wrong and is deliberate.
	// The question being answered is not "is this chain publicly valid" but
	// "does this endpoint's certificate come from a CA this organisation
	// watches", and an issuing CA registered in CertPilot answers that on its
	// own — whether or not someone also got round to registering the root above
	// it.
	Roots *x509.CertPool
	// Certs holds the same certificates as parsed values, because building an
	// intermediate pool needs them individually and a CertPool cannot be read
	// back out.
	Certs []*x509.Certificate
	// Names maps a subject DN to the CA's name in CertPilot, so a finding can
	// say "issued by Production Issuing CA G2" rather than repeating a DN.
	Names map[string]string
	count int
}

// Empty reports whether there is nothing to verify against.
func (a *TrustAnchors) Empty() bool { return a == nil || a.count == 0 }

func (s *Scanner) loadTrustAnchors(ctx context.Context) (*TrustAnchors, error) {
	anchors := &TrustAnchors{Roots: x509.NewCertPool(), Names: map[string]string{}}

	cas, err := s.store.ListCAAuthorities(ctx, store.CAFilter{IncludePEM: true})
	if err != nil {
		return anchors, err
	}
	for _, ca := range cas {
		if ca.CertificatePEM == "" {
			continue
		}
		block, _ := pem.Decode([]byte(ca.CertificatePEM))
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			slog.Debug("a registered CA's certificate could not be parsed for trust checking", "ca", ca.Name, "error", err)
			continue
		}
		anchors.Roots.AddCert(cert)
		anchors.Certs = append(anchors.Certs, cert)
		anchors.Names[cert.Subject.String()] = ca.Name
		anchors.count++
	}
	return anchors, nil
}

// sniFor returns the SNI value for a host, which is empty for IP literals.
func sniFor(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

// allNames returns every name in the certificate a scan might match a target
// against — DNS names and IP addresses, plus the common name when it is not
// already among them, because plenty of internal certificates still carry the
// hostname only there.
func allNames(cert *x509.Certificate) []string {
	names := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+1)
	seen := map[string]bool{}
	appendName := func(n string) {
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		names = append(names, n)
	}
	for _, n := range cert.DNSNames {
		appendName(n)
	}
	for _, ip := range cert.IPAddresses {
		appendName(ip.String())
	}
	appendName(cert.Subject.CommonName)
	return names
}

func encodePEM(certs []*x509.Certificate) string {
	var b strings.Builder
	for _, cert := range certs {
		if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return b.String()
		}
	}
	return b.String()
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}

// keyExchangeName names the negotiated group. A zero CurveID means a legacy RSA
// key exchange was used, which carries no forward secrecy at all — worth saying
// in words rather than leaving the column empty.
func keyExchangeName(id tls.CurveID) string {
	if id == 0 {
		return "RSA key transport (no forward secrecy)"
	}
	return id.String()
}

// allCipherSuites offers everything Go can speak, insecure suites included.
//
// Only the client's offer. What matters is what the server picked, and a server
// that picks 3DES has told us something we could not have learned by refusing to
// let it.
func allCipherSuites() []uint16 {
	suites := tls.CipherSuites()
	insecure := tls.InsecureCipherSuites()
	ids := make([]uint16, 0, len(suites)+len(insecure))
	for _, s := range suites {
		ids = append(ids, s.ID)
	}
	for _, s := range insecure {
		ids = append(ids, s.ID)
	}
	return ids
}
