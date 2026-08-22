package fleet

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/store"
	providerv1 "github.com/certpilot/certpilot/pkg/pb/provider/v1"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/certpilot/certpilot/pkg/x509util"
)

// maxRequestedNames bounds one request.
//
// A certificate for four hundred hostnames is not a certificate somebody meant
// to ask for, and refusing it early is cheaper than discovering the CA's own
// limit at the far end of an issuance.
const maxRequestedNames = 100

// Issuer signs certificate requests that came from a host.
//
// This is the point of the whole agent. The key was generated on the machine
// that will use it and has never left; what arrives here is a request, and
// CertPilot never holds a secret it could lose, copy, or be compelled to
// produce.
//
// Which makes authorisation the entire security surface. A credential that can
// request any name is a way to obtain a certificate for the payroll system from
// a compromised web server, signed by the organisation's own CA, indexed in the
// audit log next to every legitimate issuance. So nothing is signed that an
// operator did not grant in advance.
type Issuer struct {
	store     store.Store
	pluginMgr *pluginmgr.Manager
	keyring   *secrets.Keyring
	broker    *events.Broker
	now       func() time.Time
}

// NewIssuer creates the issuer.
func NewIssuer(s store.Store, pm *pluginmgr.Manager, kr *secrets.Keyring, broker *events.Broker) *Issuer {
	return &Issuer{store: s, pluginMgr: pm, keyring: kr, broker: broker, now: time.Now}
}

// Request is what an agent submits.
type Request struct {
	// CSRPem carries the names, the public key, and a signature proving the
	// requester holds the private half. Nothing else in it is honoured.
	CSRPem string `json:"csr_pem"`
	// InstallPath is where the agent intends to keep it, recorded so the
	// inventory can be matched against issuance without guessing.
	InstallPath string `json:"install_path,omitempty"`
	// Renews is the certificate this replaces, when the agent is rotating a key
	// it already holds.
	Renews string `json:"renews,omitempty"`
}

// Issued is what goes back to the host.
type Issued struct {
	CertificateID  string    `json:"certificate_id"`
	CommonName     string    `json:"common_name"`
	SANs           []string  `json:"sans"`
	CertificatePEM string    `json:"certificate_pem"`
	ChainPEM       string    `json:"chain_pem,omitempty"`
	NotAfter       time.Time `json:"not_after"`
	// RenewAfter is when this host may ask for a replacement. Decided by the
	// grant, not by the agent, so a fleet cannot decide to renew itself hourly.
	RenewAfter time.Time `json:"renew_after"`
}

// Issue validates a request against what its host has been granted, and signs
// it if it holds up.
func (i *Issuer) Issue(ctx context.Context, agent *store.Agent, req Request) (*Issued, error) {
	csr, err := parseCSR(req.CSRPem)
	if err != nil {
		return nil, err
	}

	names, err := requestedNames(csr)
	if err != nil {
		return nil, err
	}

	grant, err := i.authorise(ctx, agent, csr, names)
	if err != nil {
		// Refusals are published, not only returned. A host asking for a name
		// it has not been granted is either a misconfiguration somebody needs
		// to fix or the first sign of a compromised credential, and both look
		// identical from here — which is exactly why a person should see it.
		i.announceRefusal(agent, names, err)
		return nil, err
	}

	account, err := i.store.GetCAAccount(ctx, grant.CAAccountID)
	if err != nil {
		return nil, fmt.Errorf("the CA account this grant issues from no longer exists: %w", err)
	}
	gateway, err := i.gateway(account)
	if err != nil {
		return nil, err
	}
	config, err := decryptCAConfig(i.keyring, account)
	if err != nil {
		return nil, err
	}

	keyType, keySize := describeCSRKey(csr)
	slog.Info("signing a request from a host",
		"agent", agent.Name, "names", names, "grant", grant.Name,
		"ca_account", account.Name, "key", fmt.Sprintf("%s/%d", keyType, keySize),
		"private_key", "never sent, never held")

	resp, err := gateway.Client.IssueCertificate(ctx, &providerv1.IssueCertificateRequest{
		CsrPem: []byte(req.CSRPem),
		// The names CertPilot validated, not the ones the request asked for.
		// The two are the same here — that is what authorise checked — but
		// passing the validated set means a gateway that trusts its caller is
		// trusting a decision that was actually made.
		Domains:        names,
		KeyType:        keyType,
		KeySize:        int32(keySize),
		ValidityDays:   int32(grant.ValidityDays),
		ProviderConfig: config,
	})
	if err != nil {
		return nil, fmt.Errorf("the CA refused this request: %w", err)
	}
	if resp.Certificate == nil || len(resp.Certificate.CertificatePem) == 0 {
		return nil, fmt.Errorf("the gateway reported success and returned no certificate")
	}

	// Parsed before it is stored, so a gateway that returns something that is
	// not a certificate cannot put it in the inventory.
	info, err := x509util.ParseCertificatePEM(resp.Certificate.CertificatePem)
	if err != nil {
		return nil, fmt.Errorf("the CA returned data that is not a valid X.509 certificate: %w", err)
	}

	// A gateway that returns a private key for a CSR-based request has
	// generated its own keypair and ignored the request. Storing that would be
	// worse than failing: the certificate on the host would not match the key
	// in the database, and both would look fine.
	if len(resp.Certificate.PrivateKeyPem) > 0 {
		return nil, fmt.Errorf(
			"the %s gateway returned a private key for a request that carried its own public key, which means it ignored the request. Refusing to store a certificate whose key CertPilot was not supposed to have",
			account.ProviderType)
	}

	cert, err := i.record(ctx, agent, grant, req, info, resp)
	if err != nil {
		return nil, err
	}

	issued := &Issued{
		CertificateID:  cert.ID,
		CommonName:     cert.CommonName,
		SANs:           cert.SANs,
		CertificatePEM: string(resp.Certificate.CertificatePem),
		ChainPEM:       string(resp.Certificate.ChainPem),
		NotAfter:       info.NotAfter,
		RenewAfter:     info.NotAfter.AddDate(0, 0, -grant.RenewBeforeDays),
	}
	return issued, nil
}

// record writes the issued certificate to the inventory.
//
// With no private key, and said so explicitly rather than left as an absence:
// KeyCustodyAgent is the difference between "we do not have this key" and "this
// key is on a host and we could not produce it if we were ordered to".
func (i *Issuer) record(ctx context.Context, agent *store.Agent, grant *store.AgentGrant,
	req Request, info *x509util.CertInfo, resp *providerv1.IssueCertificateResponse) (*store.Certificate, error) {

	notBefore, notAfter := info.NotBefore, info.NotAfter
	certPEM := string(resp.Certificate.CertificatePem)
	holder := agent.ID
	accountID := grant.CAAccountID

	cert := &store.Certificate{
		FingerprintSHA256: info.FingerprintSHA256,
		CommonName:        info.CommonName,
		SANs:              info.SANs,
		SerialNumber:      info.SerialNumber,
		IssuerDN:          info.IssuerDN,
		NotBefore:         &notBefore,
		NotAfter:          &notAfter,
		DaysRemaining:     info.DaysRemaining,
		KeyType:           info.KeyType,
		KeySize:           info.KeySize,
		Status:            "ISSUED",
		// The core does not renew this one. The host holds the key, so only the
		// host can rotate it, and a sweep that tried would fail on every
		// attempt forever.
		AutoRenew:        false,
		RenewalLeadDays:  grant.RenewBeforeDays,
		CAAccountID:      &accountID,
		CertificatePEM:   &certPEM,
		DiscoveredVia:    "AGENT",
		KeyCustody:       store.KeyCustodyAgent,
		KeyHolderAgentID: &holder,
	}
	if len(resp.Certificate.ChainPem) > 0 {
		chain := string(resp.Certificate.ChainPem)
		cert.ChainPEM = &chain
	}

	if err := i.store.CreateCertificate(ctx, cert); err != nil {
		return nil, fmt.Errorf("the certificate was issued and could not be recorded: %w", err)
	}

	_ = i.store.CreateAuditLog(ctx, &store.AuditLog{
		Action:     "cert.issued_to_agent",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		Details: fmt.Sprintf(`{"cn":%q,"agent":%q,"grant":%q,"install_path":%q,"key_custody":"AGENT"}`,
			cert.CommonName, agent.Name, grant.Name, req.InstallPath),
	})

	if i.broker != nil {
		i.broker.Publish(events.Event{
			Topic:    events.TopicCertIssued,
			Severity: events.SeverityInfo,
			EntityID: cert.ID,
			Payload: map[string]any{
				"common_name": cert.CommonName,
				"not_after":   notAfter.Format(time.RFC3339),
				"gateway":     agent.Name + " (key generated on the host)",
			},
		})
	}
	return cert, nil
}

// authorise decides whether this host may have this certificate.
func (i *Issuer) authorise(ctx context.Context, agent *store.Agent,
	csr *x509.CertificateRequest, names []string) (*store.AgentGrant, error) {

	grants, err := i.store.GetGrantsForAgent(ctx, agent.ID)
	if err != nil {
		return nil, fmt.Errorf("could not read what this host is allowed to ask for: %w", err)
	}
	if len(grants) == 0 {
		return nil, fmt.Errorf(
			"%s has no grant, so it may not request certificates. Create one with POST /api/v1/agent-grants naming this agent or a label it carries",
			agent.Name)
	}

	keyType, keySize := describeCSRKey(csr)

	// One grant has to cover the whole request. Assembling permission from
	// several would let a host combine a grant for one tier's names with
	// another tier's CA account, and the resulting certificate would be
	// something nobody authorised as a whole.
	var reasons []string
	for _, grant := range grants {
		if missing := uncovered(grant, names); len(missing) > 0 {
			reasons = append(reasons, fmt.Sprintf("%s does not cover %s",
				grant.Name, strings.Join(missing, ", ")))
			continue
		}
		if ok, why := grant.AllowsKey(keyType, keySize); !ok {
			reasons = append(reasons, fmt.Sprintf("%s: %s", grant.Name, why))
			continue
		}
		return grant, nil
	}

	return nil, fmt.Errorf("no grant permits this request from %s — %s",
		agent.Name, strings.Join(reasons, "; "))
}

func uncovered(grant *store.AgentGrant, names []string) []string {
	missing := []string{}
	for _, name := range names {
		if !grant.Covers(name) {
			missing = append(missing, name)
		}
	}
	return missing
}

// parseCSR reads a request and checks it is what it claims to be.
func parseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("csr_pem is not a PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("csr_pem is not a certificate request: %w", err)
	}

	// Proof of possession, and the reason a CSR is worth more than a list of
	// names. Without this check anybody who can reach this endpoint could
	// obtain a certificate for a public key belonging to somebody else — which
	// is a certificate issued to that somebody else, from an authority this
	// organisation runs.
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("the request is not signed by the key it contains: %w", err)
	}

	if err := refuseDangerousExtensions(csr); err != nil {
		return nil, err
	}
	return csr, nil
}

// OIDs for the extensions a request has no business asking for.
var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
)

// refuseDangerousExtensions rejects a request that asks to be an authority.
//
// A CSR is a request, not an instruction, and a correct CA builds its own
// template and ignores everything in the request but the public key and the
// names. That is what the gateways here do — but "the code downstream is
// careful" is not a control, it is a hope about code that may be replaced by a
// third-party gateway next year.
//
// So it is refused rather than stripped. A client asking for basicConstraints
// CA:TRUE or keyCertSign is either broken or hostile, and both deserve an error
// rather than a certificate that silently is not what they asked for.
func refuseDangerousExtensions(csr *x509.CertificateRequest) error {
	for _, ext := range csr.Extensions {
		switch {
		case ext.Id.Equal(oidBasicConstraints):
			var bc struct {
				IsCA       bool `asn1:"optional"`
				MaxPathLen int  `asn1:"optional,default:-1"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &bc); err == nil && bc.IsCA {
				return fmt.Errorf(
					"this request asks for a CA certificate (basicConstraints CA:TRUE). An agent may request certificates for the names it has been granted, never an authority that could issue more")
			}
		case ext.Id.Equal(oidKeyUsage):
			var usage asn1.BitString
			if _, err := asn1.Unmarshal(ext.Value, &usage); err != nil {
				continue
			}
			// Bit 5 is keyCertSign in the KeyUsage bit string.
			const keyCertSignBit = 5
			if usage.BitLength > keyCertSignBit && usage.At(keyCertSignBit) == 1 {
				return fmt.Errorf(
					"this request asks for the keyCertSign usage, which would let the certificate sign others. An agent may request certificates, never an authority")
			}
		}
	}
	return nil
}

// requestedNames pulls the hostnames out of a request.
//
// The common name is folded into the set rather than treated separately,
// because a grant has to authorise every name a certificate will carry and CN
// is one of them — a request whose SANs are all permitted and whose CN is not
// would otherwise produce a certificate for a name nobody granted.
func requestedNames(csr *x509.CertificateRequest) ([]string, error) {
	if len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		return nil, fmt.Errorf(
			"this request carries an IP address, email, or URI name. Only DNS names are issued to agents: the others are validated differently and a grant has no way to express them")
	}

	seen := map[string]bool{}
	names := []string{}
	add := func(name string) {
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		names = append(names, name)
	}

	add(csr.Subject.CommonName)
	for _, name := range csr.DNSNames {
		add(name)
	}

	if len(names) == 0 {
		return nil, fmt.Errorf("this request names nothing: it has no common name and no DNS names")
	}
	if len(names) > maxRequestedNames {
		return nil, fmt.Errorf("this request carries %d names, which is more than the %d allowed",
			len(names), maxRequestedNames)
	}
	return names, nil
}

// describeCSRKey reports the key in a request.
func describeCSRKey(csr *x509.CertificateRequest) (string, int) {
	switch pub := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case ed25519.PublicKey:
		return "Ed25519", 256
	}
	return csr.PublicKeyAlgorithm.String(), 0
}

func (i *Issuer) gateway(account *store.CAAccount) (*pluginmgr.GatewayClient, error) {
	gw, err := i.pluginMgr.GetGateway(account.Name)
	if err == nil {
		return gw, nil
	}
	gw, err = i.pluginMgr.GetGateway(account.ProviderType)
	if err != nil {
		return nil, fmt.Errorf("the gateway for CA account %s is not connected: %w", account.Name, err)
	}
	return gw, nil
}

// decryptCAConfig opens a CA account's sealed configuration.
func decryptCAConfig(keyring *secrets.Keyring, acc *store.CAAccount) (string, error) {
	if acc.ConfigEncrypted == "" {
		return "", nil
	}
	if !secrets.IsEnvelope(acc.ConfigEncrypted) {
		return acc.ConfigEncrypted, nil
	}
	plaintext, err := keyring.DecryptString(acc.ConfigEncrypted, secrets.ContextCAAccountConfig)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt the configuration for CA account %q: %w", acc.Name, err)
	}
	return plaintext, nil
}

// announceRefusal publishes a request that was not permitted.
//
// A host asking for a name it has not been granted is either a
// misconfiguration somebody needs to fix or the first sign of a stolen
// credential being used, and the two are indistinguishable from here. That is
// precisely why it goes to a person rather than only into a log.
func (i *Issuer) announceRefusal(agent *store.Agent, names []string, cause error) {
	if i.broker == nil {
		return
	}
	i.broker.Publish(events.Event{
		Topic:    events.TopicAgentRequestRefused,
		Severity: events.SeverityWarning,
		EntityID: agent.ID,
		Payload: map[string]any{
			"agent":    agent.Name,
			"hostname": agent.Hostname,
			"names":    names,
			"reason":   cause.Error(),
		},
	})
}
