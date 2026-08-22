// Package deploy installs certificates where they are actually served.
//
// This is the point where CertPilot stops observing and starts changing
// something that is already carrying traffic, and the whole package is shaped
// by one difference:
//
//	Renewal creates new material. Deployment replaces material that is
//	currently in use.
//
// A renewal that goes wrong leaves a certificate nobody installed — bad, and
// recoverable by trying again. A deployment that goes wrong replaces a working
// certificate on a live listener. So: nothing is deployed that has not been
// parsed, nothing is deployed without the key that matches it when the target
// needs one, every attempt is recorded against the place it was made, and
// success here is reported as what it is — a claim that bytes were accepted,
// not evidence that they are being served. The evidence comes from the verifier,
// which opens a connection and looks.
package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Bundle is what a deployer installs.
//
// Built from the certificate as it stands at deploy time, not from the
// fingerprint the job recorded at enqueue. If a second renewal happened while
// the job waited, installing the fingerprint the job was created for would push
// an older certificate to a live listener — and the newer renewal's own enqueue
// may well have been a no-op, because this binding already had a job
// outstanding. Deploying what is current is the only choice that cannot leave a
// target permanently behind.
type Bundle struct {
	CertificateID     string
	CommonName        string
	SANs              []string
	SerialNumber      string
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time

	CertificatePEM string
	ChainPEM       string

	// PrivateKeyPEM is present only when the target declared that it needs one.
	// It is decrypted for the length of a single deploy and never written to
	// the job row, the audit log, or any log line.
	PrivateKeyPEM string

	// Options is the binding's placement — which secret, which path, which
	// listener. Passed through so one target can serve many certificates that
	// land in different places on it.
	Options map[string]any
}

// Deployer installs a bundle in one place.
type Deployer interface {
	// Type is the stored target type, e.g. "webhook".
	Type() string
	// Describe names this target on screen and in errors — a URL, a cluster, a
	// vault. Never a credential.
	Describe() string
	// NeedsPrivateKey reports whether this target cannot install a certificate
	// without the matching key.
	//
	// Asked before the key is fetched, so a target that does not need one never
	// causes it to be decrypted. The commonest deployment is to something that
	// already holds the key.
	NeedsPrivateKey() bool
	// Deploy installs the bundle and returns what happened, in words.
	//
	// The returned string is kept in the attempt log and shown to a person, so
	// it should name what was written where. "Deployed successfully" is not
	// something anybody can check.
	Deploy(ctx context.Context, b Bundle) (string, error)
}

// Types lists the target types that can currently be deployed to.
//
// Deliberately shorter than the set the schema allows. `deployment_targets`
// has permitted filesystem, aws_acm, kubernetes, gcp_lb and azure_kv since
// migration 001, and accepting one of those here because a check constraint
// tolerates it would create a target that can be configured, bound, and queued,
// and that fails at the last moment with an error about an unknown type.
func Types() []string {
	return []string{TypeWebhook, TypeAgent}
}

// ValidateConfig checks a target configuration and returns the JSON that will
// be sealed, along with whether this target receives private key material.
//
// Validation happens before the credentials are encrypted, so a typo is a 400
// at creation rather than a failed deployment discovered during an outage.
//
// The second return value is stored in a plain column on the target. "Which
// places does this organisation ship private keys to" has to be answerable
// without the KEK; deriving it from a sealed blob at read time would make the
// answer available only to something that can decrypt every deployment
// credential in the system.
func ValidateConfig(targetType string, config map[string]any) (raw []byte, deploysPrivateKey bool, err error) {
	if strings.EqualFold(strings.TrimSpace(targetType), TypeAgent) {
		return nil, false, fmt.Errorf(
			"an agent target cannot be created here. It appears on its own when a host running the agent reports where it installs certificates, and is named after that host")
	}
	d, err := build(targetType, config)
	if err != nil {
		return nil, false, err
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, false, err
	}
	return encoded, d.NeedsPrivateKey(), nil
}

// Build constructs a deployer from a sealed-then-opened configuration.
func Build(targetType string, configJSON string) (Deployer, error) {
	config := map[string]any{}
	if strings.TrimSpace(configJSON) != "" {
		if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
			return nil, fmt.Errorf("the configuration for this %s target is not valid JSON: %w", targetType, err)
		}
	}
	return build(targetType, config)
}

func build(targetType string, config map[string]any) (Deployer, error) {
	switch strings.TrimSpace(strings.ToLower(targetType)) {
	case TypeWebhook:
		return newWebhookDeployer(config)
	case TypeAgent:
		return newAgentDeployer(config)
	case "":
		return nil, fmt.Errorf("a deployment target needs a target_type; supported: %s", strings.Join(Types(), ", "))
	default:
		return nil, fmt.Errorf(
			"target type %q cannot be deployed to yet; supported: %s", targetType, strings.Join(Types(), ", "))
	}
}

// ── Configuration helpers ───────────────────────────────────

func configString(config map[string]any, key string) string {
	if v, ok := config[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func configBool(config map[string]any, key string) bool {
	switch v := config[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	}
	return false
}

func configStringMap(config map[string]any, key string) map[string]string {
	raw, ok := config[key].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// sortedKeys gives map iteration a stable order, so an error naming several
// fields reads the same way twice.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// missingField phrases a configuration error as an instruction rather than a
// complaint, because it is read by whoever has to fix it.
func missingField(targetType, field, what string) error {
	return fmt.Errorf("a %s target needs %s: %s", targetType, field, what)
}

// defaultClient bounds an outbound deployment.
//
// Shorter than a scan and longer than an API call: installing a certificate
// usually means a write plus a reload on the far side, and the timeout has to
// leave room for the reload without letting one wedged target hold a worker for
// minutes.
func defaultClient() *http.Client {
	return &http.Client{Timeout: 45 * time.Second}
}
