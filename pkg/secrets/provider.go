package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// Provider supplies the key encryption key at start-up.
//
// The KEK is the one secret CertPilot cannot function without and cannot
// recover if it is lost: every certificate private key and CA credential in the
// database is sealed under it. Where it comes from is therefore a deployment
// decision, not a code one, and this interface is what makes it configurable
// without the rest of the package caring.
//
// Providers return base64 rather than raw bytes so that decodeKey stays the
// single place a key is validated. A provider that returned []byte would each
// have to decide what "wrong length" means, and they would drift.
type Provider interface {
	// Name identifies the provider in logs and error messages. An operator
	// debugging a failed start needs to know which one was asked.
	Name() string
	// Load returns the primary KEK and any retired ones. Retired keys are
	// accepted for decryption only, which is what makes rotation incremental
	// rather than a flag day.
	Load(ctx context.Context) (primary string, retired []string, err error)
}

// ── Environment ─────────────────────────────────────────

// EnvProvider reads CERTPILOT_KEK and CERTPILOT_KEK_RETIRED.
//
// The original mechanism and still the default, because changing it silently
// would strand every existing deployment. It is also the weakest: an
// environment variable is readable through /proc/<pid>/environ by anything
// running as the same user, is inherited by every child process, appears in
// core dumps and in `docker inspect`, and tends to end up committed in an
// orchestrator manifest. FileProvider exists because none of that is true of a
// mounted secret.
type EnvProvider struct{}

func (EnvProvider) Name() string { return "environment" }

func (EnvProvider) Load(context.Context) (string, []string, error) {
	primary := strings.TrimSpace(os.Getenv("CERTPILOT_KEK"))
	if primary == "" {
		return "", nil, ErrNoKey
	}
	return primary, splitRetired(os.Getenv("CERTPILOT_KEK_RETIRED")), nil
}

// ── File ────────────────────────────────────────────────

// FileProvider reads the KEK from a file.
//
// This is the shape every secret manager already speaks: a Docker secret, a
// Kubernetes secret volume, a systemd credential, and `vault agent` templating
// all arrive as a file on disk. None of them need the value to pass through the
// process environment on the way.
type FileProvider struct {
	Path string
	// RetiredPaths are read for decryption only. One key per file rather than a
	// list in one file, because that is how a secret manager mounts them and
	// because a parse error in a shared file would take the primary down too.
	RetiredPaths []string
}

func (f FileProvider) Name() string { return "file " + f.Path }

func (f FileProvider) Load(context.Context) (string, []string, error) {
	if f.Path == "" {
		return "", nil, fmt.Errorf("secrets: no key file is configured")
	}

	primary, err := readKeyFile(f.Path)
	if err != nil {
		return "", nil, err
	}

	retired := make([]string, 0, len(f.RetiredPaths))
	for _, path := range f.RetiredPaths {
		key, err := readKeyFile(path)
		if err != nil {
			return "", nil, fmt.Errorf("secrets: retired key file: %w", err)
		}
		retired = append(retired, key)
	}
	return primary, retired, nil
}

func readKeyFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("secrets: could not read the key file %s: %w", path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("secrets: %s is a directory, not a key file", path)
	}

	mode := info.Mode().Perm()

	// Writable by group or other is refused, not warned about. Anybody who can
	// write this file can replace the KEK — which after the next restart makes
	// every stored secret undecryptable, and lets them seal new ones under a key
	// they hold. That is not a permissions nicety, it is control of the system.
	if mode&0o022 != 0 {
		return "", fmt.Errorf(
			"secrets: the key file %s is writable by other users (mode %#o). Anybody who can write it "+
				"can replace the key encryption key, which would make every stored secret unreadable. "+
				"Run: chmod 600 %s", path, mode, path)
	}

	// Readable by others is a warning rather than a refusal. It is genuinely
	// wrong on a shared host and genuinely harmless in a single-tenant
	// container, and Kubernetes mounts secret volumes 0644 by default — so
	// refusing would break correct deployments to enforce a rule that does not
	// always apply.
	if mode&0o044 != 0 {
		slog.Warn("the key encryption key file is readable by other users",
			"path", path, "mode", fmt.Sprintf("%#o", mode),
			"advice", "chmod 600 unless the filesystem is private to this process")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("secrets: could not read the key file %s: %w", path, err)
	}

	// Trimmed, because a key file written with `echo` has a trailing newline
	// and base64 decoding would fail on it — reporting an invalid key for a file
	// whose contents are perfectly correct.
	key := strings.TrimSpace(string(raw))
	if key == "" {
		return "", fmt.Errorf("secrets: the key file %s is empty", path)
	}
	return key, nil
}

// ── HashiCorp Vault ─────────────────────────────────────

// VaultProvider reads the KEK from Vault's key/value store.
//
// The key still ends up in this process's memory — that is inherent to a system
// that has to use it, and is listed as undefended in the security model. What
// changes is everything around it: the key is not in an environment variable,
// not on the disk of the machine running the core, and reading it is
// authenticated, audited by Vault, and revocable without redeploying anything.
//
// Delegated unwrapping — Vault's transit engine, where the core never holds the
// key at all and asks Vault to unwrap each DEK — would be better still. It is
// not this, because it changes the envelope format rather than where a key
// comes from. See the note in docs/security.md.
type VaultProvider struct {
	// Address is the Vault API base, e.g. https://vault.internal:8200.
	Address string
	// Path is the full API path to the secret, e.g.
	// "secret/data/certpilot/kek" for KV v2 or "secret/certpilot/kek" for v1.
	Path string
	// Field and RetiredField name the keys within that secret. Field defaults
	// to "kek"; RetiredField defaults to "retired" and may be absent.
	Field        string
	RetiredField string
	// Token authenticates the read. TokenFile is preferred: it is what an
	// AppRole login, `vault agent`, or a Kubernetes service account produces,
	// and it can be rotated under a running process.
	Token     string
	TokenFile string
	// Namespace is Vault Enterprise's tenancy header. Empty for open source.
	Namespace string
	// Client may be supplied to control TLS. Nil uses a default with a timeout.
	Client *http.Client
}

func (v VaultProvider) Name() string { return "vault " + v.Address + "/" + v.Path }

func (v VaultProvider) Load(ctx context.Context) (string, []string, error) {
	if v.Address == "" || v.Path == "" {
		return "", nil, fmt.Errorf("secrets: the Vault key provider needs both an address and a path")
	}

	token := strings.TrimSpace(v.Token)
	if v.TokenFile != "" {
		raw, err := os.ReadFile(v.TokenFile)
		if err != nil {
			return "", nil, fmt.Errorf("secrets: could not read the Vault token file %s: %w", v.TokenFile, err)
		}
		token = strings.TrimSpace(string(raw))
	}
	if token == "" {
		token = strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	}
	if token == "" {
		return "", nil, fmt.Errorf(
			"secrets: no Vault token is available. Set secrets.vault.token_file, or VAULT_TOKEN " +
				"for development")
	}

	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	url := strings.TrimSuffix(v.Address, "/") + "/v1/" + strings.TrimPrefix(v.Path, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("X-Vault-Token", token)
	if v.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.Namespace)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("secrets: could not reach Vault at %s: %w", v.Address, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", nil, fmt.Errorf("secrets: could not read Vault's response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Vault's own error text is included: "permission denied" and "no
		// handler for route" call for completely different fixes, and an
		// operator whose core will not start needs to know which it was.
		return "", nil, fmt.Errorf("secrets: Vault returned HTTP %d reading %s: %s",
			resp.StatusCode, v.Path, strings.TrimSpace(string(body)))
	}

	var envelope struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", nil, fmt.Errorf("secrets: Vault's response was not JSON: %w", err)
	}

	fields, err := vaultFields(envelope.Data)
	if err != nil {
		return "", nil, err
	}

	field := v.Field
	if field == "" {
		field = "kek"
	}
	primary, ok := fields[field]
	if !ok || strings.TrimSpace(primary) == "" {
		return "", nil, fmt.Errorf("secrets: the Vault secret at %s has no %q field", v.Path, field)
	}

	retiredField := v.RetiredField
	if retiredField == "" {
		retiredField = "retired"
	}
	return strings.TrimSpace(primary), splitRetired(fields[retiredField]), nil
}

// vaultFields flattens the KV v1 and KV v2 response shapes.
//
// KV v2 nests the secret one level deeper than v1 ({"data":{"data":{...}}}
// against {"data":{...}}), and which one a path uses is invisible from the path
// itself when someone has remounted it. Detecting it here means an operator
// does not have to declare a version that Vault already knows.
func vaultFields(data map[string]json.RawMessage) (map[string]string, error) {
	if data == nil {
		return nil, fmt.Errorf("secrets: Vault returned no data for this path")
	}

	if nested, ok := data["data"]; ok {
		var inner map[string]string
		if err := json.Unmarshal(nested, &inner); err == nil && inner != nil {
			return inner, nil
		}
	}

	flat := make(map[string]string, len(data))
	for key, raw := range data {
		var value string
		if err := json.Unmarshal(raw, &value); err == nil {
			flat[key] = value
		}
	}
	return flat, nil
}

// splitRetired parses a comma-separated list, tolerating spaces and blanks.
func splitRetired(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// ── Assembly ────────────────────────────────────────────

// LoadKeyringFrom builds a keyring from any provider.
//
// The validation lives here rather than in each provider so that "this is not a
// 32-byte key" reads identically however the key arrived, and so a new provider
// cannot accidentally accept something the others would refuse.
func LoadKeyringFrom(ctx context.Context, p Provider) (*Keyring, error) {
	if p == nil {
		return nil, ErrNoKey
	}

	primaryB64, retiredB64, err := p.Load(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(primaryB64) == "" {
		return nil, ErrNoKey
	}

	primary, err := decodeKey(primaryB64)
	if err != nil {
		return nil, fmt.Errorf("secrets: the key from %s is invalid: %w", p.Name(), err)
	}

	retired := make([][]byte, 0, len(retiredB64))
	for i, encoded := range retiredB64 {
		key, err := decodeKey(encoded)
		if err != nil {
			return nil, fmt.Errorf("secrets: retired key %d from %s is invalid: %w", i, p.Name(), err)
		}
		retired = append(retired, key)
	}

	return NewKeyring(primary, retired...)
}
