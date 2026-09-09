package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func aKey(seed byte) string {
	key := make([]byte, KEKSize)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func writeKeyFile(t *testing.T, dir, name, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	// Chmod afterwards because WriteFile respects the umask — without this the
	// permission tests below would be testing the umask.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// ── Environment ─────────────────────────────────────────

func TestEnvProviderReadsTheKey(t *testing.T) {
	t.Setenv("CERTPILOT_KEK", aKey(1))
	t.Setenv("CERTPILOT_KEK_RETIRED", aKey(2)+", "+aKey(3))

	kr, err := LoadKeyringFrom(context.Background(), EnvProvider{})
	if err != nil {
		t.Fatal(err)
	}
	if len(kr.keks) != 3 {
		t.Errorf("expected the primary and two retired keys, got %d", len(kr.keks))
	}
}

func TestEnvProviderWithNoKeyIsErrNoKey(t *testing.T) {
	t.Setenv("CERTPILOT_KEK", "")
	if _, err := LoadKeyringFrom(context.Background(), EnvProvider{}); !errors.Is(err, ErrNoKey) {
		t.Fatalf("expected ErrNoKey, got %v", err)
	}
}

// ── File ────────────────────────────────────────────────

func TestFileProviderReadsTheKey(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyFile(t, dir, "kek", aKey(1), 0o600)
	retired := writeKeyFile(t, dir, "kek.old", aKey(2), 0o600)

	kr, err := LoadKeyringFrom(context.Background(), FileProvider{
		Path: path, RetiredPaths: []string{retired},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(kr.keks) != 2 {
		t.Errorf("expected the primary and one retired key, got %d", len(kr.keks))
	}
}

// A key file written with `echo` has a trailing newline. Failing on it would
// report an invalid key for a file whose contents are exactly right, which is a
// miserable thing to debug at the point where nothing will start.
func TestFileProviderToleratesATrailingNewline(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyFile(t, dir, "kek", aKey(1)+"\n", 0o600)

	if _, err := LoadKeyringFrom(context.Background(), FileProvider{Path: path}); err != nil {
		t.Fatalf("a trailing newline must not make a valid key invalid: %v", err)
	}
}

// Anybody who can write this file can replace the key encryption key — which
// after the next restart makes every stored secret unreadable, and lets them
// seal new ones under a key they hold. That is control of the system, not a
// permissions nicety, so it is refused rather than warned about.
func TestFileProviderRefusesAWorldWritableKey(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyFile(t, dir, "kek", aKey(1), 0o666)

	_, err := LoadKeyringFrom(context.Background(), FileProvider{Path: path})
	if err == nil {
		t.Fatal("a world-writable key file must be refused")
	}
	if !strings.Contains(err.Error(), "chmod") {
		t.Errorf("the error must say how to fix it, got %q", err)
	}
}

// Readable by others is wrong on a shared host and harmless in a single-tenant
// container, and Kubernetes mounts secret volumes 0644 by default. Refusing
// would break correct deployments to enforce a rule that does not always apply.
func TestFileProviderAcceptsAGroupReadableKey(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyFile(t, dir, "kek", aKey(1), 0o644)

	if _, err := LoadKeyringFrom(context.Background(), FileProvider{Path: path}); err != nil {
		t.Fatalf("a 0644 key file is what Kubernetes mounts; it must still load: %v", err)
	}
}

func TestFileProviderExplainsAMissingFile(t *testing.T) {
	_, err := LoadKeyringFrom(context.Background(), FileProvider{Path: "/nonexistent/kek"})
	if err == nil {
		t.Fatal("a missing key file must be an error")
	}
	if !strings.Contains(err.Error(), "/nonexistent/kek") {
		t.Errorf("the error must name the path, got %q", err)
	}
}

// A configured-but-empty file must not report ErrNoKey, which the server treats
// as "no key configured" and, alongside the in-memory store, answers by
// inventing an ephemeral one.
func TestFileProviderRefusesAnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyFile(t, dir, "kek", "\n", 0o600)

	_, err := LoadKeyringFrom(context.Background(), FileProvider{Path: path})
	if err == nil {
		t.Fatal("an empty key file must be an error")
	}
	if errors.Is(err, ErrNoKey) {
		t.Error("an empty configured file is a misconfiguration, not an absent key — " +
			"reporting ErrNoKey would let the server invent an ephemeral key instead")
	}
}

// ── Vault ───────────────────────────────────────────────

func vaultServer(t *testing.T, status int, body any) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(server.Close)
	return server
}

// KV v2 nests the secret one level deeper than v1, and which one a path uses is
// invisible from the path when somebody has remounted it.
func TestVaultProviderReadsKVv2(t *testing.T) {
	server := vaultServer(t, http.StatusOK, map[string]any{
		"data": map[string]any{
			"data": map[string]string{"kek": aKey(1), "retired": aKey(2)},
		},
	})

	kr, err := LoadKeyringFrom(context.Background(), VaultProvider{
		Address: server.URL, Path: "secret/data/certpilot/kek", Token: "a-token",
		Client: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(kr.keks) != 2 {
		t.Errorf("expected the primary and one retired key, got %d", len(kr.keks))
	}
}

func TestVaultProviderReadsKVv1(t *testing.T) {
	server := vaultServer(t, http.StatusOK, map[string]any{
		"data": map[string]string{"kek": aKey(1)},
	})

	if _, err := LoadKeyringFrom(context.Background(), VaultProvider{
		Address: server.URL, Path: "secret/certpilot/kek", Token: "a-token",
		Client: server.Client(),
	}); err != nil {
		t.Fatalf("a KV v1 secret must load without being told the version: %v", err)
	}
}

// Vault's own message is carried through, because "permission denied" and "no
// handler for route" call for completely different fixes and the operator whose
// core will not start needs to know which it was.
func TestVaultProviderCarriesVaultsError(t *testing.T) {
	server := vaultServer(t, http.StatusNotFound, map[string]any{
		"errors": []string{`no handler for route "secret/wrong/path"`},
	})

	_, err := LoadKeyringFrom(context.Background(), VaultProvider{
		Address: server.URL, Path: "secret/wrong/path", Token: "a-token",
		Client: server.Client(),
	})
	if err == nil {
		t.Fatal("a 404 from Vault must be an error")
	}
	if !strings.Contains(err.Error(), "no handler for route") {
		t.Errorf("Vault's own reason must survive, got %q", err)
	}
}

func TestVaultProviderReadsATokenFile(t *testing.T) {
	dir := t.TempDir()
	tokenFile := writeKeyFile(t, dir, "token", "s.a-vault-token\n", 0o600)

	var seen string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Vault-Token")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"data": map[string]string{"kek": aKey(1)}},
		})
	}))
	t.Cleanup(server.Close)

	if _, err := LoadKeyringFrom(context.Background(), VaultProvider{
		Address: server.URL, Path: "secret/data/kek", TokenFile: tokenFile,
		Client: server.Client(),
	}); err != nil {
		t.Fatal(err)
	}
	if seen != "s.a-vault-token" {
		t.Errorf("token sent = %q; a trailing newline in the file must be trimmed", seen)
	}
}

func TestVaultProviderNamesTheMissingField(t *testing.T) {
	server := vaultServer(t, http.StatusOK, map[string]any{
		"data": map[string]any{"data": map[string]string{"something_else": aKey(1)}},
	})

	_, err := LoadKeyringFrom(context.Background(), VaultProvider{
		Address: server.URL, Path: "secret/data/kek", Token: "a-token", Client: server.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), `"kek"`) {
		t.Fatalf("the error must name the field it looked for, got %v", err)
	}
}

// ── Assembly ────────────────────────────────────────────

// One validator, whatever the source. A provider that accepted a short key
// would produce a keyring the others would have refused.
func TestEveryProviderIsHeldToTheSameKeyLength(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("too short"))

	dir := t.TempDir()
	path := writeKeyFile(t, dir, "kek", short, 0o600)
	server := vaultServer(t, http.StatusOK, map[string]any{
		"data": map[string]any{"data": map[string]string{"kek": short}},
	})

	t.Setenv("CERTPILOT_KEK", short)
	providers := []Provider{
		EnvProvider{},
		FileProvider{Path: path},
		VaultProvider{Address: server.URL, Path: "secret/data/kek", Token: "t", Client: server.Client()},
	}

	for _, p := range providers {
		_, err := LoadKeyringFrom(context.Background(), p)
		if err == nil {
			t.Errorf("%s accepted a key that is not %d bytes", p.Name(), KEKSize)
			continue
		}
		if !strings.Contains(err.Error(), "32 bytes") {
			t.Errorf("%s: the error should say what was wrong with the key, got %q", p.Name(), err)
		}
	}
}

// A key is a key wherever it came from. Two providers holding the same value
// must produce keyrings that open each other's ciphertext — the property that
// makes moving off an environment variable a configuration change rather than a
// migration of every stored secret.
func TestAKeyMovedBetweenProvidersStillDecrypts(t *testing.T) {
	key := aKey(7)
	t.Setenv("CERTPILOT_KEK", key)

	fromEnv, err := LoadKeyringFrom(context.Background(), EnvProvider{})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := fromEnv.EncryptString("a private key", ContextCertificatePrivKey)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := writeKeyFile(t, dir, "kek", key, 0o600)
	fromFile, err := LoadKeyringFrom(context.Background(), FileProvider{Path: path})
	if err != nil {
		t.Fatal(err)
	}

	opened, err := fromFile.DecryptString(sealed, ContextCertificatePrivKey)
	if err != nil {
		t.Fatalf("moving the same key to a file must not orphan existing ciphertext: %v", err)
	}
	if opened != "a private key" {
		t.Errorf("decrypted %q", opened)
	}
}
