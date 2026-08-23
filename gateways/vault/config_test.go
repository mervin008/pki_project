package vault

import (
	"crypto/rand"
	"math/big"
	"strings"
	"testing"
)

// TestVaultSerialMatchesTheFormVaultUses covers a conversion that fails
// silently in the worst possible place. Vault's serial is colon-separated
// hexadecimal derived from the certificate's serial as a big integer; Go
// prints the same number without the colons and without a leading zero. A
// serial converted wrongly revokes nothing, and the HTTP call still succeeds.
func TestVaultSerialMatchesTheFormVaultUses(t *testing.T) {
	cases := map[string]string{
		"3a1b2c":   "3a:1b:2c",
		"3A1B2C":   "3a:1b:2c",
		"3a:1b:2c": "3a:1b:2c",
		"3a-1b-2c": "3a:1b:2c",
		"a1b2c":    "0a:1b:2c", // odd length: the leading zero Go drops
		"0a1b2c":   "0a:1b:2c",
		"":         "",
		"ff":       "ff",
	}
	for input, want := range cases {
		if got := vaultSerial(input); got != want {
			t.Errorf("vaultSerial(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestSerialsSurviveTheRoundTripThroughGo generates the values this codebase
// actually produces rather than the ones a test author thinks of. big.Int
// drops leading zeros, so roughly one serial in sixteen is odd-length — often
// enough to reach production, rarely enough to pass a hand-written table.
func TestSerialsSurviveTheRoundTripThroughGo(t *testing.T) {
	for i := 0; i < 500; i++ {
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
		if err != nil {
			t.Fatalf("generating a serial: %v", err)
		}
		colons := vaultSerial(serial.Text(16))
		bytes := strings.Split(colons, ":")
		if len(bytes) != len(serial.Bytes()) {
			t.Fatalf("serial %s became %d bytes, want %d",
				serial.Text(16), len(bytes), len(serial.Bytes()))
		}
		if again := vaultSerial(colons); again != colons {
			t.Fatalf("converting twice changed the serial: %q then %q", colons, again)
		}
	}
}

// TestPlainHTTPIsRefusedExceptOnLoopback keeps a Vault token off the wire.
func TestPlainHTTPIsRefusedExceptOnLoopback(t *testing.T) {
	cases := map[string]bool{
		"https://vault.internal:8200": true,
		"http://127.0.0.1:8200":       true,
		"http://localhost:8200":       true,
		"http://vault.internal:8200":  false,
		"vault.internal:8200":         false,
		"ftp://vault.internal":        false,
	}
	for address, wantOK := range cases {
		err := checkAddress(address)
		if wantOK && err != nil {
			t.Errorf("checkAddress(%q) = %v, want accepted", address, err)
		}
		if !wantOK && err == nil {
			t.Errorf("checkAddress(%q) was accepted", address)
		}
	}
}

// TestTheAuthMethodIsInferredFromTheCredentialSupplied saves an operator from
// naming the method as well as the credential.
func TestTheAuthMethodIsInferredFromTheCredentialSupplied(t *testing.T) {
	cases := map[string]string{
		`{"address":"https://v","role":"r","token":"t"}`:                   AuthToken,
		`{"address":"https://v","role":"r","role_id":"a","secret_id":"b"}`: AuthAppRole,
		`{"address":"https://v","role":"r","kubernetes_role":"k"}`:         AuthKubernetes,
	}
	for raw, want := range cases {
		cfg, err := ParseConfig(raw, "", "")
		if err != nil {
			t.Fatalf("parsing %s: %v", raw, err)
		}
		if cfg.AuthMethod != want {
			t.Errorf("auth method for %s = %q, want %q", raw, cfg.AuthMethod, want)
		}
	}
}

// TestContradictoryTLSSettingsAreRefused catches a configuration that supplies
// the CA to verify Vault with and then says not to verify it.
func TestContradictoryTLSSettingsAreRefused(t *testing.T) {
	cfg, err := ParseConfig(
		`{"address":"https://v","role":"r","token":"t","ca_cert_pem":"-----BEGIN CERTIFICATE-----","tls_skip_verify":true}`, "", "")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	errs, _ := cfg.Validate()
	if len(errs) == 0 {
		t.Fatalf("a configuration that both pins and ignores the CA was accepted")
	}
}

// TestAccountsWithDifferentCredentialsNeverShareAToken. The cache key decides
// which token is used for which account, and a collision would issue under an
// identity the account never named.
func TestAccountsWithDifferentCredentialsNeverShareAToken(t *testing.T) {
	base := `{"address":"https://vault.internal","role":"web","role_id":"same","secret_id":%q}`
	first, err := ParseConfig(strings.Replace(base, "%q", `"one"`, 1), "", "")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	second, err := ParseConfig(strings.Replace(base, "%q", `"two"`, 1), "", "")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if first.identity() == second.identity() {
		t.Fatalf("two accounts with different SecretIDs share a cached token")
	}

	// And the key must not be the secret itself: it goes in log lines and map
	// dumps that a credential must never reach.
	if strings.Contains(first.identity(), "one") {
		t.Fatalf("the cache key contains the credential it was derived from")
	}
}

// TestTheMountAndRoleArePathsNotNames covers the escaping that keeps a role
// name from reaching into a different endpoint.
func TestTheMountAndRoleArePathsNotNames(t *testing.T) {
	cfg, err := ParseConfig(
		`{"address":"https://v","mount":"pki-int/","role":"web app","issuer_ref":"my issuer","token":"t"}`, "", "")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if cfg.Mount != "pki-int" {
		t.Fatalf("mount = %q, want the slashes trimmed", cfg.Mount)
	}
	path := cfg.issuancePath("sign")
	if strings.Contains(path, " ") {
		t.Fatalf("issuance path %q contains an unescaped space", path)
	}
	if !strings.HasPrefix(path, "/v1/pki-int/issuer/") {
		t.Fatalf("issuance path = %q, want it pinned to the named issuer", path)
	}
}

// TestATokenAccountIsWarnedAboutBeingUnattended. A static token is the option
// that works today and stops working on a date nobody wrote down.
func TestATokenAccountIsWarnedAboutBeingUnattended(t *testing.T) {
	cfg, err := ParseConfig(`{"address":"https://v","role":"r","token":"t","issuer_ref":"i"}`, "", "")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	errs, warnings := cfg.Validate()
	if len(errs) != 0 {
		t.Fatalf("a valid token configuration was rejected: %v", errs)
	}
	if !strings.Contains(strings.Join(warnings, " "), "approle or kubernetes") {
		t.Fatalf("no warning about unattended operation: %v", warnings)
	}
}
