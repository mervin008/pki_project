package secrets

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func newTestKeyring(t *testing.T) *Keyring {
	t.Helper()
	kr, err := NewEphemeralKeyring()
	if err != nil {
		t.Fatalf("NewEphemeralKeyring: %v", err)
	}
	return kr
}

func TestRoundTrip(t *testing.T) {
	kr := newTestKeyring(t)

	plaintext := "-----BEGIN PRIVATE KEY-----\nnot really a key\n-----END PRIVATE KEY-----"
	sealed, err := kr.EncryptString(plaintext, ContextCertificatePrivKey)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	if strings.Contains(sealed, "PRIVATE KEY") {
		t.Fatal("ciphertext leaks plaintext")
	}

	got, err := kr.DecryptString(sealed, ContextCertificatePrivKey)
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if got != plaintext {
		t.Fatalf("round trip mismatch:\n got %q\nwant %q", got, plaintext)
	}
}

func TestEmptyPlaintextRoundTrips(t *testing.T) {
	kr := newTestKeyring(t)

	sealed, err := kr.EncryptString("", ContextCAAccountConfig)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	got, err := kr.DecryptString(sealed, ContextCAAccountConfig)
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestCiphertextsAreNonDeterministic(t *testing.T) {
	kr := newTestKeyring(t)

	a, err := kr.EncryptString("same input", ContextCAAccountConfig)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	b, err := kr.EncryptString("same input", ContextCAAccountConfig)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	if a == b {
		t.Fatal("identical plaintext produced identical ciphertext; nonce or DEK is being reused")
	}
}

// The context binding is the property that stops a ciphertext being moved from
// one column to another, so it deserves a direct test.
func TestContextMismatchFailsClosed(t *testing.T) {
	kr := newTestKeyring(t)

	sealed, err := kr.EncryptString("cloudflare-api-token", ContextCAAccountConfig)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	if _, err := kr.DecryptString(sealed, ContextCertificatePrivKey); !errors.Is(err, ErrWrongContext) {
		t.Fatalf("expected ErrWrongContext, got %v", err)
	}
}

func TestTamperedCiphertextIsRejected(t *testing.T) {
	kr := newTestKeyring(t)

	sealed, err := kr.EncryptString("payload worth tampering with", ContextCAAccountConfig)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Flip a bit in the final ciphertext byte.
	raw[len(raw)-1] ^= 0x01
	tampered := base64.StdEncoding.EncodeToString(raw)

	if _, err := kr.DecryptString(tampered, ContextCAAccountConfig); !errors.Is(err, ErrWrongContext) {
		t.Fatalf("expected authentication failure, got %v", err)
	}
}

func TestForeignKeyringCannotDecrypt(t *testing.T) {
	mine := newTestKeyring(t)
	theirs := newTestKeyring(t)

	sealed, err := mine.EncryptString("secret", ContextCAAccountConfig)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	if _, err := theirs.DecryptString(sealed, ContextCAAccountConfig); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("expected ErrUnknownKey, got %v", err)
	}
}

func TestRotationReadsOldWritesNew(t *testing.T) {
	oldKEK := make([]byte, KEKSize)
	newKEK := make([]byte, KEKSize)
	for i := range oldKEK {
		oldKEK[i] = byte(i)
		newKEK[i] = byte(255 - i)
	}

	before, err := NewKeyring(oldKEK)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	sealed, err := before.EncryptString("legacy value", ContextCAAccountConfig)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	// Operator rotates: new primary, old key retained for reads.
	after, err := NewKeyring(newKEK, oldKEK)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}

	got, err := after.DecryptString(sealed, ContextCAAccountConfig)
	if err != nil {
		t.Fatalf("post-rotation decrypt: %v", err)
	}
	if got != "legacy value" {
		t.Fatalf("got %q, want %q", got, "legacy value")
	}

	if !after.NeedsRotation(sealed) {
		t.Fatal("NeedsRotation should flag a ciphertext sealed under the retired key")
	}

	resealed, err := after.EncryptString(got, ContextCAAccountConfig)
	if err != nil {
		t.Fatalf("reseal: %v", err)
	}
	if after.NeedsRotation(resealed) {
		t.Fatal("freshly sealed ciphertext should not need rotation")
	}

	// Once the old key is dropped, only the resealed value survives.
	final, err := NewKeyring(newKEK)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	if _, err := final.DecryptString(sealed, ContextCAAccountConfig); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("expected old ciphertext to be unreadable, got %v", err)
	}
	if _, err := final.DecryptString(resealed, ContextCAAccountConfig); err != nil {
		t.Fatalf("resealed ciphertext should still open: %v", err)
	}
}

func TestMalformedInputs(t *testing.T) {
	kr := newTestKeyring(t)

	cases := map[string]string{
		"empty":            "",
		"not base64":       "!!!!not base64!!!!",
		"too short":        base64.StdEncoding.EncodeToString([]byte("CPS1short")),
		"wrong magic":      base64.StdEncoding.EncodeToString(make([]byte, envelopeOverhead+8)),
		"plaintext legacy": "plain-old-unencrypted-config",
	}

	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := kr.DecryptString(input, ContextCAAccountConfig); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestIsEnvelope(t *testing.T) {
	kr := newTestKeyring(t)

	sealed, err := kr.EncryptString("value", ContextCAAccountConfig)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	if !IsEnvelope(sealed) {
		t.Fatal("sealed value should be recognised as an envelope")
	}
	for _, plain := range []string{"", "{\"directory_url\":\"https://example\"}", "not-base64!!"} {
		if IsEnvelope(plain) {
			t.Fatalf("plaintext %q should not be recognised as an envelope", plain)
		}
	}
}

func TestNewKeyringRejectsWrongLength(t *testing.T) {
	if _, err := NewKeyring(make([]byte, 16)); err == nil {
		t.Fatal("expected an error for a 16-byte primary key")
	}
	if _, err := NewKeyring(make([]byte, KEKSize), make([]byte, 31)); err == nil {
		t.Fatal("expected an error for a 31-byte retired key")
	}
}

func TestLoadKeyringRequiresKey(t *testing.T) {
	t.Setenv("CERTPILOT_KEK", "")
	if _, err := LoadKeyring(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("expected ErrNoKey, got %v", err)
	}
}

func TestLoadKeyringFromEnv(t *testing.T) {
	primary, err := GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}
	retired, err := GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}

	t.Setenv("CERTPILOT_KEK", primary)
	t.Setenv("CERTPILOT_KEK_RETIRED", retired)

	kr, err := LoadKeyring()
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	if len(kr.keks) != 2 {
		t.Fatalf("expected 2 keys in the ring, got %d", len(kr.keks))
	}

	sealed, err := kr.EncryptString("env round trip", ContextACMEAccountKey)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	got, err := kr.DecryptString(sealed, ContextACMEAccountKey)
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if got != "env round trip" {
		t.Fatalf("got %q", got)
	}
}

func TestLoadKeyringRejectsBadEncoding(t *testing.T) {
	t.Setenv("CERTPILOT_KEK", "obviously-not-a-32-byte-base64-key")
	if _, err := LoadKeyring(); err == nil {
		t.Fatal("expected an error for a malformed key")
	}
}

func TestNilKeyringFailsClosed(t *testing.T) {
	var kr *Keyring
	if _, err := kr.EncryptString("x", ContextCAAccountConfig); !errors.Is(err, ErrNoKey) {
		t.Fatalf("expected ErrNoKey on encrypt, got %v", err)
	}
	if _, err := kr.DecryptString("x", ContextCAAccountConfig); !errors.Is(err, ErrNoKey) {
		t.Fatalf("expected ErrNoKey on decrypt, got %v", err)
	}
}

func TestLargePayload(t *testing.T) {
	kr := newTestKeyring(t)

	large := strings.Repeat("chain-pem-block\n", 8192)
	sealed, err := kr.EncryptString(large, ContextCertificatePrivKey)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	got, err := kr.DecryptString(sealed, ContextCertificatePrivKey)
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if got != large {
		t.Fatal("large payload did not round trip")
	}
}
