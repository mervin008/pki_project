package passwords

import (
	"errors"
	"strings"
	"testing"
)

func TestAHashVerifiesAgainstItsOwnPassword(t *testing.T) {
	const secret = "correct horse battery staple"
	encoded, err := Hash(secret)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := Verify(secret, encoded); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestTheSamePasswordHashesDifferentlyEachTime(t *testing.T) {
	const secret = "correct horse battery staple"
	first, _ := Hash(secret)
	second, _ := Hash(secret)

	if first == second {
		t.Fatal("two hashes of one password are identical — the salt is not random, " +
			"so a stolen table would reveal which accounts share a password")
	}
	if err := Verify(secret, second); err != nil {
		t.Fatalf("the second hash does not verify: %v", err)
	}
}

func TestAWrongPasswordIsRejected(t *testing.T) {
	encoded, _ := Hash("correct horse battery staple")
	if err := Verify("Correct horse battery staple", encoded); !errors.Is(err, ErrMismatch) {
		t.Fatalf("err = %v, want ErrMismatch — verification is not case sensitive", err)
	}
}

// TestAnAccountWithNoPasswordCannotBeSignedInto. An SSO-only user has a null
// hash, and an empty stored value must never be treated as "matches anything".
func TestAnAccountWithNoPasswordCannotBeSignedInto(t *testing.T) {
	for _, stored := range []string{"", "   "} {
		if err := Verify("anything at all", stored); !errors.Is(err, ErrUnusable) {
			t.Fatalf("Verify against %q = %v, want ErrUnusable", stored, err)
		}
	}
}

// TestParametersAreReadFromTheHash is what allows the cost to be raised later
// without invalidating every existing password.
func TestParametersAreReadFromTheHash(t *testing.T) {
	// A hash made with deliberately smaller parameters than the current build.
	const secret = "correct horse battery staple"
	encoded, _ := Hash(secret)

	weaker := strings.Replace(encoded, "m=65536,t=3,p=4", "m=16384,t=2,p=2", 1)
	if weaker == encoded {
		t.Fatalf("the parameter substitution did not apply: %s", encoded)
	}

	// It must fail to match rather than error: the parameters differ, so the
	// derived key differs. The point is that it is *read* and not assumed.
	if err := Verify(secret, weaker); !errors.Is(err, ErrMismatch) {
		t.Fatalf("err = %v, want a clean mismatch — the parameters were not read back", err)
	}
}

func TestAMalformedHashIsAnErrorNotAMatch(t *testing.T) {
	for _, bad := range []string{
		"not-a-hash",
		"$argon2id$v=19$m=65536,t=3,p=4$onlyfourparts",
		"$bcrypt$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=bad,t=3,p=4$c2FsdA$aGFzaA",
	} {
		err := Verify("anything", bad)
		if err == nil {
			t.Fatalf("Verify against %q returned nil — a broken hash was treated as a match", bad)
		}
		if errors.Is(err, ErrMismatch) {
			continue // also acceptable: refused
		}
	}
}

func TestLengthIsTheRuleAndItCountsRunes(t *testing.T) {
	if err := Validate(strings.Repeat("a", MinLength-1)); err == nil {
		t.Fatal("a password below the minimum was accepted")
	}
	if err := Validate(strings.Repeat("a", MinLength)); err != nil {
		t.Fatalf("a password at the minimum was refused: %v", err)
	}
	if err := Validate(strings.Repeat("a", MaxLength+1)); err == nil {
		t.Fatal("an unbounded password was accepted — each attempt allocates 64 MiB")
	}

	// Twelve characters, thirty-six bytes. Measuring bytes would reject it.
	if err := Validate("正確馬電池訂書針パスワード"); err != nil {
		t.Fatalf("a non-Latin passphrase of %d runes was refused: %v",
			len([]rune("正確馬電池訂書針パスワード")), err)
	}
}

func TestControlCharactersAreRefused(t *testing.T) {
	for _, bad := range []string{
		"password with\na newline",
		"password with\ra return",
		"password with\x00a null",
		"            ",
	} {
		if err := Validate(bad); err == nil {
			t.Fatalf("Validate(%q) accepted it", bad)
		}
	}
}
