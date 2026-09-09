// Package passwords hashes and verifies account passwords with Argon2id.
//
// Argon2id rather than bcrypt: bcrypt silently truncates at 72 bytes, which
// turns a long passphrase into a shorter one without telling anybody, and its
// cost parameter tunes time only. Argon2id is memory-hard, which is what makes
// a GPU farm expensive rather than merely slow.
package passwords

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

// Parameters for new hashes.
//
// Encoded into every hash rather than assumed, so that raising them later
// leaves existing passwords verifiable instead of locking everyone out — the
// mistake that turns a security improvement into an outage.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

// MinLength is deliberately a length floor and not a character-class rule.
//
// Composition rules ("one capital, one digit, one symbol") reliably produce
// Password1! and nothing better. Length is the property that actually costs an
// attacker something, and NIST SP 800-63B has recommended exactly this since
// 2017: a long minimum, a check against known-breached values, and no forced
// rotation.
const MinLength = 12

// MaxLength bounds the work a single request can ask for. Argon2id at these
// parameters allocates 64 MiB per call, so an unbounded password is a cheap way
// to make the core do expensive things.
const MaxLength = 256

var (
	// ErrMismatch is returned for a wrong password. It is deliberately the same
	// error whatever was wrong with it.
	ErrMismatch = errors.New("password does not match")
	// ErrUnusable marks an account with no password set — an SSO-only user.
	ErrUnusable = errors.New("this account has no password set")
)

// Hash returns an encoded Argon2id hash of the password.
func Hash(password string) (string, error) {
	if err := Validate(password); err != nil {
		return "", err
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("passwords: could not read random bytes for a salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	// The PHC string format, so the parameters travel with the hash.
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verify reports whether the password matches the encoded hash.
//
// The comparison is constant-time. A byte-by-byte comparison leaks how much of
// a guess was correct through its timing, which over enough attempts recovers
// the value.
func Verify(password, encoded string) error {
	if strings.TrimSpace(encoded) == "" {
		return ErrUnusable
	}

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return fmt.Errorf("passwords: stored hash is not in the expected argon2id format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return fmt.Errorf("passwords: stored hash has no version: %w", err)
	}
	if version != argon2.Version {
		return fmt.Errorf("passwords: stored hash uses argon2 version %d, this build has %d",
			version, argon2.Version)
	}

	// Read back from the hash, never from the constants above: an older hash
	// made with smaller parameters must still verify.
	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return fmt.Errorf("passwords: stored hash has unreadable parameters: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("passwords: stored hash has an unreadable salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("passwords: stored hash is unreadable: %w", err)
	}

	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

// Validate reports whether a password may be used.
//
// The message names the requirement rather than saying "invalid password",
// because somebody choosing one needs to know what would satisfy it.
func Validate(password string) error {
	// Counted in runes: a passphrase in a non-Latin script would otherwise be
	// measured in bytes and rejected for being long.
	length := len([]rune(password))

	if length < MinLength {
		return fmt.Errorf("a password must be at least %d characters; this one is %d",
			MinLength, length)
	}
	if length > MaxLength {
		return fmt.Errorf("a password may be at most %d characters", MaxLength)
	}

	// Rejected because they are almost always a paste that went wrong, and
	// because a password that is only whitespace cannot be typed back reliably.
	if strings.TrimSpace(password) == "" {
		return errors.New("a password cannot be only whitespace")
	}
	for _, r := range password {
		if r == '\n' || r == '\r' || r == 0 {
			return errors.New("a password cannot contain line breaks or null bytes")
		}
		if unicode.IsControl(r) && r != '\t' {
			return errors.New("a password cannot contain control characters")
		}
	}
	return nil
}
