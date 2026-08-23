// Package webhooksig defines the one signature scheme CertPilot uses when it
// posts to somebody else's HTTP endpoint.
//
// One definition rather than one per feature. Alerts and deployments both sign
// their bodies, and if the two drifted an integrator would end up with a
// verifier that works for notifications and silently rejects — or worse,
// silently accepts — deployments. The scheme is small enough that a second copy
// is pure risk.
package webhooksig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// Headers CertPilot sets on a signed delivery.
const (
	// SignatureHeader carries the hex HMAC-SHA256.
	SignatureHeader = "X-CertPilot-Signature"
	// TimestampHeader carries the Unix seconds the signature covers.
	TimestampHeader = "X-CertPilot-Timestamp"
	// EventHeader lets a receiver route without parsing the body.
	EventHeader = "X-CertPilot-Event"
)

// Sign returns the hex HMAC-SHA256 a receiver should reproduce.
//
// The timestamp is inside the signed string, not merely alongside it. Signing
// the body alone yields a signature that stays valid forever, so anyone who
// captures one delivery can replay it indefinitely and the receiver cannot
// tell. With the timestamp covered, a receiver rejects anything older than its
// own tolerance and replay becomes bounded.
//
// The signed string is exactly:
//
//	<unix-seconds> "." <raw request body>
//
// Exported so a receiver written in Go can call it, and so the test suite
// verifies the same function an integrator would.
func Sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a signature in constant time and enforces a freshness window.
//
// Provided so the property the sender promises is testable, and so a Go
// receiver has no reason to hand-roll the comparison with ==.
func Verify(secret, timestamp, signature string, body []byte, tolerance time.Duration) error {
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("timestamp is not valid: %w", err)
	}
	age := time.Since(time.Unix(seconds, 0))
	if age < 0 {
		age = -age
	}
	if tolerance > 0 && age > tolerance {
		return fmt.Errorf("timestamp is %s outside the tolerance of %s", age.Round(time.Second), tolerance)
	}

	want := Sign(secret, timestamp, body)
	if !hmac.Equal([]byte(want), []byte(signature)) {
		return fmt.Errorf("signature does not match")
	}
	return nil
}
