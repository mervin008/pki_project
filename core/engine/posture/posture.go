// Package posture answers what a team actually has to plan around: which parts
// of this estate's cryptography stop working when the algorithms change, and
// which parts are losing something today.
//
// The single most important distinction in this package, and the one most
// reporting on this subject gets backwards:
//
//	A classical *signature* is a problem in the 2030s. A classical *key
//	exchange* is a problem this afternoon.
//
// Nobody can retroactively forge a handshake that already happened, so an
// RSA-signed certificate expiring in ninety days is not a quantum risk — it
// will have been replaced several times over before a cryptographically
// relevant quantum computer exists. But traffic protected by a classical key
// exchange can be recorded today and decrypted whenever that machine arrives.
// That is harvest-now-decrypt-later, it is happening now, and the fix is
// already deployed in every current browser: hybrid key exchange.
//
// So a report that ranks "your certificates use RSA" above "your endpoints do
// not negotiate X25519MLKEM768" has ordered the work by which fact is easier to
// collect rather than by which one is costing something.
package posture

import (
	"fmt"
	"strings"
)

// CNSA 2.0, as published by the NSA. The algorithm suite is stated here rather
// than referred to, so that a reader can check it against the source instead of
// trusting this package's memory of it.
//
// Deliberately no dates. The suite is published and stable; the transition
// deadlines have been revised, are stated differently for different categories
// of system, and a compliance tool that invents a deadline is worse than one
// that reports none.
const (
	CNSASignature   = "ML-DSA-87"
	CNSAKeyExchange = "ML-KEM-1024"
	CNSASymmetric   = "AES-256"
	// CNSAHash is SHA-384 or SHA-512. SHA-256 is not broken and does not meet
	// this: Grover's algorithm halves the effective preimage resistance, so
	// SHA-256 offers 128 bits against a quantum adversary where the suite asks
	// for 192.
	CNSAHash = "SHA-384 or SHA-512"
)

// Verdicts, ordered by what somebody should do about them.
const (
	// VerdictExposed is the one that costs something today: traffic to this
	// endpoint is being protected by a key exchange that a future quantum
	// computer breaks retroactively.
	VerdictExposed = "EXPOSED"
	// VerdictClassical is the ordinary state of almost every certificate in the
	// world. It is a plan, not an incident.
	VerdictClassical = "CLASSICAL"
	// VerdictHybrid means the key exchange is already protected, whatever the
	// certificate is signed with.
	VerdictHybrid = "HYBRID"
	// VerdictReady is post-quantum throughout.
	VerdictReady = "READY"
	// VerdictWeak is a certificate with a problem that has nothing to do with
	// quantum computing at all — SHA-1, RSA-1024 — and which matters now.
	VerdictWeak = "WEAK"
)

// Requirement is one CNSA 2.0 algorithm requirement, and what was found in its
// place.
type Requirement struct {
	// Code is stable and machine-readable: signature, hash, key_exchange.
	Code     string `json:"code"`
	Requires string `json:"requires"`
	Found    string `json:"found"`
	Met      bool   `json:"met"`
	// Detail says what the gap means rather than restating it. "Found RSA,
	// wanted ML-DSA-87" is not something anybody can act on.
	Detail string `json:"detail,omitempty"`
}

// Assessment is one certificate's or endpoint's cryptographic posture.
type Assessment struct {
	Verdict string `json:"verdict"`
	// Score is the percentage of applicable CNSA 2.0 requirements met, and is
	// deliberately not a risk score.
	//
	// A certificate scoring zero is the normal, correct state of nearly every
	// certificate in production today, and presenting that as an alarm would
	// make this whole report the thing people mute. What the score is for is
	// measuring movement: the same estate, six months later.
	Score        int           `json:"score"`
	Requirements []Requirement `json:"requirements"`
	// Summary is the sentence a person reads. It leads with whichever fact is
	// costing something, which is usually not the certificate.
	Summary string `json:"summary"`
}

// Certificate assesses one certificate's algorithms.
//
// A certificate has no key exchange — that belongs to the connection — so this
// covers signature and hash only, and says so. Reporting a certificate as
// "quantum ready" on the strength of its signature while the endpoint serving
// it negotiates X25519 would be exactly the half-truth this package exists to
// avoid.
func Certificate(keyType string, keySize int, signatureAlgorithm string) Assessment {
	sig := classifySignature(keyType, signatureAlgorithm)
	hash := classifyHash(signatureAlgorithm)

	assessment := Assessment{Requirements: []Requirement{sig, hash}}
	assessment.Score = scoreOf(assessment.Requirements)

	switch {
	case weakNow(keyType, keySize, signatureAlgorithm) != "":
		assessment.Verdict = VerdictWeak
		assessment.Summary = weakNow(keyType, keySize, signatureAlgorithm)
	case sig.Met && hash.Met:
		assessment.Verdict = VerdictReady
		assessment.Summary = fmt.Sprintf(
			"Signed with %s. This certificate's authenticity survives a quantum computer.", sig.Found)
	default:
		assessment.Verdict = VerdictClassical
		// Phrased as the plan it is. The alternative — "this certificate is
		// vulnerable" — is true of essentially every certificate on the
		// internet and tells nobody what to do differently this quarter.
		assessment.Summary = fmt.Sprintf(
			"Signed with %s, which a quantum computer would break. Nothing can forge a signature retroactively, so this matters when the certificate is reissued rather than now.",
			sig.Found)
	}
	return assessment
}

// Endpoint assesses what a TLS handshake actually negotiated.
//
// This is the half that is costing something today, and the half no inventory
// can produce: it takes a real handshake against a real server.
func Endpoint(tlsVersion, keyExchangeGroup string, hybrid, offeredHybrid bool) Assessment {
	kex := Requirement{
		Code: "key_exchange", Requires: CNSAKeyExchange,
		Found: fallback(keyExchangeGroup, "none observed"),
	}

	assessment := Assessment{}
	switch {
	case !offeredHybrid:
		// The finding would be about the scanner, not the server. Said rather
		// than guessed: an observation whose meaning depends on what the
		// observer offered is not an observation until the offer is recorded.
		kex.Detail = "CertPilot did not offer a hybrid group on this handshake, so nothing can be concluded about the server"
		assessment.Verdict = VerdictClassical
		assessment.Summary = "This handshake did not offer a post-quantum group, so it says nothing about whether this endpoint supports one."
		assessment.Requirements = []Requirement{kex}
		return assessment

	case hybrid:
		kex.Met = true
		kex.Detail = fmt.Sprintf(
			"%s carries ML-KEM alongside a classical exchange, so recorded traffic stays protected", keyExchangeGroup)
		assessment.Verdict = VerdictHybrid
		assessment.Summary = fmt.Sprintf(
			"Negotiated %s. Traffic to this endpoint is already protected against being recorded now and decrypted later.",
			keyExchangeGroup)

	case !supportsTLS13(tlsVersion):
		// A different finding entirely, and a much bigger job. There is no
		// hybrid key exchange below TLS 1.3, so this endpoint cannot be fixed
		// by enabling a group — it needs a protocol upgrade.
		kex.Detail = "hybrid key exchange requires TLS 1.3, which this endpoint did not negotiate"
		assessment.Verdict = VerdictExposed
		assessment.Summary = fmt.Sprintf(
			"Negotiated %s. There is no post-quantum key exchange below TLS 1.3, so traffic recorded today can be decrypted later and enabling a group will not fix it — this endpoint needs TLS 1.3.",
			fallback(tlsVersion, "an older protocol"))

	default:
		kex.Detail = "the server chose a classical group, so this traffic can be recorded now and decrypted later"
		assessment.Verdict = VerdictExposed
		assessment.Summary = fmt.Sprintf(
			"Negotiated %s over TLS 1.3, and did not take the post-quantum group that was offered. Traffic recorded today can be decrypted whenever a quantum computer arrives.",
			fallback(keyExchangeGroup, "a classical group"))
	}

	assessment.Requirements = []Requirement{kex}
	assessment.Score = scoreOf(assessment.Requirements)
	return assessment
}

// ── Classification ──────────────────────────────────────────

func classifySignature(keyType, signatureAlgorithm string) Requirement {
	found := fallback(signatureAlgorithm, keyType)
	req := Requirement{Code: "signature", Requires: CNSASignature, Found: found}

	switch {
	case isPostQuantumSignature(keyType), isPostQuantumSignature(signatureAlgorithm):
		req.Met = strings.Contains(strings.ToUpper(found), "ML-DSA-87")
		if !req.Met {
			req.Detail = fmt.Sprintf(
				"%s is post-quantum but is not the parameter set CNSA 2.0 specifies", found)
		}
	default:
		req.Detail = "a quantum computer could forge this signature, which matters at reissuance rather than now"
	}
	return req
}

// classifyHash reads the digest out of an X.509 signature algorithm name.
//
// The hash is a separate fact from the key and is not implied by it: a
// certificate can carry a perfectly good ECDSA P-384 key and be signed with
// SHA-1, and a report that looked only at key type would call it healthy.
func classifyHash(signatureAlgorithm string) Requirement {
	name := strings.ToUpper(signatureAlgorithm)
	req := Requirement{Code: "hash", Requires: CNSAHash, Found: "unknown"}

	switch {
	case strings.Contains(name, "SHA512"), strings.Contains(name, "SHA-512"):
		req.Found, req.Met = "SHA-512", true
	case strings.Contains(name, "SHA384"), strings.Contains(name, "SHA-384"):
		req.Found, req.Met = "SHA-384", true
	case strings.Contains(name, "SHA256"), strings.Contains(name, "SHA-256"):
		req.Found = "SHA-256"
		// Not broken, and worth being precise about rather than lumping in with
		// SHA-1. Grover halves the effective preimage resistance, so SHA-256
		// offers 128 bits against a quantum adversary where the suite asks for
		// 192 — a shortfall, not a break.
		req.Detail = "SHA-256 is sound today; against a quantum adversary it offers 128-bit security where CNSA 2.0 asks for 192"
	case strings.Contains(name, "SHA1"), strings.Contains(name, "SHA-1"):
		req.Found = "SHA-1"
		req.Detail = "SHA-1 is broken against classical computers and has been since 2017; this is not a quantum problem"
	case name == "":
		req.Detail = "the signature algorithm was not recorded"
	default:
		req.Found = signatureAlgorithm
	}
	return req
}

// weakNow returns a sentence when a certificate has a problem that has nothing
// to do with quantum computing, or "" when it does not.
//
// Reported ahead of any post-quantum verdict. A certificate signed with SHA-1
// is forgeable by somebody with a cluster and a weekend, today, and burying
// that under a paragraph about the 2030s would be this product's founding
// complaint committed by this product.
func weakNow(keyType string, keySize int, signatureAlgorithm string) string {
	name := strings.ToUpper(signatureAlgorithm)
	switch {
	case strings.Contains(name, "SHA1"), strings.Contains(name, "SHA-1"):
		return "Signed with SHA-1, which is forgeable today by anyone with a modest budget. This is not a quantum problem and is not waiting for one."
	case strings.Contains(name, "MD5"):
		return "Signed with MD5, which has been forgeable since 2008."
	case strings.EqualFold(keyType, "RSA") && keySize > 0 && keySize < 2048:
		return fmt.Sprintf("An RSA-%d key, which is below the 2048-bit floor and is a problem now rather than a quantum one.", keySize)
	case strings.EqualFold(keyType, "DSA"):
		return "A DSA key. DSA is deprecated and should not be in use at all."
	}
	return ""
}

func isPostQuantumSignature(name string) bool {
	upper := strings.ToUpper(name)
	for _, prefix := range []string{"ML-DSA", "SLH-DSA", "FALCON", "DILITHIUM", "SPHINCS"} {
		if strings.Contains(upper, prefix) {
			return true
		}
	}
	return false
}

func supportsTLS13(version string) bool {
	return strings.Contains(version, "1.3")
}

// scoreOf is the percentage of applicable requirements met.
//
// Plain arithmetic on purpose. A weighted score would be a set of opinions
// about relative importance encoded as a number nobody can check, and the
// opinions belong in the summary sentence where they can be read and argued
// with.
func scoreOf(requirements []Requirement) int {
	if len(requirements) == 0 {
		return 0
	}
	met := 0
	for _, r := range requirements {
		if r.Met {
			met++
		}
	}
	return met * 100 / len(requirements)
}

func fallback(value, or string) string {
	if strings.TrimSpace(value) == "" {
		return or
	}
	return value
}
