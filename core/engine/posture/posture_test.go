package posture

import (
	"strings"
	"testing"
)

// TestASignatureIsAPlanAndAKeyExchangeIsAnIncident.
//
// The distinction this whole package exists to make, and the one most
// reporting on the subject gets backwards. Nobody forges a handshake that
// already happened, so a classical signature is something to fix at reissuance.
// Traffic under a classical key exchange is being recorded now.
func TestASignatureIsAPlanAndAKeyExchangeIsAnIncident(t *testing.T) {
	cert := Certificate("ECDSA", 256, "ECDSA-SHA256")
	if cert.Verdict != VerdictClassical {
		t.Fatalf("an ordinary ECDSA certificate is classical, got %s", cert.Verdict)
	}
	if !strings.Contains(cert.Summary, "reissued rather than now") {
		t.Fatalf("a classical signature should be framed as a plan: %q", cert.Summary)
	}

	// The same estate's endpoint, offered a hybrid group and declining it.
	endpoint := Endpoint("TLS 1.3", "CurveP256", false, true)
	if endpoint.Verdict != VerdictExposed {
		t.Fatalf("a TLS 1.3 endpoint refusing a hybrid group is exposed, got %s", endpoint.Verdict)
	}
	if !strings.Contains(endpoint.Summary, "recorded today") {
		t.Fatalf("the endpoint summary should name harvest-now-decrypt-later: %q", endpoint.Summary)
	}
}

// TestAnObservationIsNotAFindingUntilWeKnowWhatWeOffered.
//
// "This endpoint did not negotiate a post-quantum group" is a fact about the
// server only if one was offered. Otherwise the same row is a fact about
// CertPilot, and reporting it as the first would be a scanner blaming an estate
// for its own configuration.
func TestAnObservationIsNotAFindingUntilWeKnowWhatWeOffered(t *testing.T) {
	silent := Endpoint("TLS 1.3", "CurveP256", false, false)
	if silent.Verdict == VerdictExposed {
		t.Fatal("without offering a hybrid group, nothing can be concluded about the server")
	}
	if !strings.Contains(silent.Summary, "says nothing about whether this endpoint") {
		t.Fatalf("the summary should say the observation is empty: %q", silent.Summary)
	}
	if !strings.Contains(silent.Requirements[0].Detail, "CertPilot did not offer") {
		t.Fatalf("the requirement should name whose fault the gap is: %q", silent.Requirements[0].Detail)
	}
}

// TestTLS12CannotBeFixedByEnablingAGroup.
//
// There is no hybrid key exchange below TLS 1.3, so an endpoint on 1.2 needs a
// protocol upgrade rather than a configuration change — a much bigger job, and
// one that reads identically to the smaller one if the message does not say so.
func TestTLS12CannotBeFixedByEnablingAGroup(t *testing.T) {
	old := Endpoint("TLS 1.2", "CurveP256", false, true)
	if old.Verdict != VerdictExposed {
		t.Fatalf("expected EXPOSED, got %s", old.Verdict)
	}
	if !strings.Contains(old.Summary, "needs TLS 1.3") {
		t.Fatalf("the summary should say a group cannot fix this: %q", old.Summary)
	}

	modern := Endpoint("TLS 1.3", "X25519MLKEM768", true, true)
	if modern.Verdict != VerdictHybrid || modern.Score != 100 {
		t.Fatalf("a hybrid handshake should be HYBRID at 100, got %s at %d", modern.Verdict, modern.Score)
	}
}

// TestSomethingBrokenTodayOutranksSomethingBrokenIn2035.
//
// A certificate signed with SHA-1 is forgeable now by anyone with a modest
// budget. Burying that under a paragraph about quantum computing would be this
// product's founding complaint, committed by this product.
func TestSomethingBrokenTodayOutranksSomethingBrokenIn2035(t *testing.T) {
	cases := map[string]struct {
		keyType   string
		keySize   int
		signature string
		mentions  string
	}{
		"SHA-1":    {"RSA", 2048, "SHA1-RSA", "not a quantum problem"},
		"MD5":      {"RSA", 2048, "MD5-RSA", "forgeable since 2008"},
		"RSA-1024": {"RSA", 1024, "SHA256-RSA", "below the 2048-bit floor"},
		"DSA":      {"DSA", 2048, "DSA-SHA256", "should not be in use at all"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := Certificate(tc.keyType, tc.keySize, tc.signature)
			if got.Verdict != VerdictWeak {
				t.Fatalf("expected WEAK, got %s", got.Verdict)
			}
			if !strings.Contains(got.Summary, tc.mentions) {
				t.Fatalf("expected the summary to mention %q, got %q", tc.mentions, got.Summary)
			}
		})
	}
}

// TestSHA256IsAShortfallRatherThanABreak.
//
// Lumping SHA-256 in with SHA-1 would be false and would teach the reader to
// ignore the category. Grover halves the effective preimage resistance, so
// SHA-256 gives 128 bits where CNSA 2.0 asks for 192 — a gap, not a break.
func TestSHA256IsAShortfallRatherThanABreak(t *testing.T) {
	got := Certificate("ECDSA", 256, "ECDSA-SHA256")
	if got.Verdict == VerdictWeak {
		t.Fatal("SHA-256 is not broken and must not be reported as though it were")
	}

	var hash *Requirement
	for i := range got.Requirements {
		if got.Requirements[i].Code == "hash" {
			hash = &got.Requirements[i]
		}
	}
	if hash == nil || hash.Found != "SHA-256" || hash.Met {
		t.Fatalf("SHA-256 should be found and unmet: %+v", hash)
	}
	if !strings.Contains(hash.Detail, "sound today") {
		t.Fatalf("the detail should distinguish a shortfall from a break: %q", hash.Detail)
	}

	// SHA-384 meets it.
	stronger := Certificate("ECDSA", 384, "ECDSA-SHA384")
	for _, r := range stronger.Requirements {
		if r.Code == "hash" && !r.Met {
			t.Fatal("SHA-384 meets CNSA 2.0")
		}
	}
}

// TestOnlyTheSpecifiedParameterSetMeetsCNSA.
//
// ML-DSA-44 is post-quantum and is not what CNSA 2.0 asks for. Reporting it as
// compliant would make the whole assessment worthless to the only people who
// have to care about CNSA 2.0.
func TestOnlyTheSpecifiedParameterSetMeetsCNSA(t *testing.T) {
	weakerPQ := Certificate("ML-DSA-44", 0, "ML-DSA-44")
	for _, r := range weakerPQ.Requirements {
		if r.Code == "signature" {
			if r.Met {
				t.Fatal("ML-DSA-44 is not ML-DSA-87")
			}
			if !strings.Contains(r.Detail, "not the parameter set") {
				t.Fatalf("the detail should say why: %q", r.Detail)
			}
		}
	}
	if weakerPQ.Verdict == VerdictReady {
		t.Fatalf("only the specified parameter set is READY, got %s", weakerPQ.Verdict)
	}

	full := Certificate("ML-DSA-87", 0, "ML-DSA-87-SHA512")
	if full.Verdict != VerdictReady || full.Score != 100 {
		t.Fatalf("ML-DSA-87 with SHA-512 is ready, got %s at %d", full.Verdict, full.Score)
	}
}

// TestTheScoreIsConformanceNotRisk.
//
// A certificate scoring zero is the normal state of nearly every certificate in
// production, and presenting that as an alarm is how a report gets muted.
func TestTheScoreIsConformanceNotRisk(t *testing.T) {
	ordinary := Certificate("RSA", 2048, "SHA256-RSA")
	if ordinary.Score != 0 {
		t.Fatalf("RSA-2048 with SHA-256 meets neither CNSA 2.0 requirement, got %d", ordinary.Score)
	}
	if ordinary.Verdict == VerdictWeak {
		t.Fatal("RSA-2048 with SHA-256 is entirely fine today and must not read as weak")
	}

	half := Certificate("RSA", 3072, "SHA384-RSA")
	if half.Score != 50 {
		t.Fatalf("meeting one of two requirements is 50, got %d", half.Score)
	}
}
