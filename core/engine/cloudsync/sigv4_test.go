package cloudsync

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// The signer is checked against AWS's own published test vector rather than
// against a live account.
//
// This matters more here than the usual "tests are good": SigV4 is
// hand-implemented, and the failure mode of getting it subtly wrong is a 403
// from AWS, which on a dashboard reads as "this account refused us" — an
// access problem somebody would go and investigate in IAM, finding nothing.
//
// Vector: aws-sig-v4-test-suite, get-vanilla.
func TestSigV4MatchesTheAWSTestVector(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}

	creds := awsCredentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}
	signedAt := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)

	signV4(req, nil, creds, "us-east-1", "service", signedAt)

	const want = "AWS4-HMAC-SHA256 " +
		"Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, " +
		"Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"

	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization header does not match the AWS test vector\n got: %s\nwant: %s", got, want)
	}
}

// A session token must be signed, not merely sent. Omitted from the signed
// headers it is accepted by some AWS services and rejected by others, and the
// resulting intermittent 403 is a miserable thing to chase.
func TestSessionTokenIsSigned(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://acm.eu-west-1.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Amz-Target", "CertificateManager.ListCertificates")

	signV4(req, []byte(`{}`), awsCredentials{
		AccessKeyID:     "AKID",
		SecretAccessKey: "secret",
		SessionToken:    "session-token",
	}, "eu-west-1", "acm", time.Now())

	if req.Header.Get("X-Amz-Security-Token") != "session-token" {
		t.Error("the session token was not sent")
	}
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "x-amz-security-token") {
		t.Errorf("the session token is not in SignedHeaders: %s", auth)
	}
	if !strings.Contains(auth, "x-amz-target") {
		t.Errorf("the operation target is not in SignedHeaders: %s", auth)
	}
}

// Credentials that expire mid-request must be replaced before it is sent.
// Reporting an expiring token as the account refusing us would be this tool
// blaming the system it is monitoring for its own housekeeping.
func TestCredentialsExpireEarly(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

	if (awsCredentials{}).expired(now) {
		t.Error("static credentials with no expiry read as expired")
	}
	if (awsCredentials{Expires: now.Add(10 * time.Minute)}).expired(now) {
		t.Error("credentials good for ten more minutes read as expired")
	}
	if !(awsCredentials{Expires: now.Add(30 * time.Second)}).expired(now) {
		t.Error("credentials expiring in thirty seconds were treated as usable")
	}
}
