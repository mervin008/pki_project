package cloudsync

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4.
//
// Written out rather than pulled in, because the alternative is the AWS SDK's
// dependency tree — some two hundred modules — inside a process that holds
// every private key this system has ever issued. For one signed POST to one
// endpoint, the supply chain costs more than the code does.
//
// It is also entirely deterministic, which means it can be checked against
// AWS's own published test vectors rather than against a live account.

const (
	sigv4Algorithm  = "AWS4-HMAC-SHA256"
	sigv4Terminator = "aws4_request"
)

// awsCredentials are the three values a signed request needs. SessionToken is
// empty for long-lived keys and set for anything assumed.
type awsCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expires         time.Time
}

// expired reports whether these credentials need replacing.
//
// The minute of slack is not politeness: a request signed with credentials that
// expire while it is in flight fails with an authentication error, which reads
// on a dashboard as "this account rejected us" rather than "we needed to renew
// a token". A monitoring tool must not misreport its own housekeeping as the
// monitored system's fault.
func (c awsCredentials) expired(now time.Time) bool {
	if c.Expires.IsZero() {
		return false
	}
	return !now.Add(time.Minute).Before(c.Expires)
}

// signV4 signs an HTTP request in place.
//
// payload must be the exact body bytes the request will send; SigV4 signs a
// hash of it, so a body built twice is a signature that does not verify.
func signV4(req *http.Request, payload []byte, creds awsCredentials, region, service string, now time.Time) {
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Date", amzDate)
	if creds.SessionToken != "" {
		// Signed, not merely sent. A session token omitted from the signed
		// headers is accepted by some services and rejected by others, and the
		// resulting intermittent 403 is a miserable thing to debug.
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	canonicalHeaders, signedHeaders := canonicalizeHeaders(req)
	payloadHash := hexSHA256(payload)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURIPath(req.URL.EscapedPath()),
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, sigv4Terminator}, "/")
	stringToSign := strings.Join([]string{
		sigv4Algorithm,
		amzDate,
		scope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	signingKey := hmacSHA256(
		hmacSHA256(
			hmacSHA256(
				hmacSHA256([]byte("AWS4"+creds.SecretAccessKey), []byte(dateStamp)),
				[]byte(region)),
			[]byte(service)),
		[]byte(sigv4Terminator))

	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	req.Header.Set("Authorization", sigv4Algorithm+
		" Credential="+creds.AccessKeyID+"/"+scope+
		", SignedHeaders="+signedHeaders+
		", Signature="+signature)
}

// canonicalizeHeaders returns the canonical header block and the signed header
// list. Every header present is signed: signing fewer would let an intermediary
// add one without invalidating the signature.
func canonicalizeHeaders(req *http.Request) (string, string) {
	names := make([]string, 0, len(req.Header)+1)
	values := map[string]string{}

	for name, vs := range req.Header {
		lower := strings.ToLower(name)
		names = append(names, lower)
		trimmed := make([]string, 0, len(vs))
		for _, v := range vs {
			trimmed = append(trimmed, strings.Join(strings.Fields(v), " "))
		}
		values[lower] = strings.Join(trimmed, ",")
	}
	if _, ok := values["host"]; !ok {
		names = append(names, "host")
		values["host"] = req.URL.Host
	}
	sort.Strings(names)

	var canonical strings.Builder
	for _, name := range names {
		canonical.WriteString(name)
		canonical.WriteString(":")
		canonical.WriteString(values[name])
		canonical.WriteString("\n")
	}
	return canonical.String(), strings.Join(names, ";")
}

// canonicalURIPath normalises the path. An empty path signs as "/", which is
// the shape every AWS JSON endpoint uses.
func canonicalURIPath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
