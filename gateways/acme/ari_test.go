package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testCertificate builds a certificate with a known AKI and serial so the
// RFC 9773 identifier can be checked exactly.
func testCertificate(t *testing.T, aki []byte, serial *big.Int) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        pkix.Name{CommonName: "example.com"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(30 * 24 * time.Hour),
		AuthorityKeyId: aki,
		DNSNames:       []string{"example.com"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func TestARICertID(t *testing.T) {
	aki := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	cert := testCertificate(t, aki, big.NewInt(0x1234))

	got, err := ARICertID(cert)
	if err != nil {
		t.Fatalf("ARICertID: %v", err)
	}

	akiPart, serialPart, found := strings.Cut(got, ".")
	if !found {
		t.Fatalf("certID %q is not two base64url segments joined by a dot", got)
	}

	decodedAKI, err := base64.RawURLEncoding.DecodeString(akiPart)
	if err != nil {
		t.Fatalf("AKI segment is not unpadded base64url: %v", err)
	}
	if string(decodedAKI) != string(aki) {
		t.Fatalf("AKI = %x, want %x", decodedAKI, aki)
	}

	decodedSerial, err := base64.RawURLEncoding.DecodeString(serialPart)
	if err != nil {
		t.Fatalf("serial segment is not unpadded base64url: %v", err)
	}
	if want := []byte{0x12, 0x34}; string(decodedSerial) != string(want) {
		t.Fatalf("serial = %x, want %x", decodedSerial, want)
	}

	// Padding characters are not permitted in the identifier.
	if strings.Contains(got, "=") {
		t.Fatalf("certID %q contains base64 padding", got)
	}
}

// A serial whose leading byte has the high bit set needs a 0x00 prefix, or the
// DER INTEGER would read as negative and the CA would not recognise the
// certificate.
func TestARICertIDHighBitSerial(t *testing.T) {
	cert := testCertificate(t, []byte{0xAA}, new(big.Int).SetBytes([]byte{0x80, 0x01}))

	got, err := ARICertID(cert)
	if err != nil {
		t.Fatalf("ARICertID: %v", err)
	}

	_, serialPart, _ := strings.Cut(got, ".")
	decoded, err := base64.RawURLEncoding.DecodeString(serialPart)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	want := []byte{0x00, 0x80, 0x01}
	if string(decoded) != string(want) {
		t.Fatalf("serial = %x, want %x (missing the DER sign padding byte)", decoded, want)
	}
}

func TestARICertIDRequiresAKI(t *testing.T) {
	cert := testCertificate(t, nil, big.NewInt(1))

	if _, err := ARICertID(cert); err == nil {
		t.Fatal("expected an error for a certificate with no Authority Key Identifier")
	}
}

func TestDERIntegerBytes(t *testing.T) {
	cases := []struct {
		in   *big.Int
		want []byte
	}{
		{big.NewInt(0), []byte{0}},
		{big.NewInt(1), []byte{1}},
		{big.NewInt(127), []byte{127}},
		{big.NewInt(128), []byte{0x00, 0x80}},
		{big.NewInt(255), []byte{0x00, 0xFF}},
		{big.NewInt(256), []byte{0x01, 0x00}},
		{nil, []byte{0}},
	}

	for _, tc := range cases {
		got := derIntegerBytes(tc.in)
		if string(got) != string(tc.want) {
			t.Errorf("derIntegerBytes(%v) = %x, want %x", tc.in, got, tc.want)
		}
	}
}

func TestFetchRenewalInfo(t *testing.T) {
	start := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	end := start.Add(48 * time.Hour)

	var gotPath string
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/directory", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce":    srv.URL + "/nonce",
			"newOrder":    srv.URL + "/order",
			"renewalInfo": srv.URL + "/renewal-info",
		})
	})
	mux.HandleFunc("/renewal-info/", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Retry-After", "21600")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"suggestedWindow": map[string]string{
				"start": start.Format(time.RFC3339),
				"end":   end.Format(time.RFC3339),
			},
			"explanationURL": "https://example.com/incident",
		})
	})

	client := newARIClient(http.DefaultClient)
	cert := testCertificate(t, []byte{0xDE, 0xAD}, big.NewInt(42))

	info, err := client.Fetch(context.Background(), srv.URL+"/directory", cert)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if !info.Start.Equal(start) {
		t.Errorf("start = %s, want %s", info.Start, start)
	}
	if !info.End.Equal(end) {
		t.Errorf("end = %s, want %s", info.End, end)
	}
	if info.ExplanationURL != "https://example.com/incident" {
		t.Errorf("explanationURL = %q", info.ExplanationURL)
	}
	if info.RetryAfter != 6*time.Hour {
		t.Errorf("retryAfter = %s, want 6h", info.RetryAfter)
	}

	certID, _ := ARICertID(cert)
	if wantPath := "/renewal-info/" + certID; gotPath != wantPath {
		t.Errorf("requested %q, want %q", gotPath, wantPath)
	}
}

// A CA with no renewalInfo endpoint is a normal CA, not an error condition.
func TestFetchRenewalInfoUnsupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"newOrder": "https://example.com/order"})
	}))
	defer srv.Close()

	client := newARIClient(http.DefaultClient)
	cert := testCertificate(t, []byte{0x01}, big.NewInt(1))

	_, err := client.Fetch(context.Background(), srv.URL, cert)
	if err != errARIUnsupported {
		t.Fatalf("err = %v, want errARIUnsupported", err)
	}
}

// A 404 means this CA did not issue the certificate; callers fall back to
// lead-time renewal rather than failing.
func TestFetchRenewalInfoNotFound(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/directory", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"renewalInfo": srv.URL + "/renewal-info"})
	})
	mux.HandleFunc("/renewal-info/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	client := newARIClient(http.DefaultClient)
	cert := testCertificate(t, []byte{0x01}, big.NewInt(1))

	if _, err := client.Fetch(context.Background(), srv.URL+"/directory", cert); err != errARIUnsupported {
		t.Fatalf("err = %v, want errARIUnsupported", err)
	}
}

func TestRenewNow(t *testing.T) {
	now := time.Now()

	cases := map[string]struct {
		info *RenewalInfo
		want bool
	}{
		"window in the future": {&RenewalInfo{Start: now.Add(time.Hour), End: now.Add(2 * time.Hour)}, false},
		"window is open":       {&RenewalInfo{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}, true},
		"window has passed":    {&RenewalInfo{Start: now.Add(-2 * time.Hour), End: now.Add(-time.Hour)}, false},
		"nil":                  {nil, false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tc.info.RenewNow(); got != tc.want {
				t.Fatalf("RenewNow = %v, want %v", got, tc.want)
			}
		})
	}
}

// Randomising within the window is the entire point of ARI: renewing at window
// start would relocate the thundering herd rather than disperse it.
func TestSelectRenewalTimeIsSpreadAcrossTheWindow(t *testing.T) {
	start := time.Now().Add(24 * time.Hour)
	end := start.Add(48 * time.Hour)
	info := &RenewalInfo{Start: start, End: end}

	seen := make(map[int64]bool)
	for i := 0; i < 200; i++ {
		picked := info.SelectRenewalTime()
		if picked.Before(start) || picked.After(end) {
			t.Fatalf("picked %s, outside [%s, %s]", picked, start, end)
		}
		seen[picked.Unix()] = true
	}

	// With a 48-hour window, 200 draws landing on a handful of values would
	// mean the selection is not actually spreading load.
	if len(seen) < 50 {
		t.Fatalf("only %d distinct times across 200 draws; selection is not spreading load", len(seen))
	}
}

func TestSelectRenewalTimeWithWindowAlreadyOpen(t *testing.T) {
	now := time.Now()
	info := &RenewalInfo{Start: now.Add(-24 * time.Hour), End: now.Add(24 * time.Hour)}

	picked := info.SelectRenewalTime()
	if picked.Before(now.Add(-time.Minute)) {
		t.Fatalf("picked %s, which is in the past; a late client should renew from now onward", picked)
	}
	if picked.After(info.End) {
		t.Fatalf("picked %s, past the window end", picked)
	}
}

func TestSelectRenewalTimeWithDegenerateWindow(t *testing.T) {
	at := time.Now().Add(time.Hour)
	info := &RenewalInfo{Start: at, End: at}

	if picked := info.SelectRenewalTime(); !picked.Equal(at) {
		t.Fatalf("picked %s, want %s for a zero-width window", picked, at)
	}
}

func TestParseRetryAfter(t *testing.T) {
	cases := map[string]time.Duration{
		"":                              0,
		"3600":                          time.Hour,
		"0":                             0,
		"-5":                            0,
		"not a number":                  0,
		"Mon, 02 Jan 2006 15:04:05 GMT": 0, // in the past
	}

	for input, want := range cases {
		t.Run(input, func(t *testing.T) {
			if got := parseRetryAfter(input); got != want {
				t.Fatalf("parseRetryAfter(%q) = %s, want %s", input, got, want)
			}
		})
	}

	future := time.Now().Add(2 * time.Hour).UTC().Format(http.TimeFormat)
	if got := parseRetryAfter(future); got < 90*time.Minute || got > 2*time.Hour {
		t.Fatalf("parseRetryAfter(http date) = %s, want roughly 2h", got)
	}
}

// The directory lookup is cached, so a per-certificate poll does not refetch it.
func TestRenewalInfoEndpointIsCached(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_ = json.NewEncoder(w).Encode(map[string]string{"renewalInfo": "https://example.com/ari"})
	}))
	defer srv.Close()

	client := newARIClient(http.DefaultClient)
	for i := 0; i < 5; i++ {
		if _, err := client.renewalInfoEndpoint(context.Background(), srv.URL); err != nil {
			t.Fatalf("renewalInfoEndpoint: %v", err)
		}
	}

	if hits != 1 {
		t.Fatalf("directory fetched %d times, want 1", hits)
	}
}
