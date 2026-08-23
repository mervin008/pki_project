package solver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestChallengeFQDN(t *testing.T) {
	cases := map[string]string{
		"example.com":     "_acme-challenge.example.com",
		"www.example.com": "_acme-challenge.www.example.com",
		"example.com.":    "_acme-challenge.example.com",
	}

	for domain, want := range cases {
		ch := Challenge{Domain: domain}
		if got := ch.FQDN(); got != want {
			t.Errorf("FQDN(%q) = %q, want %q", domain, got, want)
		}
	}
}

// ACME validates "*.example.com" against the TXT record for
// "_acme-challenge.example.com", so the wildcard label must come off first.
func TestBaseDomain(t *testing.T) {
	cases := map[string]string{
		"*.example.com":     "example.com",
		"example.com":       "example.com",
		"*.www.example.com": "www.example.com",
	}

	for in, want := range cases {
		if got := BaseDomain(in); got != want {
			t.Errorf("BaseDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSetPrefersDNS01(t *testing.T) {
	http01, err := NewHTTP01("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewHTTP01: %v", err)
	}
	defer http01.Close()

	cf, err := NewCloudflare("token")
	if err != nil {
		t.Fatalf("NewCloudflare: %v", err)
	}

	set := NewSet(http01, cf)

	// dns-01 must be listed first: it is the only type that can satisfy a
	// wildcard, so it should be tried first when a CA offers a choice.
	types := set.Types()
	if len(types) != 2 || types[0] != TypeDNS01 {
		t.Fatalf("Types() = %v, want dns-01 first", types)
	}
	if set.Empty() {
		t.Fatal("set should not be empty")
	}
}

func TestEmptySet(t *testing.T) {
	set := NewSet()
	if !set.Empty() {
		t.Fatal("expected an empty set")
	}
	if _, ok := set.For(TypeDNS01); ok {
		t.Fatal("empty set should resolve no solvers")
	}

	var nilSet *Set
	if !nilSet.Empty() {
		t.Fatal("a nil set should report empty")
	}
	if err := nilSet.Close(); err != nil {
		t.Fatalf("closing a nil set should be a no-op: %v", err)
	}
}

func TestHTTP01ServesChallenge(t *testing.T) {
	s, err := NewHTTP01("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewHTTP01: %v", err)
	}
	defer s.Close()

	ch := Challenge{Type: TypeHTTP01, Domain: "example.com", Token: "test-token", Value: "test-token.key-auth"}
	if err := s.Present(context.Background(), ch); err != nil {
		t.Fatalf("Present: %v", err)
	}

	base := "http://" + s.Addr()

	resp, err := http.Get(base + ChallengePathPrefix + "test-token")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != ch.Value {
		t.Fatalf("body = %q, want %q", body, ch.Value)
	}

	// An unknown token must 404 rather than echo anything.
	unknown, err := http.Get(base + ChallengePathPrefix + "other-token")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer unknown.Body.Close()
	if unknown.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown token status = %d, want 404", unknown.StatusCode)
	}

	// After cleanup the token must stop being served.
	if err := s.CleanUp(context.Background(), ch); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	after, err := http.Get(base + ChallengePathPrefix + "test-token")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer after.Body.Close()
	if after.StatusCode != http.StatusNotFound {
		t.Fatalf("status after cleanup = %d, want 404", after.StatusCode)
	}
}

// The listener must not answer anything outside the well-known path.
func TestHTTP01DoesNotServeOtherPaths(t *testing.T) {
	s, err := NewHTTP01("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewHTTP01: %v", err)
	}
	defer s.Close()

	for _, path := range []string{"/", "/index.html", "/.well-known/", "/.well-known/acme-challenge/"} {
		resp, err := http.Get("http://" + s.Addr() + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestHTTP01RejectsEmptyToken(t *testing.T) {
	s, err := NewHTTP01("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewHTTP01: %v", err)
	}
	defer s.Close()

	if err := s.Present(context.Background(), Challenge{Type: TypeHTTP01}); err == nil {
		t.Fatal("expected an error for an empty token")
	}
}

// Cleanup of a challenge that was never presented must not error: it is called
// on the failure path, where some challenges may not have been reached.
func TestHTTP01CleanUpIsIdempotent(t *testing.T) {
	s, err := NewHTTP01("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewHTTP01: %v", err)
	}
	defer s.Close()

	ch := Challenge{Token: "never-presented"}
	for i := 0; i < 3; i++ {
		if err := s.CleanUp(context.Background(), ch); err != nil {
			t.Fatalf("CleanUp: %v", err)
		}
	}
}

func TestWebhookSolver(t *testing.T) {
	const signingSecret = "shared-signing-secret"

	var got WebhookRequest
	var gotSignature, gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotSignature = r.Header.Get(SignatureHeader)
		gotAuth = r.Header.Get("Authorization")
		_ = json.Unmarshal(body, &got)

		// Verify the signature the way a real receiver would.
		mac := hmac.New(sha256.New, []byte(signingSecret))
		mac.Write(body)
		if !hmac.Equal([]byte(gotSignature), []byte(hex.EncodeToString(mac.Sum(nil)))) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, err := NewWebhook(srv.URL, "bearer-token", signingSecret)
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}

	ch := Challenge{Type: TypeDNS01, Domain: "example.com", Token: "tok", Value: "txt-value"}
	if err := s.Present(context.Background(), ch); err != nil {
		t.Fatalf("Present: %v", err)
	}

	if got.Action != "present" {
		t.Errorf("action = %q, want present", got.Action)
	}
	if got.FQDN != "_acme-challenge.example.com" {
		t.Errorf("fqdn = %q", got.FQDN)
	}
	if got.Value != "txt-value" {
		t.Errorf("value = %q", got.Value)
	}
	if gotAuth != "Bearer bearer-token" {
		t.Errorf("authorization = %q", gotAuth)
	}
	if gotSignature == "" {
		t.Error("expected an HMAC signature header")
	}

	if err := s.CleanUp(context.Background(), ch); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if got.Action != "cleanup" {
		t.Errorf("action = %q, want cleanup", got.Action)
	}
}

func TestWebhookSurfacesReceiverErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("zone is read-only"))
	}))
	defer srv.Close()

	s, err := NewWebhook(srv.URL, "", "")
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}

	err = s.Present(context.Background(), Challenge{Type: TypeDNS01, Domain: "example.com", Value: "v"})
	if err == nil {
		t.Fatal("expected an error")
	}
	// The receiver's message is the actionable part, so it must survive.
	if !contains(err.Error(), "zone is read-only") {
		t.Fatalf("error should include the receiver's message, got: %v", err)
	}
}

func TestWebhookValidatesURL(t *testing.T) {
	for _, bad := range []string{"", "   ", "ftp://example.com", "example.com"} {
		if _, err := NewWebhook(bad, "", ""); err == nil {
			t.Errorf("expected an error for URL %q", bad)
		}
	}
}

func TestCloudflareRequiresToken(t *testing.T) {
	for _, bad := range []string{"", "   "} {
		if _, err := NewCloudflare(bad); err == nil {
			t.Errorf("expected an error for token %q", bad)
		}
	}
}

func TestPropagationDefaults(t *testing.T) {
	opts := PropagationOptions{}.withDefaults()

	if opts.MinWait <= 0 || opts.Timeout <= 0 || opts.PollInterval <= 0 {
		t.Fatalf("defaults must all be positive, got %+v", opts)
	}
	// A timeout shorter than the minimum wait would make the minimum
	// unreachable.
	if opts.Timeout < opts.MinWait {
		t.Fatalf("timeout %s is shorter than the minimum wait %s", opts.Timeout, opts.MinWait)
	}

	clamped := PropagationOptions{MinWait: 60_000_000_000, Timeout: 1}.withDefaults()
	if clamped.Timeout < clamped.MinWait {
		t.Fatal("a timeout below the minimum wait should be raised to it")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
