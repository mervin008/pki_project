package ctlog

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/store"
)

// NormalizeSerial is load-bearing and invisible when it is wrong.
//
// CertPilot stores serials as unpadded lowercase hex; log indexes pad them and
// vary in case. A mismatch reports this system's own certificates as ones
// nobody manages — and a findings list full of your own certificates is one
// nobody reads.
func TestNormalizeSerial(t *testing.T) {
	cases := map[string]string{
		"04A2B3":                           "4a2b3",
		"04a2b3":                           "4a2b3",
		"4a2b3":                            "4a2b3",
		"0x04A2B3":                         "4a2b3",
		"04:a2:b3":                         "4a2b3",
		"  04A2B3  ":                       "4a2b3",
		"000000":                           "0",
		"0624d0ab311558780b7d5213b9631831": "624d0ab311558780b7d5213b9631831",
	}
	for in, want := range cases {
		if got := NormalizeSerial(in); got != want {
			t.Errorf("NormalizeSerial(%q) = %q, want %q", in, got, want)
		}
	}

	// The two sides must agree on a real serial from each format.
	fromCertPilot := NormalizeSerial("624d0ab311558780b7d5213b9631831")
	fromLog := NormalizeSerial("0624D0AB311558780B7D5213B9631831")
	if fromCertPilot != fromLog {
		t.Errorf("the same certificate normalizes differently: %q vs %q", fromCertPilot, fromLog)
	}
}

func TestCrtShParsesEntries(t *testing.T) {
	srv := crtShServer(t, http.StatusOK, `[
	  {"id": 12345, "issuer_name": "C=US, O=Let's Encrypt, CN=R11",
	   "common_name": "api.example.com",
	   "name_value": "api.example.com\nwww.api.example.com\napi.example.com",
	   "entry_timestamp": "2026-08-01T10:11:12.345",
	   "not_before": "2026-08-01T09:00:00", "not_after": "2026-10-30T09:00:00",
	   "serial_number": "04A2B3"}
	]`)

	entries, err := NewCrtSh(WithBaseURL(srv)).Search(context.Background(), "example.com", true, nil)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}

	e := entries[0]
	if e.ID != 12345 {
		t.Errorf("id = %d", e.ID)
	}
	if e.SerialNumber != "4a2b3" {
		t.Errorf("serial = %q, want the normalized form", e.SerialNumber)
	}
	// The duplicate in name_value must not become two SANs.
	if len(e.SANs) != 2 {
		t.Errorf("sans = %v, want the two distinct names", e.SANs)
	}
	if e.LoggedAt.IsZero() || e.NotAfter.IsZero() {
		t.Errorf("timestamps not parsed: logged=%v not_after=%v", e.LoggedAt, e.NotAfter)
	}
	if !strings.Contains(e.IssuerDN, "R11") {
		t.Errorf("issuer = %q", e.IssuerDN)
	}
}

// A source failure must be an error, never an empty result. "The index changed
// shape" and "this domain has no certificates" are opposite conclusions, and
// only one of them means you are safe.
func TestCrtShFailuresAreErrorsNotEmptyResults(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
	}{
		"rate limited":    {http.StatusTooManyRequests, "slow down"},
		"server error":    {http.StatusInternalServerError, "boom"},
		"not json at all": {http.StatusOK, "<html>maintenance</html>"},
	}
	for name, tc := range cases {
		srv := crtShServer(t, tc.status, tc.body)
		entries, err := NewCrtSh(WithBaseURL(srv)).Search(context.Background(), "example.com", true, nil)
		if err == nil {
			t.Errorf("%s: returned %d entries and no error", name, len(entries))
		}
	}
}

// The watermark is what stops every check re-reporting years of history.
func TestCrtShSkipsEntriesAlreadySeen(t *testing.T) {
	srv := crtShServer(t, http.StatusOK, `[
	  {"id": 300, "common_name": "c.example.com", "name_value": "c.example.com", "serial_number": "03"},
	  {"id": 200, "common_name": "b.example.com", "name_value": "b.example.com", "serial_number": "02"},
	  {"id": 100, "common_name": "a.example.com", "name_value": "a.example.com", "serial_number": "01"}
	]`)

	since := int64(200)
	entries, err := NewCrtSh(WithBaseURL(srv)).Search(context.Background(), "example.com", true, &since)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != 300 {
		t.Fatalf("got %+v, want only entry 300", entries)
	}
}

// The apex must be covered. Watching "%.example.com" alone misses
// example.com itself, which is usually the one certificate everybody assumed
// was included.
func TestSubdomainQueryCoversTheApex(t *testing.T) {
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query().Get("q")
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)

	if _, err := NewCrtSh(WithBaseURL(srv.URL)).Search(context.Background(), "example.com", true, nil); err != nil {
		t.Fatalf("Search: %v", err)
	}
	if query != "%.example.com" {
		t.Errorf("query = %q; crt.sh treats %%.example.com as covering the apex too", query)
	}
}

// The distinction the whole feature rests on: a monitor that could not reach
// the log must not look like one that found nothing.
func TestAFailedCheckDoesNotLookLikeACleanOne(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	monitor := &store.CTMonitor{Domain: "example.com", IncludeSubdomains: true,
		IsEnabled: true, CheckIntervalMinutes: 360}
	if err := st.CreateCTMonitor(ctx, monitor); err != nil {
		t.Fatalf("CreateCTMonitor: %v", err)
	}

	failing := NewMonitor(st, WithSource(&stubSource{err: fmt.Errorf("crt.sh answered 503")}))
	failing.CheckDue(ctx)

	after, err := st.GetCTMonitor(ctx, monitor.ID)
	if err != nil {
		t.Fatalf("GetCTMonitor: %v", err)
	}
	if after.LastCheckedAt == nil {
		t.Error("the attempt was not recorded")
	}
	// The load-bearing assertion.
	if after.LastSuccessAt != nil {
		t.Error("a failed check moved last_success_at, so the monitor now reads as healthy")
	}
	if after.LastError == "" {
		t.Error("the failure was not recorded, so nothing on screen can say why")
	}
	if after.NextCheckAt == nil {
		t.Error("a failed check left the monitor due, so it will retry every tick forever")
	}

	// And a successful check that finds nothing looks different from that.
	quiet := NewMonitor(st, WithSource(&stubSource{}))
	quiet.CheckDue(ctx)
	// Not due yet — force it.
	quiet.Check(ctx, after)

	settled, _ := st.GetCTMonitor(ctx, monitor.ID)
	if settled.LastSuccessAt == nil {
		t.Error("a check that answered did not move last_success_at")
	}
	if settled.LastError != "" {
		t.Errorf("a successful check left an error behind: %q", settled.LastError)
	}
}

// A certificate CertPilot issued must not be reported as one nobody manages.
func TestOwnCertificatesAreRecognised(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	if err := st.CreateCertificate(ctx, &store.Certificate{
		CommonName: "api.example.com", SerialNumber: "624d0ab311558780b7d5213b9631831", Status: "ISSUED",
	}); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	monitor := &store.CTMonitor{Domain: "example.com", IsEnabled: true, CheckIntervalMinutes: 360}
	if err := st.CreateCTMonitor(ctx, monitor); err != nil {
		t.Fatalf("CreateCTMonitor: %v", err)
	}

	m := NewMonitor(st, WithSource(&stubSource{entries: []Entry{
		// Padded and upper-cased, the way a log index writes it.
		{ID: 1, SerialNumber: NormalizeSerial("0624D0AB311558780B7D5213B9631831"),
			CommonName: "api.example.com", IssuerDN: "CN=R11"},
		{ID: 2, SerialNumber: "aabbcc", CommonName: "shadow.example.com", IssuerDN: "CN=R11"},
	}}))
	m.CheckDue(ctx)

	certs, _, err := st.ListCTCertificates(ctx, store.CTCertificateFilter{MonitorID: monitor.ID})
	if err != nil {
		t.Fatalf("ListCTCertificates: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d records, want 2", len(certs))
	}

	byName := map[string]*store.CTCertificate{}
	for _, c := range certs {
		byName[c.CommonName] = c
	}
	if byName["api.example.com"].ManagementState != store.DiscoveryManaged {
		t.Error("a certificate CertPilot issued was reported as unmanaged")
	}
	if byName["api.example.com"].MatchedCertificateID == nil {
		t.Error("the managed record does not name the certificate it matched")
	}
	if byName["shadow.example.com"].ManagementState != store.DiscoveryUnmanaged {
		t.Error("a certificate nobody issued here was reported as managed")
	}

	after, _ := st.GetCTMonitor(ctx, monitor.ID)
	if after.UnmanagedSeen != 1 {
		t.Errorf("unmanaged_seen = %d, want 1", after.UnmanagedSeen)
	}
}

// Check windows overlap by design. An alert repeating the same certificate
// every six hours is how a channel gets muted — taking the CA expiry alerts
// sharing it along with it.
func TestARepeatedCheckReportsNothingNew(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	monitor := &store.CTMonitor{Domain: "example.com", IsEnabled: true, CheckIntervalMinutes: 360}
	if err := st.CreateCTMonitor(ctx, monitor); err != nil {
		t.Fatalf("CreateCTMonitor: %v", err)
	}

	source := &stubSource{entries: []Entry{
		{ID: 1, SerialNumber: "aabbcc", CommonName: "shadow.example.com"},
	}}
	m := NewMonitor(st, WithSource(source))

	m.Check(ctx, monitor)
	first, _ := st.GetCTMonitor(ctx, monitor.ID)
	if first.CertificatesSeen != 1 {
		t.Fatalf("first check recorded %d, want 1", first.CertificatesSeen)
	}

	// The same entry comes back, as it would if the source ignores the
	// watermark.
	m.Check(ctx, first)
	second, _ := st.GetCTMonitor(ctx, monitor.ID)
	if second.CertificatesSeen != 1 {
		t.Errorf("certificates_seen = %d after a repeat check, want 1", second.CertificatesSeen)
	}

	certs, total, _ := st.ListCTCertificates(ctx, store.CTCertificateFilter{MonitorID: monitor.ID})
	if total != 1 || len(certs) != 1 {
		t.Errorf("stored %d records for one certificate", total)
	}
}

// A precertificate and its final certificate are two log entries for one
// certificate. Counting both doubles every finding.
func TestPrecertificatesDoNotDoubleCount(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	monitor := &store.CTMonitor{Domain: "example.com", IsEnabled: true, CheckIntervalMinutes: 360}
	if err := st.CreateCTMonitor(ctx, monitor); err != nil {
		t.Fatalf("CreateCTMonitor: %v", err)
	}

	m := NewMonitor(st, WithSource(&stubSource{entries: []Entry{
		{ID: 1, SerialNumber: "aabbcc", CommonName: "shadow.example.com", IsPrecertificate: true},
		{ID: 2, SerialNumber: "aabbcc", CommonName: "shadow.example.com"},
	}}))
	m.Check(ctx, monitor)

	_, all, _ := st.ListCTCertificates(ctx, store.CTCertificateFilter{MonitorID: monitor.ID})
	if all != 2 {
		t.Errorf("both log entries should be stored, got %d", all)
	}

	// But one certificate counts once.
	_, deduped, _ := st.ListCTCertificates(ctx, store.CTCertificateFilter{
		MonitorID: monitor.ID, ExcludePrecertificates: true,
	})
	if deduped != 1 {
		t.Errorf("deduplicated count = %d, want 1", deduped)
	}
}

func TestValidateMonitor(t *testing.T) {
	cases := map[string]struct {
		monitor *store.CTMonitor
		wantErr string
	}{
		"a domain":         {&store.CTMonitor{Domain: "example.com", CheckIntervalMinutes: 360}, ""},
		"upper case":       {&store.CTMonitor{Domain: "Example.COM", CheckIntervalMinutes: 360}, ""},
		"a URL":            {&store.CTMonitor{Domain: "https://example.com", CheckIntervalMinutes: 360}, "not a domain"},
		"a wildcard":       {&store.CTMonitor{Domain: "*.example.com", CheckIntervalMinutes: 360}, "include_subdomains"},
		"not a domain":     {&store.CTMonitor{Domain: "localhost", CheckIntervalMinutes: 360}, "does not look like"},
		"empty":            {&store.CTMonitor{CheckIntervalMinutes: 360}, "needs a domain"},
		"polling too hard": {&store.CTMonitor{Domain: "example.com", CheckIntervalMinutes: 5}, "shortest check interval"},
	}
	for name, tc := range cases {
		err := ValidateMonitor(tc.monitor)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.wantErr != "" && err == nil:
			t.Errorf("%s: accepted, want an error mentioning %q", name, tc.wantErr)
		case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
			t.Errorf("%s: error = %q, want %q", name, err, tc.wantErr)
		}
	}

	// Normalised in place, so two monitors for the same domain collide.
	m := &store.CTMonitor{Domain: "  Example.COM ", CheckIntervalMinutes: 360}
	if err := ValidateMonitor(m); err != nil {
		t.Fatalf("ValidateMonitor: %v", err)
	}
	if m.Domain != "example.com" {
		t.Errorf("domain = %q, want it normalized", m.Domain)
	}
}

func TestMonitorLifecycleIsSafe(t *testing.T) {
	m := NewMonitor(store.NewMemoryStore(), WithSource(&stubSource{}))
	m.Stop()
	m.Stop()

	running := NewMonitor(store.NewMemoryStore(), WithSource(&stubSource{}), WithTick(10*time.Millisecond))
	running.Start()
	running.Start()
	time.Sleep(30 * time.Millisecond)
	running.Stop()
	running.Stop()
}

// ── helpers ─────────────────────────────────────────────

type stubSource struct {
	entries []Entry
	err     error
}

func (s *stubSource) Name() string { return "stub" }

func (s *stubSource) Search(_ context.Context, _ string, _ bool, _ *int64) ([]Entry, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.entries, nil
}

func crtShServer(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// A failing service's error has to be readable where it lands: a dashboard
// field, a Slack message. A gateway error page is several lines of markup, and
// pasting that buries the one fact that matters — that the check did not
// happen.
func TestErrorsFromTheIndexAreReadable(t *testing.T) {
	srv := crtShServer(t, http.StatusBadGateway,
		"<html>\n<head><title>502 Bad Gateway</title></head>\n<body>\n<center><h1>502 Bad Gateway</h1></center>\n<hr><center>nginx</center>\n</body>\n</html>")

	_, err := NewCrtSh(WithBaseURL(srv)).Search(context.Background(), "example.com", true, nil)
	if err == nil {
		t.Fatal("a 502 was not reported as an error")
	}
	msg := err.Error()
	if strings.Contains(msg, "<") || strings.Contains(msg, "\n") {
		t.Errorf("the error carries raw markup:\n%s", msg)
	}
	if !strings.Contains(msg, "502") {
		t.Errorf("the error does not say what the service answered: %s", msg)
	}
	if !strings.Contains(msg, "crt.sh") {
		t.Errorf("the error does not attribute the failure: %s", msg)
	}
}

// crt.sh returns a precertificate and its final certificate as two rows, and
// publishes no field saying which is which. Left unlabelled the counts double:
// a live check of badssl.com reported eighteen certificates where there are
// nine, and a headline number wrong by a factor of two is one people act on.
func TestPrecertificatePairsAreLabelled(t *testing.T) {
	// Shaped like the real response: two rows per certificate, sharing a
	// serial, the pre-issuance one logged first and so carrying the lower id.
	srv := crtShServer(t, http.StatusOK, `[
	  {"id": 902, "common_name": "*.badssl.com", "name_value": "*.badssl.com",
	   "serial_number": "0aaa", "issuer_name": "CN=YE1"},
	  {"id": 901, "common_name": "*.badssl.com", "name_value": "*.badssl.com",
	   "serial_number": "0aaa", "issuer_name": "CN=YE1"},
	  {"id": 800, "common_name": "revoked.badssl.com", "name_value": "revoked.badssl.com",
	   "serial_number": "0bbb", "issuer_name": "CN=YE1"}
	]`)

	entries, err := NewCrtSh(WithBaseURL(srv)).Search(context.Background(), "badssl.com", true, nil)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want all 3 log entries kept", len(entries))
	}

	byID := map[int64]Entry{}
	for _, e := range entries {
		byID[e.ID] = e
	}
	if byID[901].IsPrecertificate != true {
		t.Error("the earlier entry of a pair is not labelled as the precertificate")
	}
	if byID[902].IsPrecertificate != false {
		t.Error("the newer entry of a pair was labelled as a precertificate")
	}
	// A certificate with only one entry is not a precertificate.
	if byID[800].IsPrecertificate != false {
		t.Error("a certificate with a single log entry was labelled a precertificate")
	}
}

// And the labelling has to translate into the count somebody reads.
func TestFindingsAreCountedOncePerCertificate(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	monitor := &store.CTMonitor{Domain: "badssl.com", IsEnabled: true, CheckIntervalMinutes: 360}
	if err := st.CreateCTMonitor(ctx, monitor); err != nil {
		t.Fatalf("CreateCTMonitor: %v", err)
	}

	entries := []Entry{
		{ID: 902, SerialNumber: "0aaa", CommonName: "*.badssl.com"},
		{ID: 901, SerialNumber: "0aaa", CommonName: "*.badssl.com"},
		{ID: 800, SerialNumber: "0bbb", CommonName: "revoked.badssl.com"},
	}
	markPrecertificates(entries)

	NewMonitor(st, WithSource(&stubSource{entries: entries})).Check(ctx, monitor)

	_, all, _ := st.ListCTCertificates(ctx, store.CTCertificateFilter{MonitorID: monitor.ID})
	if all != 3 {
		t.Errorf("stored %d log entries, want all 3 — each is a real record", all)
	}

	_, distinct, _ := st.ListCTCertificates(ctx, store.CTCertificateFilter{
		MonitorID: monitor.ID, ExcludePrecertificates: true,
	})
	if distinct != 2 {
		t.Errorf("counted %d certificates, want 2", distinct)
	}
}
