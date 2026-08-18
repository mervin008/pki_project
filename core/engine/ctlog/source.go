// Package ctlog watches Certificate Transparency for certificates issued in
// your name.
//
// This is the half of discovery that network scanning cannot reach. A scan
// answers "what is being served on the addresses I told you about". CT answers
// "what has been issued for our domains at all" — by any CA, to anyone, whether
// or not it was ever deployed and whether or not the machine is reachable from
// here. A developer who obtained a certificate for api.corp.example.com with a
// personal ACME account appears in no scan of any range, and appears in CT
// within minutes, because every publicly-trusted CA is required to log there
// and browsers reject certificates that are not.
package ctlog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Entry is one certificate a log reported.
type Entry struct {
	// ID identifies the entry in the source's index, and is what makes a
	// re-check idempotent.
	ID           int64
	LoggedAt     time.Time
	SerialNumber string
	IssuerDN     string
	CommonName   string
	SANs         []string
	NotBefore    time.Time
	NotAfter     time.Time
	// IsPrecertificate marks the pre-issuance entry. A precertificate and its
	// final certificate are two entries for one certificate, and counting both
	// doubles every finding.
	IsPrecertificate bool
}

// Source is where CT data is read from.
//
// An interface because the ecosystem has no single answer. Reading the logs
// directly is not viable — it means downloading every certificate ever issued —
// so everyone queries an index, and which index is a deployment decision rather
// than a design one.
type Source interface {
	// Name identifies the source in errors and on screen, so "we found nothing"
	// can be attributed to something.
	Name() string
	// Search returns entries for a domain, newest first. `sinceID` is the
	// newest entry already seen; a source that cannot filter by it returns
	// everything and lets the caller discard.
	Search(ctx context.Context, domain string, includeSubdomains bool, sinceID *int64) ([]Entry, error)
}

// crtShURL is the default index. Free, unauthenticated, and run as a community
// service by Sectigo — which is precisely why the poll interval has a floor and
// the client identifies itself.
const crtShURL = "https://crt.sh"

// CrtSh reads the crt.sh index.
type CrtSh struct {
	baseURL string
	client  *http.Client
	// maxEntries bounds one response. A domain with years of history returns
	// tens of thousands of rows, and the first check of a busy domain should
	// not try to hold all of them in memory to report them as findings nobody
	// asked for.
	maxEntries int
}

// NewCrtSh creates a source pointed at crt.sh.
func NewCrtSh(opts ...CrtShOption) *CrtSh {
	s := &CrtSh{
		baseURL: crtShURL,
		client: &http.Client{
			// Generous: crt.sh is a shared service and a slow answer is far
			// more common than no answer. Still bounded, because a monitor that
			// hangs is a monitor that silently stops watching.
			Timeout: 60 * time.Second,
		},
		maxEntries: 1000,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// CrtShOption configures the source.
type CrtShOption func(*CrtSh)

// WithBaseURL points the source elsewhere — a mirror, or a test server.
func WithBaseURL(u string) CrtShOption {
	return func(s *CrtSh) {
		if u != "" {
			s.baseURL = strings.TrimRight(u, "/")
		}
	}
}

// WithHTTPClient replaces the client.
func WithHTTPClient(c *http.Client) CrtShOption {
	return func(s *CrtSh) {
		if c != nil {
			s.client = c
		}
	}
}

// WithMaxEntries bounds one response.
func WithMaxEntries(n int) CrtShOption {
	return func(s *CrtSh) {
		if n > 0 {
			s.maxEntries = n
		}
	}
}

// Name identifies the source.
func (s *CrtSh) Name() string { return "crt.sh" }

// crtShEntry is one row of the crt.sh JSON output.
type crtShEntry struct {
	ID             int64  `json:"id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
	ResultCount    int    `json:"result_count"`
}

// Search queries the index for one domain.
func (s *CrtSh) Search(ctx context.Context, domain string, includeSubdomains bool, sinceID *int64) ([]Entry, error) {
	query := domain
	if includeSubdomains {
		// crt.sh uses SQL LIKE semantics, so % is the wildcard. Matching
		// "%.example.com" alone would miss the apex, which is usually the one
		// certificate everybody assumed was covered.
		query = "%." + domain
	}

	endpoint := fmt.Sprintf("%s/?q=%s&output=json&exclude=expired",
		s.baseURL, url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	// Identifies the caller, because this is somebody else's free service and
	// an unattributed poller is one they are right to block.
	req.Header.Set("User-Agent", "CertPilot/ct-monitor (+https://github.com/certpilot/certpilot)")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		// A deadline the caller set is reported as the deadline, not as a
		// transport error. "crt.sh did not answer in time" is actionable — wait
		// and retry, or widen the budget — and `context deadline exceeded` is
		// not.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s did not answer within the time allowed; the domain was not checked", s.Name())
		}
		return nil, fmt.Errorf("querying %s: %w", s.Name(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("%s answered %d: %s", s.Name(), resp.StatusCode, readableError(string(body)))
	}

	var rows []crtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		// A decode failure is reported rather than swallowed into an empty
		// result: "the index changed shape" and "this domain has no
		// certificates" are opposite conclusions.
		return nil, fmt.Errorf("%s returned something that is not the expected JSON: %w", s.Name(), err)
	}

	entries := make([]Entry, 0, len(rows))
	for _, row := range rows {
		if sinceID != nil && row.ID <= *sinceID {
			continue
		}
		entries = append(entries, entryFromCrtSh(row))
		if len(entries) >= s.maxEntries {
			break
		}
	}
	markPrecertificates(entries)
	return entries, nil
}

// markPrecertificates labels the pre-issuance entries.
//
// The index publishes no field saying which is which, so this is inferred from
// the one signal that is reliable: a precertificate and its final certificate
// carry the **same serial number**, and the precertificate is logged first.
// Every entry for a serial except the newest is therefore the pre-issuance one.
//
// Without this the counts are doubled. A live check of badssl.com reported
// eighteen certificates where there are nine, and a headline number that is
// wrong by a factor of two is worse than no headline number — it is one people
// act on.
func markPrecertificates(entries []Entry) {
	newest := make(map[string]int64, len(entries))
	for _, e := range entries {
		if e.SerialNumber == "" {
			continue
		}
		if id, seen := newest[e.SerialNumber]; !seen || e.ID > id {
			newest[e.SerialNumber] = e.ID
		}
	}
	for i := range entries {
		if entries[i].SerialNumber == "" {
			continue
		}
		entries[i].IsPrecertificate = entries[i].ID != newest[entries[i].SerialNumber]
	}
}

func entryFromCrtSh(row crtShEntry) Entry {
	names := make([]string, 0, 4)
	seen := map[string]bool{}
	for _, n := range strings.Split(row.NameValue, "\n") {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
	}

	return Entry{
		ID:           row.ID,
		LoggedAt:     parseCrtShTime(row.EntryTimestamp),
		SerialNumber: NormalizeSerial(row.SerialNumber),
		IssuerDN:     row.IssuerName,
		CommonName:   row.CommonName,
		SANs:         names,
		NotBefore:    parseCrtShTime(row.NotBefore),
		NotAfter:     parseCrtShTime(row.NotAfter),
	}
}

// parseCrtShTime reads the several shapes crt.sh emits. An unparseable time
// yields the zero value rather than an error: a certificate whose timestamp did
// not parse is still a certificate somebody issued for your domain.
func parseCrtShTime(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// NormalizeSerial puts a serial number in the one form both sides can compare.
//
// CertPilot stores serials as lowercase hex without padding (big.Int.Text(16));
// log indexes pad them and vary in case. Comparing the raw strings silently
// fails to match a certificate this system issued itself, which would report
// your own certificate as one nobody manages — the exact false positive that
// makes a findings list get ignored.
func NormalizeSerial(serial string) string {
	serial = strings.ToLower(strings.TrimSpace(serial))
	serial = strings.ReplaceAll(serial, ":", "")
	serial = strings.TrimPrefix(serial, "0x")
	serial = strings.TrimLeft(serial, "0")
	if serial == "" {
		return "0"
	}
	// Confirm it is hex at all; anything else is returned as-is so a match on
	// an unexpected format is still possible.
	if _, err := strconv.ParseUint(serial[:min(len(serial), 16)], 16, 64); err != nil {
		return serial
	}
	return serial
}

// readableError turns whatever a failing service returned into one line.
//
// A gateway error page is several lines of HTML, and pasting it into a Slack
// message or a dashboard field buries the one fact that matters — that the
// check did not happen — under markup nobody can read.
func readableError(body string) string {
	if strings.Contains(body, "<") {
		var out strings.Builder
		inTag := false
		for _, r := range body {
			switch {
			case r == '<':
				inTag = true
			case r == '>':
				inTag = false
				out.WriteRune(' ')
			case !inTag:
				out.WriteRune(r)
			}
		}
		body = out.String()
	}
	body = strings.Join(strings.Fields(body), " ")
	if body == "" {
		return "no detail given"
	}
	if len(body) > 160 {
		return body[:160] + "…"
	}
	return body
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
