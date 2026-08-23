package ctlog

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

const (
	// tickInterval is how often due monitors are looked for. Checks are
	// measured in hours, so a minute's granularity is ample.
	tickInterval = 1 * time.Minute
	// MinCheckIntervalMinutes is the shortest permitted check interval.
	//
	// Higher than a network scan's floor, and for a different reason: the logs
	// are read through a free service somebody else pays for. Polling it every
	// few minutes per domain is how an organisation loses access to it, and
	// then finds out nothing at all.
	MinCheckIntervalMinutes = 60
	// checkTimeout bounds one domain's query.
	checkTimeout = 90 * time.Second
)

// Monitor polls Certificate Transparency for the domains being watched.
type Monitor struct {
	store  store.Store
	source Source
	broker *events.Broker
	tick   time.Duration
	now    func() time.Time

	mu      sync.Mutex
	started bool
	stopCh  chan struct{}
	stopped sync.Once
	wg      sync.WaitGroup
}

// Option configures a Monitor.
type Option func(*Monitor)

// WithBroker publishes findings to the event stream and the alert channels.
func WithBroker(b *events.Broker) Option {
	return func(m *Monitor) { m.broker = b }
}

// WithSource replaces where CT data is read from.
func WithSource(s Source) Option {
	return func(m *Monitor) {
		if s != nil {
			m.source = s
		}
	}
}

// WithTick sets how often due monitors are looked for.
func WithTick(d time.Duration) Option {
	return func(m *Monitor) {
		if d > 0 {
			m.tick = d
		}
	}
}

// NewMonitor creates a monitor.
func NewMonitor(s store.Store, opts ...Option) *Monitor {
	m := &Monitor{
		store:  s,
		source: NewCrtSh(),
		tick:   tickInterval,
		now:    time.Now,
		stopCh: make(chan struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Start begins the loop.
func (m *Monitor) Start() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()

	m.wg.Add(1)
	go m.run()

	slog.Info("certificate transparency monitor started", "source", m.source.Name(), "tick", m.tick)
}

// Stop ends the loop. Safe to call twice, and on one that never started.
func (m *Monitor) Stop() {
	if m == nil {
		return
	}
	m.stopped.Do(func() { close(m.stopCh) })
	m.wg.Wait()
}

func (m *Monitor) run() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.tick)
	defer ticker.Stop()

	m.CheckDue(context.Background())
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.CheckDue(context.Background())
		}
	}
}

// CheckDue polls every monitor that is due. Exported so a test can drive it
// without waiting on a ticker.
func (m *Monitor) CheckDue(ctx context.Context) {
	now := m.now()

	monitors, err := m.store.GetDueCTMonitors(ctx, now)
	if err != nil {
		slog.Error("could not read certificate transparency monitors; nothing is being watched", "error", err)
		return
	}

	// One domain at a time, deliberately. The index is a shared service, and a
	// burst of parallel queries from one deployment is what gets an IP blocked.
	for _, monitor := range monitors {
		select {
		case <-m.stopCh:
			return
		default:
		}
		m.Check(ctx, monitor)
	}
}

// Check polls one domain and records what came back.
func (m *Monitor) Check(ctx context.Context, monitor *store.CTMonitor) {
	now := m.now()
	next := now.Add(time.Duration(monitor.CheckIntervalMinutes) * time.Minute)

	queryCtx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()

	entries, err := m.source.Search(queryCtx, monitor.Domain, monitor.IncludeSubdomains, monitor.LastEntryID)
	if err != nil {
		// Recorded as a failed *attempt*: last_checked_at moves, last_success_at
		// does not. This is the whole reason those are two columns — a monitor
		// that cannot reach the log must never read as one that is finding
		// nothing.
		slog.Warn("a certificate transparency check failed; this domain was not looked at",
			"domain", monitor.Domain, "source", m.source.Name(), "error", err)
		if markErr := m.store.MarkCTMonitorChecked(ctx, monitor.ID, now, next, false, nil, 0, 0, err.Error()); markErr != nil {
			slog.Error("could not record a failed CT check", "domain", monitor.Domain, "error", markErr)
		}
		return
	}

	found, newest := m.classify(ctx, monitor, entries)

	added, err := m.store.RecordCTCertificates(ctx, found)
	if err != nil {
		slog.Error("certificate transparency results could not be stored",
			"domain", monitor.Domain, "error", err)
		if markErr := m.store.MarkCTMonitorChecked(ctx, monitor.ID, now, next, false, nil, 0, 0, err.Error()); markErr != nil {
			slog.Error("could not record a failed CT check", "domain", monitor.Domain, "error", markErr)
		}
		return
	}

	// Counted per certificate, not per log entry. A precertificate and its
	// final certificate are two entries for one certificate, and a running
	// total that counted both would report twice as many findings as exist —
	// a headline number wrong by a factor of two is one people act on.
	certificates, unmanaged := 0, 0
	for _, c := range added {
		if c.IsPrecertificate {
			continue
		}
		certificates++
		if c.ManagementState == store.DiscoveryUnmanaged {
			unmanaged++
		}
	}

	if err := m.store.MarkCTMonitorChecked(ctx, monitor.ID, now, next, true, newest, certificates, unmanaged, ""); err != nil {
		slog.Error("a CT check succeeded but the monitor could not be updated",
			"domain", monitor.Domain, "error", err)
	}

	slog.Info("certificate transparency check complete",
		"domain", monitor.Domain, "entries", len(added), "certificates", certificates, "unmanaged", unmanaged)

	m.announce(monitor, added, unmanaged)
}

// classify turns log entries into records, deciding for each whether CertPilot
// already knows about it.
//
// Matched on serial number. The log index does not publish a SHA-256
// fingerprint, and (issuer, serial) identifies a certificate uniquely — but the
// two sides format serials differently, which is why NormalizeSerial exists. A
// mismatch there would report this system's own certificates as ones nobody
// manages, and a findings list full of your own certificates is one nobody
// reads.
func (m *Monitor) classify(ctx context.Context, monitor *store.CTMonitor, entries []Entry) ([]*store.CTCertificate, *int64) {
	found := make([]*store.CTCertificate, 0, len(entries))
	var newest *int64

	// Loaded once for the batch rather than queried per entry: a first check of
	// a busy domain returns hundreds of rows.
	managed := m.managedSerials(ctx)

	for _, entry := range entries {
		if newest == nil || entry.ID > *newest {
			id := entry.ID
			newest = &id
		}

		record := &store.CTCertificate{
			MonitorID:        monitor.ID,
			SerialNumber:     entry.SerialNumber,
			IssuerDN:         entry.IssuerDN,
			CommonName:       entry.CommonName,
			SANs:             entry.SANs,
			IsPrecertificate: entry.IsPrecertificate,
			ManagementState:  store.DiscoveryUnmanaged,
		}
		if entry.ID != 0 {
			id := entry.ID
			record.EntryID = &id
		}
		if !entry.LoggedAt.IsZero() {
			t := entry.LoggedAt
			record.LoggedAt = &t
		}
		if !entry.NotBefore.IsZero() {
			t := entry.NotBefore
			record.NotBefore = &t
		}
		if !entry.NotAfter.IsZero() {
			t := entry.NotAfter
			record.NotAfter = &t
		}

		if certID, ok := managed[entry.SerialNumber]; ok && entry.SerialNumber != "" {
			record.ManagementState = store.DiscoveryManaged
			id := certID
			record.MatchedCertificateID = &id
		}

		found = append(found, record)
	}

	return found, newest
}

// managedSerials maps normalized serial numbers to certificate ids.
//
// A lookup failure yields an empty map, so everything reads as unmanaged. That
// overstates the problem, which is the safe direction: reporting a certificate
// as managed when the check failed is how an unknown certificate gets filed as
// somebody's routine renewal.
func (m *Monitor) managedSerials(ctx context.Context) map[string]string {
	serials := map[string]string{}

	certs, _, err := m.store.ListCertificates(ctx, store.CertificateFilter{Limit: 10000})
	if err != nil {
		slog.Warn("could not read inventory to match CT findings; they will all read as unmanaged", "error", err)
		return serials
	}
	for _, cert := range certs {
		if cert.SerialNumber == "" {
			continue
		}
		serials[NormalizeSerial(cert.SerialNumber)] = cert.ID
	}
	return serials
}

// announce publishes what the check found.
//
// Only the certificates that were *new* to this monitor. The check windows
// overlap by design, and an alert repeating the same certificate every six
// hours is how a channel gets muted — taking the CA expiry alerts sharing it
// along too.
func (m *Monitor) announce(monitor *store.CTMonitor, added []*store.CTCertificate, unmanaged int) {
	if m.broker == nil || unmanaged == 0 {
		return
	}

	names := make([]string, 0, 10)
	for _, c := range added {
		if c.ManagementState != store.DiscoveryUnmanaged || c.IsPrecertificate {
			continue
		}
		name := c.CommonName
		if name == "" && len(c.SANs) > 0 {
			name = c.SANs[0]
		}
		names = append(names, fmt.Sprintf("%s (%s)", name, issuerShortName(c.IssuerDN)))
		if len(names) == 10 {
			break
		}
	}

	m.broker.Publish(events.Event{
		Topic:    events.TopicCTUnmanaged,
		Severity: events.SeverityWarning,
		EntityID: monitor.ID,
		Payload: map[string]any{
			"monitor_id":      monitor.ID,
			"domain":          monitor.Domain,
			"unmanaged_count": unmanaged,
			"new_count":       len(added),
			"certificates":    names,
			"source":          m.source.Name(),
		},
	})
}

// issuerShortName pulls the CA's common name out of a full issuer DN, because
// an alert naming "C=US, O=Let's Encrypt, CN=R11" reads worse than "R11".
func issuerShortName(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return strings.TrimSpace(part[3:])
		}
	}
	if dn == "" {
		return "unknown issuer"
	}
	return dn
}

// ValidateMonitor checks a monitor can run, before it is stored.
func ValidateMonitor(monitor *store.CTMonitor) error {
	domain := strings.TrimSpace(strings.ToLower(monitor.Domain))
	if domain == "" {
		return fmt.Errorf("a monitor needs a domain")
	}
	if strings.Contains(domain, "://") || strings.ContainsAny(domain, "/ \t") {
		return fmt.Errorf("%q is not a domain; give a name like example.com", monitor.Domain)
	}
	if strings.HasPrefix(domain, "*.") {
		return fmt.Errorf("give the domain itself (example.com); subdomains are covered by include_subdomains")
	}
	if !strings.Contains(domain, ".") {
		return fmt.Errorf("%q does not look like a domain", monitor.Domain)
	}
	if monitor.CheckIntervalMinutes < MinCheckIntervalMinutes {
		return fmt.Errorf(
			"the shortest check interval is %d minutes; the transparency index is a free service and polling it harder is how access to it is lost",
			MinCheckIntervalMinutes)
	}
	monitor.Domain = domain
	return nil
}
