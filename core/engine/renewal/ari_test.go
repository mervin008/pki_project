package renewal

import (
	"context"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/store"
)

// A window is advice about when, and the client is supposed to pick a random
// moment inside it. Renewing at the start would move the thundering herd rather
// than disperse it, which is the entire reason the CA sends a window instead of
// a time.
func TestSelectionIsSpreadAcrossTheWindow(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	start := now.Add(24 * time.Hour)
	end := start.Add(24 * time.Hour)

	seen := map[time.Time]bool{}
	for i := 0; i < 50; i++ {
		got := selectWithin(start, end, now)
		if got.Before(start) || !got.Before(end) {
			t.Fatalf("selected %s, outside the window %s..%s", got, start, end)
		}
		seen[got] = true
	}
	if len(seen) < 40 {
		t.Errorf("50 draws produced %d distinct times; every client would renew together", len(seen))
	}
}

// A window already underway must yield a time between now and its end, so a
// client that wakes up late does not sit out until the next one.
func TestAWindowAlreadyOpenSelectsFromNow(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	start := now.Add(-12 * time.Hour)
	end := now.Add(6 * time.Hour)

	for i := 0; i < 20; i++ {
		got := selectWithin(start, end, now)
		if got.Before(now) {
			t.Fatalf("selected %s, in the past", got)
		}
		if !got.Before(end) {
			t.Fatalf("selected %s, past the window end %s", got, end)
		}
	}
}

// A window whose end has passed means renew immediately. This is precisely what
// a CA does to certificates it is about to revoke.
func TestAClosedWindowMeansNow(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	got := selectWithin(now.Add(-48*time.Hour), now.Add(-24*time.Hour), now)
	if !got.Equal(now) {
		t.Errorf("selected %s for a window that closed yesterday, want now", got)
	}
}

// The alert must not fire on the ordinary re-draw. Two checks of an unchanged
// window differ by hours simply because a different point inside it was picked,
// and alerting on that would mute the one message that matters during an
// incident before the incident.
func TestARedrawInsideTheSameWindowIsNotAnAlert(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	windowEnd := now.Add(48 * time.Hour)
	previous := now.Add(40 * time.Hour)

	cert := &store.Certificate{
		RenewalScheduledAt: &previous,
		ARIWindowEnd:       &windowEnd,
	}

	// A new draw a few hours earlier inside the same window.
	if moved, _ := pulledForward(cert, now.Add(36*time.Hour)); moved {
		t.Error("a new random draw inside the same window was reported as the CA changing its mind")
	}
	// A draw later than before is never a pull-forward.
	if moved, _ := pulledForward(cert, now.Add(47*time.Hour)); moved {
		t.Error("a later renewal time was reported as being brought forward")
	}
}

// The case this whole feature exists for: a CA pulls the window into the past
// because it is about to revoke.
func TestAWindowPulledIntoThePastIsAnAlert(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	windowEnd := now.Add(30 * 24 * time.Hour)
	previous := now.Add(25 * 24 * time.Hour)

	cert := &store.Certificate{
		CommonName:         "shop.example.com",
		RenewalScheduledAt: &previous,
		ARIWindowEnd:       &windowEnd,
	}

	moved, by := pulledForward(cert, now)
	if !moved {
		t.Fatal("a renewal brought forward by 25 days was not reported")
	}
	if by < 24*24*time.Hour {
		t.Errorf("moved by %s, want roughly 25 days", by)
	}
}

// Nothing to compare against on the first check, so the first window a CA
// publishes is never an alert.
func TestTheFirstWindowIsNotAnAlert(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	if moved, _ := pulledForward(&store.Certificate{}, now); moved {
		t.Error("the first window a CA published was reported as a change of mind")
	}
}

// ── the sweep ───────────────────────────────────────────────

func certWithSchedule(t *testing.T, st store.Store, cn string, expiresIn time.Duration, renewAt *time.Time) *store.Certificate {
	t.Helper()
	notAfter := time.Now().Add(expiresIn)
	cert := &store.Certificate{
		CommonName: cn, FingerprintSHA256: "fp-" + cn, SerialNumber: "s-" + cn,
		NotAfter: &notAfter, DaysRemaining: int(expiresIn.Hours() / 24),
		Status: "ISSUED", AutoRenew: true, RenewalLeadDays: 30,
		RenewalScheduledAt: renewAt,
	}
	if err := st.CreateCertificate(context.Background(), cert); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return cert
}

func dueNames(t *testing.T, st store.Store, leadDays int) map[string]bool {
	t.Helper()
	due, err := st.GetCertificatesDueForRenewal(context.Background(), leadDays)
	if err != nil {
		t.Fatalf("GetCertificatesDueForRenewal: %v", err)
	}
	names := map[string]bool{}
	for _, c := range due {
		names[c.CommonName] = true
	}
	return names
}

// The CA's advice beats the lead time in both directions — it can bring a
// renewal forward, and it can hold one back.
func TestTheCAsAdviceOverridesTheLeadTime(t *testing.T) {
	st := store.NewMemoryStore()
	now := time.Now()

	// Not due on lead time — 60 days left against a 30-day lead — but the CA
	// says renew now.
	early := now.Add(-time.Hour)
	certWithSchedule(t, st, "ca-says-now.example.com", 60*24*time.Hour, &early)

	// Due on lead time — 20 days left — but the CA says wait, and there is
	// comfortably more than the safety floor left.
	later := now.Add(10 * 24 * time.Hour)
	certWithSchedule(t, st, "ca-says-wait.example.com", 20*24*time.Hour, &later)

	due := dueNames(t, st, 30)
	if !due["ca-says-now.example.com"] {
		t.Error("a certificate the CA asked to renew now was not queued")
	}
	if due["ca-says-wait.example.com"] {
		t.Error("a certificate the CA asked to hold was renewed anyway; the advice is being ignored")
	}
}

// But never off a cliff. Inside the safety floor the advice stops being able to
// defer anything — a bad window, or a stale one left by a poller that stopped
// running, must not talk this system out of renewing something about to expire.
func TestTheSafetyFloorOverridesTheCAsAdvice(t *testing.T) {
	st := store.NewMemoryStore()

	// The CA says wait a month. The certificate expires in three days.
	later := time.Now().Add(30 * 24 * time.Hour)
	certWithSchedule(t, st, "about-to-expire.example.com", 3*24*time.Hour, &later)

	if !dueNames(t, st, 30)["about-to-expire.example.com"] {
		t.Fatal("a certificate three days from expiry was deferred by the CA's advice")
	}
}

// With no advice at all, nothing changes: lead time still decides.
func TestWithoutAdviceLeadTimeStillDecides(t *testing.T) {
	st := store.NewMemoryStore()
	certWithSchedule(t, st, "due.example.com", 10*24*time.Hour, nil)
	certWithSchedule(t, st, "not-due.example.com", 200*24*time.Hour, nil)

	due := dueNames(t, st, 30)
	if !due["due.example.com"] {
		t.Error("a certificate inside the lead window was not queued")
	}
	if due["not-due.example.com"] {
		t.Error("a certificate with 200 days left was queued")
	}
}

// Only certificates that could act on the answer are asked about. Anything else
// spends somebody's rate limit to learn nothing.
func TestOnlyActionableCertificatesAreAskedAbout(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()
	now := time.Now()

	account := &store.CAAccount{Name: "acme", ProviderType: "acme", GatewayAddr: "x:1", Status: "CONNECTED"}
	if err := st.CreateCAAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	pem := "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----"
	notAfter := now.Add(60 * 24 * time.Hour)

	mk := func(cn string, autoRenew bool, acct *string, body *string) {
		cert := &store.Certificate{
			CommonName: cn, FingerprintSHA256: "fp-" + cn, NotAfter: &notAfter,
			Status: "ISSUED", AutoRenew: autoRenew, CAAccountID: acct, CertificatePEM: body,
		}
		if err := st.CreateCertificate(ctx, cert); err != nil {
			t.Fatal(err)
		}
	}
	mk("asked.example.com", true, &account.ID, &pem)
	mk("manual.example.com", false, &account.ID, &pem)
	mk("no-account.example.com", true, nil, &pem)
	mk("no-body.example.com", true, &account.ID, nil)

	certs, err := st.GetCertificatesDueForARICheck(ctx, now, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || certs[0].CommonName != "asked.example.com" {
		names := []string{}
		for _, c := range certs {
			names = append(names, c.CommonName)
		}
		t.Fatalf("asked about %v, want only the one that could act on the answer", names)
	}
}

// A certificate that has just been checked must not be checked again on the
// next pass. Polling harder than the CA asked is how a client loses access to
// the endpoint that would have warned it.
func TestRetryAfterIsRespected(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()
	now := time.Now()

	account := &store.CAAccount{Name: "acme", ProviderType: "acme", GatewayAddr: "x:1", Status: "CONNECTED"}
	_ = st.CreateCAAccount(ctx, account)
	pem := "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----"
	notAfter := now.Add(60 * 24 * time.Hour)
	cert := &store.Certificate{
		CommonName: "polled.example.com", FingerprintSHA256: "fp", NotAfter: &notAfter,
		Status: "ISSUED", AutoRenew: true, CAAccountID: &account.ID, CertificatePEM: &pem,
	}
	_ = st.CreateCertificate(ctx, cert)

	next := now.Add(6 * time.Hour)
	yes := true
	if err := st.UpdateCertificateRenewalInfo(ctx, cert.ID, store.RenewalInfoUpdate{
		CheckedAt: &now, NextCheckAt: &next, Supported: &yes,
	}); err != nil {
		t.Fatal(err)
	}

	if certs, _ := st.GetCertificatesDueForARICheck(ctx, now.Add(time.Hour), 100); len(certs) != 0 {
		t.Errorf("a certificate checked an hour ago was asked about again; the CA asked for 6 hours")
	}
	if certs, _ := st.GetCertificatesDueForARICheck(ctx, now.Add(7*time.Hour), 100); len(certs) != 1 {
		t.Error("a certificate whose Retry-After has elapsed was not asked about")
	}
}

// A CA that says nothing is not the same as one nobody has asked. The flag has
// to distinguish them, or a CA that has never been reached reads as one with
// nothing to say.
func TestUnsupportedIsDistinctFromUnasked(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()

	notAfter := time.Now().Add(60 * 24 * time.Hour)
	cert := &store.Certificate{CommonName: "x.example.com", FingerprintSHA256: "fp", NotAfter: &notAfter, Status: "ISSUED"}
	_ = st.CreateCertificate(ctx, cert)

	fresh, _ := st.GetCertificate(ctx, cert.ID)
	if fresh.ARISupported != nil {
		t.Error("a certificate nobody has asked about already claims to know whether its CA supports ARI")
	}

	no := false
	now := time.Now()
	if err := st.UpdateCertificateRenewalInfo(ctx, cert.ID, store.RenewalInfoUpdate{
		CheckedAt: &now, Supported: &no,
	}); err != nil {
		t.Fatal(err)
	}
	asked, _ := st.GetCertificate(ctx, cert.ID)
	if asked.ARISupported == nil || *asked.ARISupported {
		t.Error("a CA that was asked and publishes nothing was not recorded as such")
	}
	if asked.RenewalScheduledAt != nil {
		t.Error("a CA with no advice left a renewal schedule behind that nobody stands behind")
	}
}

func TestStoppingTheARIPollerTwiceIsSafe(t *testing.T) {
	p := NewARIPoller(store.NewMemoryStore(), nil, nil, nil, WithARITick(10*time.Millisecond))
	p.Start()
	p.Start()
	p.Stop()
	p.Stop()
}
