package store

import (
	"context"
	"testing"
	"time"
)

func ptrInt(v int) *int { return &v }

// The rule the whole feature turns on. Acknowledging a CA at 30 days is an
// answer to a different question from the one asked at 7: the situation has
// materially worsened, and treating the earlier "yes, we know" as still valid is
// how an acknowledged CA expires with nobody paged.
func TestAnAcknowledgementDoesNotCoverATighterThreshold(t *testing.T) {
	now := time.Now()
	ack := &AlertAcknowledgement{Threshold: ptrInt(30), AcknowledgedAt: now}

	cases := map[string]struct {
		current *int
		want    bool
	}{
		"the same threshold":  {ptrInt(30), true},
		"a wider threshold":   {ptrInt(90), true},
		"a tighter threshold": {ptrInt(7), false},
		"one day tighter":     {ptrInt(29), false},
		"no threshold given":  {nil, true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := ack.IsActive(now, tc.current); got != tc.want {
				t.Errorf("IsActive(%v) = %v, want %v", tc.current, got, tc.want)
			}
		})
	}
}

// Acknowledging is not silencing. The common case is "yes, we have seen it" —
// the alert stops being new, and still goes out.
func TestAcknowledgingDoesNotSilenceByDefault(t *testing.T) {
	now := time.Now()

	seen := &AlertAcknowledgement{Threshold: ptrInt(14), AcknowledgedAt: now}
	if !seen.IsActive(now, ptrInt(14)) {
		t.Error("an acknowledgement without a silence should still be active")
	}
	if seen.SuppressesDelivery(now, ptrInt(14)) {
		t.Error("acknowledging with no silence_until suppressed delivery")
	}

	until := now.Add(24 * time.Hour)
	silenced := &AlertAcknowledgement{Threshold: ptrInt(14), AcknowledgedAt: now, SilenceUntil: &until}
	if !silenced.SuppressesDelivery(now, ptrInt(14)) {
		t.Error("an explicit silence did not suppress delivery")
	}
	// And it must not silence the tighter alert either.
	if silenced.SuppressesDelivery(now, ptrInt(7)) {
		t.Error("a silence granted at 14 days suppressed the 7-day alert")
	}
}

func TestASilenceExpires(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Minute)

	ack := &AlertAcknowledgement{Threshold: ptrInt(14), AcknowledgedAt: now, SilenceUntil: &past}
	if ack.SuppressesDelivery(now, ptrInt(14)) {
		t.Error("an expired silence still suppressed delivery")
	}
	// Still acknowledged, though: the record that a human looked does not
	// expire just because the quiet period did.
	if !ack.IsActive(now, ptrInt(14)) {
		t.Error("an acknowledgement stopped being active when its silence lapsed")
	}
}

func TestARevokedAcknowledgementCoversNothing(t *testing.T) {
	now := time.Now()
	until := now.Add(time.Hour)
	revoked := now.Add(-time.Minute)

	ack := &AlertAcknowledgement{
		Threshold: ptrInt(14), AcknowledgedAt: now,
		SilenceUntil: &until, RevokedAt: &revoked,
	}
	if ack.IsActive(now, ptrInt(14)) {
		t.Error("a revoked acknowledgement is still active")
	}
	if ack.SuppressesDelivery(now, ptrInt(14)) {
		t.Error("a revoked acknowledgement still suppresses delivery")
	}
}

// A nil acknowledgement is the normal "nobody has looked at this" case, and the
// methods have to answer it rather than panic — every caller reads the result of
// a lookup that usually finds nothing.
func TestNilAcknowledgementIsSafeAndInactive(t *testing.T) {
	var ack *AlertAcknowledgement
	if ack.IsActive(time.Now(), ptrInt(7)) {
		t.Error("a nil acknowledgement reported itself active")
	}
	if ack.SuppressesDelivery(time.Now(), ptrInt(7)) {
		t.Error("a nil acknowledgement suppressed delivery")
	}
}

func TestAcknowledgementStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	if got, err := s.GetActiveAcknowledgement(ctx, AckEntityCAAuthority, "ca-1"); err != nil || got != nil {
		t.Fatalf("unacknowledged entity returned (%v, %v), want (nil, nil)", got, err)
	}

	first := &AlertAcknowledgement{
		EntityType: AckEntityCAAuthority, EntityID: "ca-1",
		Threshold: ptrInt(30), Note: "replacement ordered",
	}
	if err := s.CreateAcknowledgement(ctx, first); err != nil {
		t.Fatalf("CreateAcknowledgement: %v", err)
	}
	if first.ID == "" || first.AcknowledgedAt.IsZero() {
		t.Fatalf("the store did not populate the record: %+v", first)
	}

	// A second acknowledgement supersedes the first for "current", but must not
	// erase it: who acknowledged what and when is what a review reads.
	second := &AlertAcknowledgement{
		EntityType: AckEntityCAAuthority, EntityID: "ca-1",
		Threshold: ptrInt(7), Note: "cutover Thursday",
	}
	if err := s.CreateAcknowledgement(ctx, second); err != nil {
		t.Fatalf("CreateAcknowledgement: %v", err)
	}

	active, err := s.GetActiveAcknowledgement(ctx, AckEntityCAAuthority, "ca-1")
	if err != nil {
		t.Fatalf("GetActiveAcknowledgement: %v", err)
	}
	if active.Note != "cutover Thursday" {
		t.Errorf("active note = %q, want the newest", active.Note)
	}

	history, err := s.ListAcknowledgements(ctx, AckEntityCAAuthority, "ca-1")
	if err != nil {
		t.Fatalf("ListAcknowledgements: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("history has %d entries, want 2 — an acknowledgement must never be overwritten", len(history))
	}
	if history[0].Note != "cutover Thursday" {
		t.Errorf("history is not newest-first: %q", history[0].Note)
	}
}

// The store hands out copies. Returning the live records is the defect
// ListAuditLogs shipped with — a caller holding them races every later write,
// and here the caller is the dispatcher running concurrently with an operator.
func TestAcknowledgementReadsReturnCopies(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	ack := &AlertAcknowledgement{
		EntityType: AckEntityCAAuthority, EntityID: "ca-1",
		Threshold: ptrInt(30), Note: "original",
	}
	if err := s.CreateAcknowledgement(ctx, ack); err != nil {
		t.Fatalf("CreateAcknowledgement: %v", err)
	}

	got, _ := s.GetActiveAcknowledgement(ctx, AckEntityCAAuthority, "ca-1")
	got.Note = "mutated by a caller"

	again, _ := s.GetActiveAcknowledgement(ctx, AckEntityCAAuthority, "ca-1")
	if again.Note != "original" {
		t.Errorf("a caller mutated the stored record through the returned pointer: %q", again.Note)
	}
}

func TestRevokingAnAcknowledgementKeepsTheRecord(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	ack := &AlertAcknowledgement{
		EntityType: AckEntityCAAuthority, EntityID: "ca-1", Note: "acknowledged in error",
	}
	if err := s.CreateAcknowledgement(ctx, ack); err != nil {
		t.Fatalf("CreateAcknowledgement: %v", err)
	}

	who := "alice"
	if err := s.RevokeAcknowledgement(ctx, ack.ID, &who); err != nil {
		t.Fatalf("RevokeAcknowledgement: %v", err)
	}

	active, _ := s.GetActiveAcknowledgement(ctx, AckEntityCAAuthority, "ca-1")
	if active != nil {
		t.Error("a revoked acknowledgement is still returned as active")
	}

	history, _ := s.ListAcknowledgements(ctx, AckEntityCAAuthority, "ca-1")
	if len(history) != 1 || history[0].RevokedAt == nil {
		t.Fatalf("the withdrawal did not survive as a record: %+v", history)
	}

	// Revoking twice keeps the first withdrawal's time and actor — who first
	// pulled it is what a review needs.
	firstRevoked := *history[0].RevokedAt
	bob := "bob"
	if err := s.RevokeAcknowledgement(ctx, ack.ID, &bob); err != nil {
		t.Fatalf("second RevokeAcknowledgement: %v", err)
	}
	history, _ = s.ListAcknowledgements(ctx, AckEntityCAAuthority, "ca-1")
	if !history[0].RevokedAt.Equal(firstRevoked) || *history[0].RevokedBy != "alice" {
		t.Errorf("the second revocation overwrote the first: %+v", history[0])
	}
}

func TestBulkAcknowledgementLookup(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	for _, id := range []string{"ca-1", "ca-2"} {
		if err := s.CreateAcknowledgement(ctx, &AlertAcknowledgement{
			EntityType: AckEntityCAAuthority, EntityID: id, Note: "seen " + id,
		}); err != nil {
			t.Fatalf("CreateAcknowledgement: %v", err)
		}
	}
	// A certificate acknowledgement with the same id must not leak across.
	if err := s.CreateAcknowledgement(ctx, &AlertAcknowledgement{
		EntityType: AckEntityCertificate, EntityID: "ca-3", Note: "wrong type",
	}); err != nil {
		t.Fatalf("CreateAcknowledgement: %v", err)
	}

	got, err := s.GetActiveAcknowledgements(ctx, AckEntityCAAuthority, []string{"ca-1", "ca-2", "ca-3"})
	if err != nil {
		t.Fatalf("GetActiveAcknowledgements: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("resolved %d acknowledgements, want 2: %+v", len(got), got)
	}
	if got["ca-1"].Note != "seen ca-1" || got["ca-2"].Note != "seen ca-2" {
		t.Errorf("entities were mixed up: %+v", got)
	}
	if _, leaked := got["ca-3"]; leaked {
		t.Error("a certificate acknowledgement leaked into a CA lookup")
	}

	if empty, err := s.GetActiveAcknowledgements(ctx, AckEntityCAAuthority, nil); err != nil || len(empty) != 0 {
		t.Errorf("empty lookup returned (%v, %v)", empty, err)
	}
}

func TestCreateAcknowledgementRejectsNonsense(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	if err := s.CreateAcknowledgement(ctx, &AlertAcknowledgement{
		EntityType: "gateway", EntityID: "gw-1",
	}); err == nil {
		t.Error("an unknown entity type was accepted")
	}
	if err := s.CreateAcknowledgement(ctx, &AlertAcknowledgement{
		EntityType: AckEntityCAAuthority,
	}); err == nil {
		t.Error("an acknowledgement with no entity id was accepted")
	}
}
