package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot/pkg/secrets"
)

func testChainer(t *testing.T) (*AuditChainer, *secrets.Keyring) {
	t.Helper()
	kr, err := secrets.NewEphemeralKeyring()
	if err != nil {
		t.Fatal(err)
	}
	return NewAuditChainer(kr), kr
}

func chainedMemoryStore(t *testing.T) *MemoryStore {
	t.Helper()
	m := NewMemoryStore()
	chainer, _ := testChainer(t)
	m.UseAuditChain(chainer)
	return m
}

func writeEntries(t *testing.T, m *MemoryStore, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := m.CreateAuditLog(context.Background(), &AuditLog{
			Action:     "certificate.issued",
			EntityType: "certificate",
			Details:    `{"cn":"example.test"}`,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAuditChainVerifiesCleanRecord(t *testing.T) {
	m := chainedMemoryStore(t)
	writeEntries(t, m, 5)

	report, err := m.VerifyAuditChain(context.Background(), 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Intact {
		t.Fatalf("a record nothing touched must verify: %s", report.Reason)
	}
	if report.Verified != 5 {
		t.Errorf("expected 5 verified entries, got %d", report.Verified)
	}
	if report.FirstSeq != 1 || report.LastSeq != 5 {
		t.Errorf("expected the walk to cover seq 1..5, got %d..%d", report.FirstSeq, report.LastSeq)
	}
}

// The store seeds one sample entry, which predates the chain. It must be
// counted rather than quietly skipped: an operator told the record is intact is
// entitled to know how much of it that covers.
func TestAuditChainReportsUnchainedEntries(t *testing.T) {
	m := chainedMemoryStore(t)
	writeEntries(t, m, 2)

	report, err := m.VerifyAuditChain(context.Background(), 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if report.Unchained == 0 {
		t.Error("entries written before the chain existed must be reported, not ignored")
	}
	if !report.Intact {
		t.Errorf("unchained history is not a break: %s", report.Reason)
	}
}

// The whole point. Editing a stored entry must be detectable.
func TestAuditChainDetectsAnAlteredEntry(t *testing.T) {
	m := chainedMemoryStore(t)
	writeEntries(t, m, 4)

	// Reach past the API and rewrite a row the way somebody with database
	// access would. auditLogs is newest-first, so index 1 is seq 3.
	m.auditLogs[1].Action = "certificate.renewed"

	report, err := m.VerifyAuditChain(context.Background(), 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if report.Intact {
		t.Fatal("an altered entry must not verify")
	}
	if report.BrokenAt == nil || *report.BrokenAt != 3 {
		t.Fatalf("expected the break at seq 3, got %v", report.BrokenAt)
	}
	if !strings.Contains(report.Reason, "altered") {
		t.Errorf("the reason must name the cause, got %q", report.Reason)
	}
}

// Deleting an entry is the likelier attack: nobody edits an audit record to say
// something else, they make it not be there. A gapless sequence is what turns
// that from invisible into obvious.
func TestAuditChainDetectsADeletedEntry(t *testing.T) {
	m := chainedMemoryStore(t)
	writeEntries(t, m, 4)

	// Drop seq 2, which is the second-oldest.
	m.auditLogs = append(m.auditLogs[:2], m.auditLogs[3:]...)

	report, err := m.VerifyAuditChain(context.Background(), 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if report.Intact {
		t.Fatal("a deleted entry must not leave the chain reading as intact")
	}
	if report.BrokenAt == nil || *report.BrokenAt != 2 {
		t.Fatalf("expected the break at the missing seq 2, got %v", report.BrokenAt)
	}
	if !strings.Contains(report.Reason, "deleted") {
		t.Errorf("the reason must say a record was deleted, got %q", report.Reason)
	}
}

// Recomputing the tag is not enough on its own: somebody holding the key could
// re-tag one edited entry in place. The link to the predecessor is what forces
// them to rewrite everything after it too.
func TestAuditChainDetectsARetaggedEntry(t *testing.T) {
	m := chainedMemoryStore(t)
	writeEntries(t, m, 4)

	target := m.auditLogs[2] // seq 2
	target.Action = "certificate.revoked"
	_, tag, err := m.auditChain.Link(target, target.PrevHash)
	if err != nil {
		t.Fatal(err)
	}
	target.EntryHash = tag

	report, err := m.VerifyAuditChain(context.Background(), 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if report.Intact {
		t.Fatal("re-tagging one entry must still break the link to the next")
	}
	if report.BrokenAt == nil || *report.BrokenAt != 3 {
		t.Fatalf("expected the break at seq 3, the entry that follows it, got %v", report.BrokenAt)
	}
}

// The key is what a database-only attacker does not have. Verifying under a
// different keyring must fail rather than quietly succeed.
func TestAuditChainRefusesAnUnknownKey(t *testing.T) {
	m := chainedMemoryStore(t)
	writeEntries(t, m, 2)

	other, _ := testChainer(t)
	m.auditChain = other

	report, err := m.VerifyAuditChain(context.Background(), 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if report.Intact {
		t.Fatal("a chain must not verify under a keyring that never wrote it")
	}
	if !strings.Contains(report.Reason, "cannot be checked") {
		t.Errorf("an unknown key is a different answer from a mismatch, got %q", report.Reason)
	}
}

// A tag computed today must still verify after CERTPILOT_KEK is rotated, or the
// system quietly punishes operators for rotating it.
func TestAuditChainSurvivesKeyRotation(t *testing.T) {
	m := NewMemoryStore()
	oldKEK := make([]byte, secrets.KEKSize)
	for i := range oldKEK {
		oldKEK[i] = byte(i + 1)
	}
	newKEK := make([]byte, secrets.KEKSize)
	for i := range newKEK {
		newKEK[i] = byte(200 - i)
	}

	before, err := secrets.NewKeyring(oldKEK)
	if err != nil {
		t.Fatal(err)
	}
	m.UseAuditChain(NewAuditChainer(before))
	writeEntries(t, m, 3)

	// The operator rotates: the new KEK seals new writes, the old one is
	// retired but kept for reading.
	after, err := secrets.NewKeyring(newKEK, oldKEK)
	if err != nil {
		t.Fatal(err)
	}
	m.UseAuditChain(NewAuditChainer(after))
	writeEntries(t, m, 2)

	report, err := m.VerifyAuditChain(context.Background(), 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Intact {
		t.Fatalf("a rotation must not invalidate history: %s", report.Reason)
	}
	if report.Verified != 5 {
		t.Errorf("expected all 5 entries verified across the rotation, got %d", report.Verified)
	}
}

// Without a key there is no proof, and the report must say so rather than
// return the shape of a passing answer.
func TestAuditChainWithoutAKeyIsNotIntact(t *testing.T) {
	m := NewMemoryStore()
	writeEntries(t, m, 2)

	report, err := m.VerifyAuditChain(context.Background(), 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if report.Intact {
		t.Fatal("no key means the question cannot be answered, which is not the same as yes")
	}
	if report.Unchained != 3 { // two written here plus the seeded sample
		t.Errorf("expected 3 unchained entries, got %d", report.Unchained)
	}
}

// A partial walk must not present itself as a whole-record guarantee.
func TestAuditChainReportsATruncatedWalk(t *testing.T) {
	m := chainedMemoryStore(t)
	writeEntries(t, m, 6)

	report, err := m.VerifyAuditChain(context.Background(), 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Truncated {
		t.Error("a walk that stopped at its limit must say so")
	}
	if report.Verified != 2 {
		t.Errorf("expected 2 entries checked, got %d", report.Verified)
	}
}

// Length-prefixing, not concatenation. Without it, moving a character from one
// field to the next produces the same tag input and one entry verifies as
// another.
func TestAuditCanonicalIsUnambiguous(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()
	a := &AuditLog{Seq: 1, ID: "x", Action: "ca", EntityType: "expired", CreatedAt: at}
	b := &AuditLog{Seq: 1, ID: "x", Action: "caexpired", EntityType: "", CreatedAt: at}

	if string(auditCanonical(a)) == string(auditCanonical(b)) {
		t.Fatal("two different entries must not produce the same tag input")
	}
}

// Empty and absent are different claims — "no actor" is not "an actor with a
// blank address" — and the database stores them differently too.
func TestAuditCanonicalSeparatesNullFromEmpty(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()
	empty := ""
	withNil := &AuditLog{Seq: 1, ID: "x", Action: "a", EntityType: "b", CreatedAt: at}
	withEmpty := &AuditLog{Seq: 1, ID: "x", Action: "a", EntityType: "b", ActorID: &empty, CreatedAt: at}

	if string(auditCanonical(withNil)) == string(auditCanonical(withEmpty)) {
		t.Fatal("a nil actor and an empty-string actor must not hash alike")
	}
}

// PostgreSQL stores microseconds. A tag computed over nanoseconds would stop
// verifying the moment the row was read back, and every entry would read as
// tampered.
func TestAuditChainTruncatesToMicroseconds(t *testing.T) {
	m := chainedMemoryStore(t)
	writeEntries(t, m, 1)

	got := m.auditLogs[0].CreatedAt
	if got.Nanosecond()%1000 != 0 {
		t.Errorf("created_at must be truncated to microseconds before the tag is computed, got %v", got)
	}
}
