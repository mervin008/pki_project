package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/certpilot/certpilot/pkg/secrets"
)

// AuditChainVersion is the canonicalisation format the tag is computed over.
//
// It is the first byte of every tag input, so a future change to which fields
// are covered, or how they are encoded, cannot make an old entry silently
// verify under new rules — it fails, visibly, and the verifier can say which
// format it was expecting.
const AuditChainVersion byte = 1

// AuditChainZeroPrev is the predecessor tag of the first entry in a chain.
var AuditChainZeroPrev = make([]byte, secrets.MACSize)

// ErrNoAuditChain reports that the store was never given a keyring, so audit
// entries are being written without tamper-evidence.
var ErrNoAuditChain = errors.New("store: no audit chain key configured")

// AuditChainer computes and checks the audit log's tamper-evidence tags.
//
// It lives here, above both store implementations, because the alternative is
// two definitions of what a tag covers — and the moment those disagree, the
// in-memory store's tests pass while the real one reports every entry as
// tampered. That is the same shape as the store defects this project keeps
// finding, and it is worth one shared type to make it impossible.
type AuditChainer struct {
	kr *secrets.Keyring
}

// NewAuditChainer returns a chainer keyed from kr, or nil if kr is nil.
func NewAuditChainer(kr *secrets.Keyring) *AuditChainer {
	if kr == nil {
		return nil
	}
	return &AuditChainer{kr: kr}
}

// Link computes the tag for l chained to prev, and returns it with the
// identifier of the key that produced it.
//
// l.Seq and l.CreatedAt must already be set: both are covered by the tag, and
// the sequence number is what makes a deleted entry detectable as a gap rather
// than simply absent.
func (c *AuditChainer) Link(l *AuditLog, prev []byte) (keyID string, tag []byte, err error) {
	if c == nil {
		return "", nil, ErrNoAuditChain
	}
	if len(prev) != secrets.MACSize {
		return "", nil, fmt.Errorf("store: previous audit tag is %d bytes, expected %d", len(prev), secrets.MACSize)
	}
	return c.kr.MAC(secrets.PurposeAuditChain, append(append([]byte{}, prev...), auditCanonical(l)...))
}

// Verify recomputes l's tag from the entry as it now reads and reports whether
// it still agrees.
//
// A false here means the row's contents, its position in the chain, or the
// entry before it changed after it was written. It does not say which — that
// is what walking the chain in order is for, and why the first break is the
// only one worth reporting.
func (c *AuditChainer) Verify(l *AuditLog) (bool, error) {
	if c == nil {
		return false, ErrNoAuditChain
	}
	if len(l.EntryHash) == 0 {
		return false, nil
	}
	prev := l.PrevHash
	if len(prev) == 0 {
		prev = AuditChainZeroPrev
	}
	if len(prev) != secrets.MACSize {
		return false, nil
	}
	return c.kr.VerifyMAC(l.ChainKeyID, secrets.PurposeAuditChain,
		append(append([]byte{}, prev...), auditCanonical(l)...), l.EntryHash)
}

// auditCanonical renders the covered fields of an entry as unambiguous bytes.
//
// Every field is length-prefixed rather than concatenated with a separator.
// Plain concatenation lets one entry impersonate another: action "ca" with
// entity type "expired" and action "caexpired" with entity type "" would
// produce identical input, so a tag computed over one would verify the other.
//
// A nil pointer and an empty string are encoded differently for the same
// reason they are different in the database — "no actor" and "an actor with a
// blank address" are not the same claim.
func auditCanonical(l *AuditLog) []byte {
	buf := make([]byte, 0, 256)
	buf = append(buf, AuditChainVersion)
	buf = binary.BigEndian.AppendUint64(buf, uint64(l.Seq))
	buf = auditField(buf, l.ID)
	buf = auditField(buf, l.Action)
	buf = auditField(buf, l.EntityType)
	buf = auditOptional(buf, l.EntityID)
	buf = auditOptional(buf, l.ActorID)
	buf = auditOptional(buf, l.ActorEmail)
	buf = auditField(buf, l.Details)
	buf = auditOptional(buf, l.IPAddress)
	// Microseconds, not nanoseconds: PostgreSQL's timestamptz has microsecond
	// resolution, so a tag computed over a Go timestamp's nanoseconds would
	// stop verifying the moment the row was read back. CreateAuditLog truncates
	// to match before the tag is computed.
	buf = binary.BigEndian.AppendUint64(buf, uint64(l.CreatedAt.UTC().UnixMicro()))
	return buf
}

func auditField(buf []byte, s string) []byte {
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(s)))
	return append(buf, s...)
}

func auditOptional(buf []byte, s *string) []byte {
	if s == nil {
		return append(buf, 0)
	}
	return auditField(append(buf, 1), *s)
}

// AuditChainReport is the result of walking the chain.
type AuditChainReport struct {
	// Intact is the headline answer, and is false whenever the walk could not
	// prove otherwise — including when there is no key to check with.
	Intact bool `json:"intact"`
	// Verified counts entries whose tags recomputed correctly.
	Verified int64 `json:"verified"`
	// Unchained counts entries written before tamper-evidence existed. They are
	// reported rather than ignored: an operator reading "intact" is entitled to
	// know how much of the record that claim actually covers.
	Unchained int64 `json:"unchained"`
	FirstSeq  int64 `json:"first_seq,omitempty"`
	LastSeq   int64 `json:"last_seq,omitempty"`
	// BrokenAt is the sequence number of the first entry that failed, or of the
	// gap that was found where an entry should have been.
	BrokenAt *int64 `json:"broken_at,omitempty"`
	// Reason is written for whoever reads this at 2am, and names the cause.
	Reason    string    `json:"reason,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	// Truncated reports that the walk stopped at its limit rather than at the
	// end of the chain, so Intact covers only what was examined.
	Truncated bool `json:"truncated"`
}

// verifyAuditChainOver walks entries in ascending sequence order, checking each
// tag and each link to its predecessor.
//
// Shared by both stores so that "what counts as a break" has one definition.
// Entries must arrive sorted by Seq ascending, starting at from.
func verifyAuditChainOver(entries []*AuditLog, chainer *AuditChainer, from int64, unchained int64, truncated bool) *AuditChainReport {
	report := &AuditChainReport{
		CheckedAt: time.Now().UTC(),
		Unchained: unchained,
		Truncated: truncated,
	}
	if chainer == nil {
		report.Reason = "no key encryption key is configured, so the audit chain cannot be checked"
		return report
	}

	expected := from
	if expected < 1 {
		expected = 1
	}
	var prev []byte

	for i, l := range entries {
		if i == 0 {
			report.FirstSeq = l.Seq
			// Only a walk that starts at the true beginning knows what the
			// predecessor tag should be. Starting mid-chain trusts the stored
			// prev_hash for the first link, which is why a partial verification
			// can confirm a range but never the whole record.
			if l.Seq == 1 {
				prev = AuditChainZeroPrev
			} else {
				prev = l.PrevHash
			}
			expected = l.Seq
		}

		if l.Seq != expected {
			seq := expected
			report.BrokenAt = &seq
			report.Reason = fmt.Sprintf(
				"entry %d is missing: the chain jumps from %d to %d, so at least one record was deleted",
				expected, expected-1, l.Seq)
			return report
		}

		if len(prev) == secrets.MACSize && len(l.PrevHash) == secrets.MACSize {
			if !bytes.Equal(prev, l.PrevHash) {
				seq := l.Seq
				report.BrokenAt = &seq
				report.Reason = fmt.Sprintf(
					"entry %d does not follow entry %d: it records a different predecessor than the one actually stored",
					l.Seq, l.Seq-1)
				return report
			}
		}

		ok, err := chainer.Verify(l)
		if err != nil {
			seq := l.Seq
			report.BrokenAt = &seq
			report.Reason = fmt.Sprintf("entry %d cannot be checked: %v", l.Seq, err)
			return report
		}
		if !ok {
			seq := l.Seq
			report.BrokenAt = &seq
			report.Reason = fmt.Sprintf(
				"entry %d does not match its own tag: the record was altered after it was written", l.Seq)
			return report
		}

		prev = l.EntryHash
		report.LastSeq = l.Seq
		report.Verified++
		expected++
	}

	report.Intact = true
	if report.Verified == 0 {
		report.Reason = "no chained entries to check"
	}
	return report
}
