package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/certpilot/certpilot/pkg/passwords"
	"github.com/google/uuid"
)

// loginState is the in-memory equivalent of the throttling columns.
type loginState struct {
	failed      int
	lockedUntil *time.Time
}

func (s *MemoryStore) UserByEmail(_ context.Context, email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	wanted := strings.ToLower(strings.TrimSpace(email))
	for _, u := range s.users {
		if u.Email != "" && strings.ToLower(u.Email) == wanted {
			copied := *u
			return &copied, nil
		}
	}
	return nil, nil
}

func (s *MemoryStore) CountUsers(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users), nil
}

func (s *MemoryStore) AuthenticatePassword(ctx context.Context, email, password string) (*User, LoginOutcome, error) {
	u, err := s.UserByEmail(ctx, email)
	if err != nil {
		return nil, LoginNoSuchAccount, err
	}
	if u == nil {
		// Same work as a real account, for the same reason as in PostgreSQL:
		// an early return is a measurable account-enumeration oracle.
		_ = passwords.Verify(password, decoyHash)
		return nil, LoginNoSuchAccount, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	state := s.loginFailures[u.ID]
	if state == nil {
		state = &loginState{}
		s.loginFailures[u.ID] = state
	}

	now := time.Now()
	if state.lockedUntil != nil && now.Before(*state.lockedUntil) {
		return u, LoginLockedOut, nil
	}
	if !u.IsActive() {
		return u, LoginSuspended, nil
	}

	hash := s.passwordHashes[u.ID]
	if hash == "" {
		_ = passwords.Verify(password, decoyHash)
		return u, LoginNoPasswordSet, nil
	}

	if err := passwords.Verify(password, hash); err != nil {
		state.failed++
		if state.failed >= MaxFailedLogins {
			until := now.Add(LockoutWindow)
			state.lockedUntil = &until
		}
		return u, LoginWrongPassword, nil
	}

	state.failed = 0
	state.lockedUntil = nil
	return u, LoginOK, nil
}

func (s *MemoryStore) SetUserPassword(_ context.Context, id, password string, mustChange bool) error {
	hash, err := passwords.Hash(password)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[id]; !ok {
		return fmt.Errorf("store: no user %s to set a password on", id)
	}
	s.passwordHashes[id] = hash
	if u := s.users[id]; u != nil {
		u.MustChangePassword = mustChange
	}
	delete(s.loginFailures, id)
	return nil
}

func (s *MemoryStore) CreateSession(_ context.Context, userID, tokenHash string, expiresAt time.Time, userAgent, ip string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	sess := &Session{
		ID:         uuid.NewString(),
		UserID:     userID,
		TokenHash:  tokenHash,
		ExpiresAt:  expiresAt,
		LastSeenAt: &now,
		LastSeenIP: ip,
		UserAgent:  userAgent,
		CreatedAt:  now,
	}
	s.sessions[sess.ID] = sess

	copied := *sess
	return &copied, nil
}

func (s *MemoryStore) SessionByHash(_ context.Context, tokenHash string) (*Session, *User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, sess := range s.sessions {
		if sess.TokenHash != tokenHash {
			continue
		}
		u, ok := s.users[sess.UserID]
		if !ok {
			return nil, nil, nil
		}
		sessCopy, userCopy := *sess, *u
		return &sessCopy, &userCopy, nil
	}
	return nil, nil, nil
}

func (s *MemoryStore) RevokeSession(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for _, sess := range s.sessions {
		if sess.TokenHash == tokenHash && sess.RevokedAt == nil {
			sess.RevokedAt = &now
		}
	}
	return nil
}

func (s *MemoryStore) RevokeSessionsForUser(_ context.Context, userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	revoked := 0
	for _, sess := range s.sessions {
		if sess.UserID == userID && sess.RevokedAt == nil {
			sess.RevokedAt = &now
			revoked++
		}
	}
	return revoked, nil
}

func (s *MemoryStore) TouchSession(_ context.Context, id string, seenAt time.Time, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sess, ok := s.sessions[id]; ok {
		sess.LastSeenAt = &seenAt
		if ip != "" {
			sess.LastSeenIP = ip
		}
	}
	return nil
}

func (s *MemoryStore) CountPasswordAccounts(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n := 0
	for id, hash := range s.passwordHashes {
		if hash == "" {
			continue
		}
		if u, ok := s.users[id]; ok && u.IsActive() {
			n++
		}
	}
	return n, nil
}

func (s *MemoryStore) MarkCertificateRevoked(_ context.Context, id string, reason int, actorID string) (*Certificate, error) {
	if !ValidRevocationReason(reason) {
		return nil, fmt.Errorf("store: %d is not a revocation reason CertPilot accepts", reason)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cert, ok := s.certificates[id]
	if !ok || cert.Status == "REVOKED" {
		return nil, nil
	}

	now := time.Now()
	cert.Status = "REVOKED"
	cert.RevokedAt = &now
	cert.RevocationReason = &reason
	cert.RevokedBy = actorID
	cert.UpdatedAt = now

	copied := *cert
	return &copied, nil
}
