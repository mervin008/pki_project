package store

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// roleRank orders users by how much damage they can do, most first.
func roleRank(role string) int {
	switch role {
	case RoleAdmin:
		return 0
	case RoleOperator:
		return 1
	case RoleAuditor:
		return 2
	default:
		return 3
	}
}

func (s *MemoryStore) ResolveUser(_ context.Context, identity UserIdentity, bootstrapAdmins []string) (*User, error) {
	if identity.Issuer == "" || identity.Subject == "" {
		return nil, errors.New("store: a user needs both an issuer and a subject; an empty one " +
			"means a token was accepted without the claims that identify who holds it")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.users {
		if u.Issuer == identity.Issuer && u.Subject == identity.Subject {
			// Only the details the provider owns are refreshed. Role is never
			// written here: a sign-in must not be able to change one.
			if identity.Email != "" {
				u.Email = identity.Email
			}
			if identity.DisplayName != "" {
				u.DisplayName = identity.DisplayName
			}
			u.UpdatedAt = time.Now()
			copied := *u
			return &copied, nil
		}
	}

	role, source := RoleViewer, RoleSourceDefault
	if identity.Email != "" {
		for _, candidate := range bootstrapAdmins {
			if strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(identity.Email)) {
				role, source = RoleAdmin, RoleSourceBootstrap
				break
			}
		}
	}

	now := time.Now()
	u := &User{
		ID:          uuid.NewString(),
		Issuer:      identity.Issuer,
		Subject:     identity.Subject,
		Email:       identity.Email,
		DisplayName: identity.DisplayName,
		Role:        role,
		Status:      UserStatusActive,
		RoleSource:  source,
		LastSeenAt:  &now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	s.users[u.ID] = u

	copied := *u
	return &copied, nil
}

func (s *MemoryStore) GetUser(_ context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.users[id]
	if !ok {
		return nil, nil
	}
	copied := *u
	return &copied, nil
}

func (s *MemoryStore) ListUsers(_ context.Context) ([]*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Copies, not the stored pointers: a caller holding the backing value
	// would see it mutate under them on the next sign-in.
	users := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		copied := *u
		users = append(users, &copied)
	}
	sort.Slice(users, func(i, j int) bool {
		if roleRank(users[i].Role) != roleRank(users[j].Role) {
			return roleRank(users[i].Role) < roleRank(users[j].Role)
		}
		left, right := users[i].Email, users[j].Email
		if left == "" {
			left = users[i].Subject
		}
		if right == "" {
			right = users[j].Subject
		}
		return strings.ToLower(left) < strings.ToLower(right)
	})
	return users, nil
}

func (s *MemoryStore) SetUserRole(_ context.Context, id, role string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[id]
	if !ok {
		return nil, nil
	}
	u.Role = role
	u.RoleSource = RoleSourceAssigned
	u.UpdatedAt = time.Now()

	copied := *u
	return &copied, nil
}

func (s *MemoryStore) SetUserStatus(_ context.Context, id, status string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[id]
	if !ok {
		return nil, nil
	}
	u.Status = status
	u.UpdatedAt = time.Now()

	copied := *u
	return &copied, nil
}

func (s *MemoryStore) TouchUser(_ context.Context, id string, seenAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if u, ok := s.users[id]; ok {
		u.LastSeenAt = &seenAt
	}
	return nil
}
