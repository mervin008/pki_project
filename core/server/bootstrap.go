package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/config"
	"github.com/google/uuid"
)

// bootstrapFirstAdmin creates the first account when there are none.
//
// Somebody has to be able to grant the first role, and every alternative is
// worse than naming the address in configuration. "First sign-in wins" hands
// the estate to whoever reaches the URL first, which on an instance that is
// reachable before it is announced need not be anyone you know. A default
// password is a published password.
//
// It runs only against an empty users table, so it cannot resurrect an account
// somebody deliberately removed, and it cannot re-promote one they demoted.
func bootstrapFirstAdmin(ctx context.Context, st store.Store, cfg config.AuthConfig) error {
	// Keyed on accounts that can actually sign in, not on the table being
	// empty. An instance upgraded from a token-only build already has users —
	// created the first time somebody presented a token — and checking for an
	// empty table would leave every one of them unable to sign in with no way
	// to fix it short of writing SQL.
	usable, err := st.CountPasswordAccounts(ctx)
	if err != nil {
		return fmt.Errorf("could not check whether anybody can sign in: %w", err)
	}
	if usable > 0 {
		return nil
	}

	if len(cfg.BootstrapAdmins) == 0 {
		// Not an error. An instance federated to an identity provider gets its
		// first admin from bootstrap_admins at first sign-in instead, and one
		// with neither is simply not usable yet — which is a state an operator
		// should be told about rather than have papered over.
		slog.Warn("no accounts exist and auth.bootstrap_admins is empty; " +
			"nobody can sign in until one is configured")
		return nil
	}

	email := strings.TrimSpace(cfg.BootstrapAdmins[0])
	password, err := generatePassword()
	if err != nil {
		return fmt.Errorf("could not generate a first password: %w", err)
	}

	// An account for this address may already exist — federated, or created by
	// an earlier build — in which case it is given a password rather than
	// duplicated. Two rows for one person would make "who did this" ambiguous
	// in the audit log, which is the one place it must not be.
	user, err := st.UserByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("could not look for an existing account: %w", err)
	}

	if user == nil {
		user, err = st.ResolveUser(ctx, store.UserIdentity{
			Issuer: store.LocalIssuer,
			// A local account still needs a subject: it is what every actor
			// column records, and it must not change if the address does.
			Subject:     uuid.NewString(),
			Email:       email,
			DisplayName: email,
		}, cfg.BootstrapAdmins)
		if err != nil {
			return fmt.Errorf("could not create the first account: %w", err)
		}
	} else if user.Role != store.RoleAdmin {
		// Deliberately not promoted. Somebody demoted this account on purpose,
		// and a recovery path that silently undoes that is a privilege
		// escalation with a friendly name. The password is still set, so the
		// instance is reachable, and the operator is told what they now have.
		slog.Warn("the bootstrap address holds a non-admin role; setting its password "+
			"but leaving the role alone",
			"email", email, "role", user.Role)
	}

	// must_change is set: this password was generated, printed to a terminal,
	// and very likely scrolled through a log. It is a way in, not a credential.
	if err := st.SetUserPassword(ctx, user.ID, password, true); err != nil {
		return fmt.Errorf("could not set the first password: %w", err)
	}

	// Printed rather than logged at info: this is the one moment the value
	// exists, and it must not be lost among engine start-up lines.
	fmt.Printf(`
┌─ CertPilot: first run ─────────────────────────────────────────────
│ An administrator account has been created.
│
│   email:    %s
│   password: %s
│
│ This password is shown once and cannot be recovered. Change it after
│ signing in; CertPilot will ask you to.
└────────────────────────────────────────────────────────────────────

`, email, password)

	slog.Info("created the first administrator", "email", email, "user_id", user.ID)
	return nil
}

// generatePassword returns a readable random password.
//
// The alphabet omits characters that are misread when copied off a terminal —
// 0/O and 1/l/I — because this value is printed once and typed by hand, and a
// password nobody can transcribe is a password that gets reset immediately or,
// worse, replaced with a weak one.
func generatePassword() (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	const groups, groupLen = 4, 5

	var out strings.Builder
	for g := range groups {
		if g > 0 {
			out.WriteByte('-')
		}
		for range groupLen {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			if err != nil {
				return "", err
			}
			out.WriteByte(alphabet[n.Int64()])
		}
	}
	// 20 characters from a 55-character alphabet is about 116 bits, well past
	// anything an offline attack against Argon2id makes progress on.
	return out.String(), nil
}
