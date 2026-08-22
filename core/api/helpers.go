package api

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

// unexpectedQuery returns the first query parameter this endpoint does not
// understand, or "".
//
// Used by list endpoints whose results get acted on. A filter that is silently
// dropped turns "the three certificates matching this name" into "every
// certificate", which is a difference nothing downstream can detect and which
// a delete loop cannot survive.
func unexpectedQuery(c *gin.Context, allowed ...string) string {
	known := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		known[name] = true
	}
	for name := range c.Request.URL.Query() {
		if !known[name] {
			return name
		}
	}
	return ""
}

// certificateEnvironments are the values the certificates table accepts.
//
// The schema has enforced these since migration 001, and until now nothing
// checked them before issuing. The order that mattered was the wrong way
// round: the CA signed, the row was refused by a check constraint, and the
// operator got a raw SQLSTATE — while a real certificate existed at the CA
// that CertPilot had no record of, counted against the account's rate limit,
// and would never be renewed or revoked because nothing knew it was there.
var certificateEnvironments = []string{"production", "staging", "development"}

// normalizeEnvironment canonicalises an environment, or explains what the
// choices are.
//
// Case is forgiven because "Production" is a typo with no other possible
// meaning. An unknown value is not: guessing which of three environments
// somebody meant is how a certificate ends up labelled as something it is not.
func normalizeEnvironment(environment string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(environment))
	if trimmed == "" {
		return "", nil
	}
	for _, allowed := range certificateEnvironments {
		if trimmed == allowed {
			return trimmed, nil
		}
	}
	return "", fmt.Errorf(
		"environment %q is not one of %s. Refusing here rather than at the database, because by then the CA has already issued a certificate that nothing would have a record of",
		environment, strings.Join(certificateEnvironments, ", "))
}
