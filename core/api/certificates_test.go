package api

import (
	"net/http"
	"strings"
	"testing"
)

// TestAFilterThisEndpointDoesNotUnderstandIsRefused.
//
// Paid for in a live run: a cleanup script asked for `?search=…`, which this
// handler has never read. The filter was dropped, the list came back as the
// whole estate, and the loop deleting what it matched deleted everything.
//
// A narrowing parameter that silently does not narrow is harmless on a GET a
// person reads and destructive the moment anything acts on the result.
func TestAFilterThisEndpointDoesNotUnderstandIsRefused(t *testing.T) {
	r, _ := realRouter(t)

	w := do(r, http.MethodGet, "/api/v1/certificates?search=example.com", nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unknown filter, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "search") {
		t.Fatalf("the error should name the parameter it did not understand: %s", w.Body.String())
	}

	// The filters it does understand still work, and so does no filter at all.
	for _, path := range []string{
		"/api/v1/certificates",
		"/api/v1/certificates?status=ISSUED",
		"/api/v1/certificates?common_name=example.com&limit=5",
	} {
		if w := do(r, http.MethodGet, path, nil, nil); w.Code != http.StatusOK {
			t.Fatalf("%s should be accepted, got %d: %s", path, w.Code, w.Body.String())
		}
	}
}
