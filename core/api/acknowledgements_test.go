package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// seedCA registers a CA directly in the store, so a test does not need a real
// certificate to exercise acknowledgement.
func seedCA(t *testing.T, st store.Store, name string, threshold *int) *store.CAAuthority {
	t.Helper()
	ca := &store.CAAuthority{
		Name: name, CAType: "ISSUING", Status: "CRITICAL",
		SubjectDN: "CN=" + name, IssuerDN: "CN=" + name,
		DaysRemaining: 9, LastAlertThreshold: threshold,
	}
	if err := st.CreateCAAuthority(t.Context(), ca); err != nil {
		t.Fatalf("CreateCAAuthority: %v", err)
	}
	return ca
}

func listCAs(t *testing.T, r *gin.Engine) []store.CAAuthority {
	t.Helper()
	w := do(r, http.MethodGet, "/api/v1/pki/authorities", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d (%s)", w.Code, w.Body.String())
	}
	var payload struct {
		Data []store.CAAuthority `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("list body: %v", err)
	}
	return payload.Data
}

func find(cas []store.CAAuthority, id string) *store.CAAuthority {
	for i := range cas {
		if cas[i].ID == id {
			return &cas[i]
		}
	}
	return nil
}

// The rule the whole feature turns on, tested at the surface an operator sees.
// A silenced CA must still be on the list, marked — hiding a problem because
// someone clicked a button is how CAs expire in organisations that believed they
// were monitoring them.
func TestSilencingNeverHidesTheCA(t *testing.T) {
	r, st := realRouter(t)
	ca := seedCA(t, st, "Corporate Issuing CA", ptr(14))

	before := find(listCAs(t, r), ca.ID)
	if before == nil {
		t.Fatal("the CA is not listed before acknowledgement")
	}
	if before.Acknowledgement != nil {
		t.Error("an un-acknowledged CA reports an acknowledgement")
	}

	w := do(r, http.MethodPost, "/api/v1/pki/authorities/"+ca.ID+"/acknowledge",
		gin.H{"note": "replacement issued, cutover Thursday", "silence_days": 7}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("acknowledge status = %d (%s)", w.Code, w.Body.String())
	}

	after := find(listCAs(t, r), ca.ID)
	if after == nil {
		t.Fatal("the CA disappeared from the list once it was silenced")
	}
	if after.Acknowledgement == nil {
		t.Fatal("the CA is listed but not marked as acknowledged, so the reader cannot tell anyone looked")
	}
	if after.Acknowledgement.Note != "replacement issued, cutover Thursday" {
		t.Errorf("note = %q", after.Acknowledgement.Note)
	}
	if after.Acknowledgement.SilenceUntil == nil {
		t.Error("silence_days was ignored")
	}
	// The status is untouched: acknowledgement is a note about who is handling
	// it, not a claim that the CA is healthier than it is.
	if after.Status != "CRITICAL" {
		t.Errorf("status = %q, want it unchanged by acknowledgement", after.Status)
	}
}

// The response has to say what was and was not changed, because "acknowledged"
// is ambiguous and the ambiguity is the dangerous part.
func TestTheResponseSaysExactlyWhatAcknowledgingDid(t *testing.T) {
	r, st := realRouter(t)
	ca := seedCA(t, st, "Corporate Issuing CA", ptr(14))

	quiet := do(r, http.MethodPost, "/api/v1/pki/authorities/"+ca.ID+"/acknowledge",
		gin.H{"silence_days": 7}, nil)
	body := quiet.Body.String()
	if !strings.Contains(body, "still appears on the dashboard") {
		t.Errorf("the response does not say the CA remains visible: %s", body)
	}
	if !strings.Contains(body, "tighter one") {
		t.Errorf("the response does not say a tighter threshold still alerts: %s", body)
	}

	ca2 := seedCA(t, st, "Second CA", ptr(14))
	seen := do(r, http.MethodPost, "/api/v1/pki/authorities/"+ca2.ID+"/acknowledge",
		gin.H{"note": "known"}, nil)
	if !strings.Contains(seen.Body.String(), "does not silence") {
		t.Errorf("acknowledging without silencing did not say alerts continue: %s", seen.Body.String())
	}
}

// An acknowledgement defaults to the threshold the CA has actually alerted at.
// Without that it would be unbounded and cover every future alert, including the
// 7-day one nobody has seen yet.
func TestAcknowledgementDefaultsToTheCurrentThreshold(t *testing.T) {
	r, st := realRouter(t)
	ca := seedCA(t, st, "Corporate Issuing CA", ptr(14))

	w := do(r, http.MethodPost, "/api/v1/pki/authorities/"+ca.ID+"/acknowledge", gin.H{}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d (%s)", w.Code, w.Body.String())
	}

	var payload struct {
		Data store.AlertAcknowledgement `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &payload)
	if payload.Data.Threshold == nil || *payload.Data.Threshold != 14 {
		t.Fatalf("threshold = %v, want the CA's current 14", payload.Data.Threshold)
	}
}

// Once the CA crosses a tighter threshold the earlier acknowledgement stops
// describing it, and the list must stop showing it as acknowledged — otherwise
// the annotation itself becomes the false reassurance.
func TestAnAcknowledgementStopsApplyingWhenThingsWorsen(t *testing.T) {
	r, st := realRouter(t)
	ca := seedCA(t, st, "Corporate Issuing CA", ptr(30))

	if w := do(r, http.MethodPost, "/api/v1/pki/authorities/"+ca.ID+"/acknowledge",
		gin.H{"note": "seen at 30 days"}, nil); w.Code != http.StatusCreated {
		t.Fatalf("acknowledge: %s", w.Body.String())
	}
	if find(listCAs(t, r), ca.ID).Acknowledgement == nil {
		t.Fatal("the acknowledgement is not shown at the threshold it was made at")
	}

	// The health sweep crosses the 7-day threshold.
	stored, err := st.GetCAAuthority(t.Context(), ca.ID)
	if err != nil {
		t.Fatalf("GetCAAuthority: %v", err)
	}
	stored.LastAlertThreshold = ptr(7)
	if err := st.UpdateCAAuthority(t.Context(), stored); err != nil {
		t.Fatalf("UpdateCAAuthority: %v", err)
	}

	if ack := find(listCAs(t, r), ca.ID).Acknowledgement; ack != nil {
		t.Errorf("a CA that has since crossed 7 days still reads as acknowledged at 30: %+v", ack)
	}
}

func TestWithdrawingAnAcknowledgementKeepsItsHistory(t *testing.T) {
	r, st := realRouter(t)
	ca := seedCA(t, st, "Corporate Issuing CA", ptr(14))

	do(r, http.MethodPost, "/api/v1/pki/authorities/"+ca.ID+"/acknowledge",
		gin.H{"note": "acknowledged in error"}, nil)

	w := do(r, http.MethodDelete, "/api/v1/pki/authorities/"+ca.ID+"/acknowledge", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("withdraw status = %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "alerts resume") {
		t.Errorf("the response does not say alerts resume: %s", w.Body.String())
	}

	if find(listCAs(t, r), ca.ID).Acknowledgement != nil {
		t.Error("a withdrawn acknowledgement is still shown")
	}

	// The record survives: acknowledged in error and then withdrawn is
	// something a review wants to see, not a row that vanished.
	h := do(r, http.MethodGet, "/api/v1/pki/authorities/"+ca.ID+"/acknowledgements", nil, nil)
	var history struct {
		Data []store.AlertAcknowledgement `json:"data"`
	}
	_ = json.Unmarshal(h.Body.Bytes(), &history)
	if len(history.Data) != 1 || history.Data[0].RevokedAt == nil {
		t.Fatalf("history = %+v, want one withdrawn entry", history.Data)
	}

	// Withdrawing again is a 404, not a silent success.
	if w := do(r, http.MethodDelete, "/api/v1/pki/authorities/"+ca.ID+"/acknowledge", nil, nil); w.Code != http.StatusNotFound {
		t.Errorf("second withdraw = %d, want 404", w.Code)
	}
}

// There is no indefinite silence. A permanent one is indistinguishable from
// deleting the alert, and the CA goes on expiring while the team believes it is
// monitored.
func TestSilenceIsBounded(t *testing.T) {
	r, st := realRouter(t)
	ca := seedCA(t, st, "Corporate Issuing CA", ptr(14))

	for _, days := range []int{-1, 91, 3650} {
		w := do(r, http.MethodPost, "/api/v1/pki/authorities/"+ca.ID+"/acknowledge",
			gin.H{"silence_days": days}, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("silence_days=%d gave %d, want 400", days, w.Code)
		}
	}
	if w := do(r, http.MethodPost, "/api/v1/pki/authorities/"+ca.ID+"/acknowledge",
		gin.H{"silence_days": 90}, nil); w.Code != http.StatusCreated {
		t.Errorf("the maximum silence was rejected: %s", w.Body.String())
	}
}

func TestOwnershipIsRecordedAndClearable(t *testing.T) {
	r, st := realRouter(t)
	ca := seedCA(t, st, "Corporate Issuing CA", nil)

	w := do(r, http.MethodPut, "/api/v1/pki/authorities/"+ca.ID+"/owner",
		gin.H{"owner_team": "Platform Security", "owner_email": "pki@example.com"}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("set owner status = %d (%s)", w.Code, w.Body.String())
	}

	got := find(listCAs(t, r), ca.ID)
	if got.OwnerTeam == nil || *got.OwnerTeam != "Platform Security" {
		t.Errorf("owner_team = %v", got.OwnerTeam)
	}
	if got.OwnerEmail == nil || *got.OwnerEmail != "pki@example.com" {
		t.Errorf("owner_email = %v", got.OwnerEmail)
	}

	// A typo found when a CA is hours from expiry is found too late.
	if w := do(r, http.MethodPut, "/api/v1/pki/authorities/"+ca.ID+"/owner",
		gin.H{"owner_email": "not-an-address"}, nil); w.Code != http.StatusBadRequest {
		t.Errorf("an invalid owner email was accepted (%d)", w.Code)
	}

	// Ownership moving to nobody is a real state worth seeing, so it must be
	// clearable rather than stuck on the last team's name.
	if w := do(r, http.MethodPut, "/api/v1/pki/authorities/"+ca.ID+"/owner",
		gin.H{"owner_team": "", "owner_email": ""}, nil); w.Code != http.StatusOK {
		t.Fatalf("clearing ownership failed: %s", w.Body.String())
	}
	cleared := find(listCAs(t, r), ca.ID)
	if cleared.OwnerTeam != nil || cleared.OwnerEmail != nil {
		t.Errorf("ownership was not cleared: team=%v email=%v", cleared.OwnerTeam, cleared.OwnerEmail)
	}
}

func TestAcknowledgementAndOwnershipAreAudited(t *testing.T) {
	r, st := realRouter(t)
	ca := seedCA(t, st, "Corporate Issuing CA", ptr(14))

	do(r, http.MethodPost, "/api/v1/pki/authorities/"+ca.ID+"/acknowledge", gin.H{"note": "seen"}, nil)
	do(r, http.MethodPut, "/api/v1/pki/authorities/"+ca.ID+"/owner", gin.H{"owner_team": "Platform"}, nil)
	do(r, http.MethodDelete, "/api/v1/pki/authorities/"+ca.ID+"/acknowledge", nil, nil)

	for _, action := range []string{"ca.acknowledged", "ca.owner_changed", "ca.acknowledgement_withdrawn"} {
		logs, _, err := st.ListAuditLogs(t.Context(), store.AuditLogFilter{
			Actions: []string{action}, Limit: 10,
		})
		if err != nil {
			t.Fatalf("ListAuditLogs: %v", err)
		}
		if len(logs) == 0 {
			t.Errorf("%s was not audited — who acknowledged what is the record a review reads", action)
		}
	}
}

// A wall display is a viewer. It must be able to see that a CA is acknowledged,
// and must not be able to acknowledge one — an acknowledgement is a statement
// that a human looked, and it needs a human's name against it.
func TestDisplayTokensCanReadButNotAcknowledge(t *testing.T) {
	r, st := realRouter(t)
	ca := seedCA(t, st, "Corporate Issuing CA", ptr(14))
	raw, _ := mintToken(t, r, "corridor", 30)
	headers := map[string]string{"X-Display-Token": raw}

	if w := do(r, http.MethodGet, "/api/v1/pki/authorities", nil, headers); w.Code != http.StatusOK {
		t.Fatalf("a display token could not read the CA list (%d)", w.Code)
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/pki/authorities/" + ca.ID + "/acknowledge"},
		{http.MethodDelete, "/api/v1/pki/authorities/" + ca.ID + "/acknowledge"},
		{http.MethodPut, "/api/v1/pki/authorities/" + ca.ID + "/owner"},
	} {
		if w := do(r, tc.method, tc.path, gin.H{}, headers); w.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403", tc.method, tc.path, w.Code)
		}
	}
}

func ptr(v int) *int { return &v }
