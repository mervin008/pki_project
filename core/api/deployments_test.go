package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// TestADeploymentTargetIsValidatedBeforeItIsStored. A target that cannot work
// should be a 400 now, not a deployment that fails during an incident.
func TestADeploymentTargetIsValidatedBeforeItIsStored(t *testing.T) {
	r, _ := realRouter(t)

	cases := map[string]struct {
		body gin.H
		want string
	}{
		"a type nothing can deploy to": {
			gin.H{"name": "big-ip", "target_type": "f5", "config": gin.H{"host": "10.0.0.1"}},
			"cannot be deployed to yet",
		},
		"a webhook nobody can authenticate": {
			gin.H{"name": "unsigned", "target_type": "webhook",
				"config": gin.H{"url": "https://deploy.example.com/hook"}},
			"needs signing_secret",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w := do(r, http.MethodPost, "/api/v1/deployment-targets", tc.body, nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("response should mention %q, got %s", tc.want, w.Body.String())
			}
		})
	}
}

// TestTheTargetListSaysWhereKeysGoWithoutRevealingCredentials.
//
// Two properties in one place, and they pull in opposite directions: the sealed
// configuration must never leave the process, and "which places do we ship
// private keys to" must be answerable by reading the list.
func TestTheTargetListSaysWhereKeysGoWithoutRevealingCredentials(t *testing.T) {
	r, _ := realRouter(t)

	w := do(r, http.MethodPost, "/api/v1/deployment-targets", gin.H{
		"name": "lab receiver", "target_type": "webhook",
		"config": gin.H{
			"url":                 "https://deploy.example.com/hook",
			"signing_secret":      "a-signing-secret-long-enough",
			"include_private_key": true,
		},
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	w = do(r, http.MethodGet, "/api/v1/deployment-targets", nil, nil)
	body := w.Body.String()
	if strings.Contains(body, "a-signing-secret-long-enough") || strings.Contains(body, "config_encrypted") {
		t.Fatalf("the target list must not carry credentials: %s", body)
	}

	var resp struct {
		Data []struct {
			DeploysPrivateKey bool `json:"deploys_private_key"`
		} `json:"data"`
		CarryingPrivateKey int `json:"carrying_private_key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Data) != 1 || !resp.Data[0].DeploysPrivateKey || resp.CarryingPrivateKey != 1 {
		t.Fatalf("the list should say this target carries key material: %s", body)
	}
}

// TestBindingIsRefusedWhenTheKeyDoesNotExist. A target that needs the key and a
// certificate that has none can be bound quite happily and will then fail on
// every renewal forever, which is only ever noticed the week it matters.
func TestBindingIsRefusedWhenTheKeyDoesNotExist(t *testing.T) {
	r, st := realRouter(t)

	w := do(r, http.MethodPost, "/api/v1/deployment-targets", gin.H{
		"name": "needs the key", "target_type": "webhook",
		"config": gin.H{
			"url":                 "https://deploy.example.com/hook",
			"signing_secret":      "a-signing-secret-long-enough",
			"include_private_key": true,
		},
	}, nil)
	var created struct {
		Data store.DeploymentTarget `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	cert := &store.Certificate{
		CommonName:        "discovered.example.com",
		FingerprintSHA256: "aa11",
		Status:            "ISSUED",
		DiscoveredVia:     "SCAN",
	}
	if err := st.CreateCertificate(t.Context(), cert); err != nil {
		t.Fatalf("certificate: %v", err)
	}

	w = do(r, http.MethodPost, "/api/v1/certificates/"+cert.ID+"/targets",
		gin.H{"target_id": created.Data.ID}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "no private key") {
		t.Fatalf("the refusal should say why: %s", w.Body.String())
	}
}

// TestDeployingSomethingBoundNowhereSaysSo rather than reporting success over
// an estate where nothing happened.
func TestDeployingSomethingBoundNowhereSaysSo(t *testing.T) {
	r, st := realRouter(t)

	certs, _, err := st.ListCertificates(t.Context(), store.CertificateFilter{Limit: 1})
	if err != nil || len(certs) == 0 {
		t.Fatalf("seed: %v", err)
	}

	w := do(r, http.MethodPost, "/api/v1/certificates/"+certs[0].ID+"/deploy", gin.H{}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not bound to any deployment target") {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

// TestDeployQueuesOnePerPlaceAndSaysWhatItSkipped.
func TestDeployQueuesOnePerPlaceAndSaysWhatItSkipped(t *testing.T) {
	r, st := realRouter(t)
	ctx := t.Context()

	certs, _, _ := st.ListCertificates(ctx, store.CertificateFilter{Limit: 1})
	cert := certs[0]

	live := &store.DeploymentTarget{Name: "live", TargetType: "webhook", IsEnabled: true}
	off := &store.DeploymentTarget{Name: "off", TargetType: "webhook", IsEnabled: true}
	for _, target := range []*store.DeploymentTarget{live, off} {
		if err := st.CreateDeploymentTarget(ctx, target); err != nil {
			t.Fatalf("target: %v", err)
		}
	}
	for _, b := range []*store.CertificateDeployment{
		{CertificateID: cert.ID, TargetID: live.ID, IsEnabled: true},
		{CertificateID: cert.ID, TargetID: off.ID, IsEnabled: false},
	} {
		if err := st.CreateCertificateDeployment(ctx, b); err != nil {
			t.Fatalf("bind: %v", err)
		}
	}

	w := do(r, http.MethodPost, "/api/v1/certificates/"+cert.ID+"/deploy", gin.H{}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "queued for 1 target") || !strings.Contains(body, "switched off and skipped") {
		t.Fatalf("the response should account for both targets: %s", body)
	}

	// And asking twice does not queue the same place twice.
	w = do(r, http.MethodPost, "/api/v1/certificates/"+cert.ID+"/deploy", gin.H{}, nil)
	if !strings.Contains(w.Body.String(), "already had a deployment outstanding") {
		t.Fatalf("a second request should not duplicate work: %s", w.Body.String())
	}
}

// TestTheBindingSummaryNamesTheInterestingCase — targets holding a fingerprint
// older than the one CertPilot has. That is post-renewal verification's finding
// seen from the other end, and it can be answered without opening a connection.
func TestTheBindingSummaryNamesTheInterestingCase(t *testing.T) {
	cert := &store.Certificate{FingerprintSHA256: "new"}

	cases := map[string]struct {
		bindings []*store.CertificateDeployment
		want     string
	}{
		"nowhere at all": {
			nil,
			"reach nothing",
		},
		"bound and never pushed": {
			[]*store.CertificateDeployment{{}, {}},
			"nothing has been deployed yet",
		},
		// Its own branch, because the plural form produced "All 1 target hold
		// the current certificate" in a live run — a sentence that reads as a
		// machine talking, in the one place a person goes to find out whether
		// their certificate arrived.
		"the only place has it": {
			[]*store.CertificateDeployment{{DeployedFingerprint: "new"}},
			"The one place this goes is holding the current certificate",
		},
		"all current": {
			[]*store.CertificateDeployment{{DeployedFingerprint: "new"}, {DeployedFingerprint: "new"}},
			"All 2 targets hold the current certificate",
		},
		"one behind": {
			[]*store.CertificateDeployment{{DeployedFingerprint: "new"}, {DeployedFingerprint: "old"}},
			"1 holding an older certificate",
		},
		// The case a live run caught: what a place holds and whether the last
		// attempt to change it worked are different facts. Reporting only the
		// first read as an all-clear over a deployment that had escalated.
		"up to date and still failing": {
			[]*store.CertificateDeployment{
				{DeployedFingerprint: "new", LastStatus: store.DeploymentFailed},
			},
			"The last deployment to 1 target failed.",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := summarizeBindings(cert, tc.bindings)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("summary should mention %q, got %q", tc.want, got)
			}
		})
	}
}
