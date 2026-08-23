package notifications

import (
	"context"
	"strings"
	"testing"
	"time"
)

func buildEmail(t *testing.T, config string) *emailNotifier {
	t.Helper()
	n, err := Build(TypeEmail, []byte(config), nil)
	if err != nil {
		t.Fatalf("Build(%s): %v", config, err)
	}
	return n.(*emailNotifier)
}

func TestEmailConfigRejectsWhatCannotWork(t *testing.T) {
	cases := map[string]struct {
		config string
		want   string
	}{
		"no host":           {`{"from":"a@b.test","to":["c@d.test"]}`, "SMTP host"},
		"no from":           {`{"host":"smtp.test","to":["c@d.test"]}`, "from address is required"},
		"no recipients":     {`{"host":"smtp.test","from":"a@b.test"}`, "at least one recipient"},
		"bad from":          {`{"host":"smtp.test","from":"not an address","to":["c@d.test"]}`, "not valid"},
		"bad recipient":     {`{"host":"smtp.test","from":"a@b.test","to":["@@@"]}`, "not valid"},
		"bad encryption":    {`{"host":"smtp.test","from":"a@b.test","to":["c@d.test"],"encryption":"ssl"}`, "encryption must be"},
		"port out of range": {`{"host":"smtp.test","port":70000,"from":"a@b.test","to":["c@d.test"]}`, "out of range"},
		"malformed json":    {`{"host":`, "not valid JSON"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Build(TypeEmail, []byte(tc.config), nil)
			if err == nil {
				t.Fatal("accepted a configuration that cannot deliver")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// Go's smtp.PlainAuth refuses to send credentials over an unencrypted
// connection at send time. Refusing it at save time means the operator finds out
// while they are still looking at the form, rather than from an alert that never
// arrived.
func TestEmailRefusesCredentialsOverAnUnencryptedConnection(t *testing.T) {
	config := `{"host":"smtp.test","from":"a@b.test","to":["c@d.test"],"encryption":"none","password":"hunter2"}`
	_, err := Build(TypeEmail, []byte(config), nil)
	if err == nil {
		t.Fatal("a password over an unencrypted connection was accepted")
	}
	if !strings.Contains(err.Error(), "unencrypted") {
		t.Errorf("error = %q", err)
	}
}

func TestEmailPortDefaultsFollowTheEncryptionMode(t *testing.T) {
	cases := map[string]int{"starttls": 587, "tls": 465, "none": 25, "": 587}
	for enc, want := range cases {
		t.Run("encryption="+enc, func(t *testing.T) {
			config := `{"host":"smtp.test","from":"a@b.test","to":["c@d.test"],"encryption":"` + enc + `"}`
			n := buildEmail(t, config)
			if n.cfg.Port != want {
				t.Errorf("port = %d, want %d", n.cfg.Port, want)
			}
		})
	}
}

// A display name is accepted but only the bare address goes into the SMTP
// envelope, or the relay rejects the whole message.
func TestEmailAddressesAreNormalised(t *testing.T) {
	n := buildEmail(t, `{"host":"smtp.test","from":"PKI Team <pki@example.test>","to":["On Call <oncall@example.test>"]}`)
	if n.cfg.From != "pki@example.test" {
		t.Errorf("from = %q, want the bare address", n.cfg.From)
	}
	if len(n.cfg.To) != 1 || n.cfg.To[0] != "oncall@example.test" {
		t.Errorf("to = %v, want the bare address", n.cfg.To)
	}
}

// The one that matters. A CA's common name comes from a certificate CertPilot
// did not issue, and it reaches the Subject header. Without sanitising, a name
// containing CRLF injects headers into every alert about that CA — including a
// Bcc that silently copies them elsewhere.
func TestEmailHeaderInjectionIsImpossible(t *testing.T) {
	n := buildEmail(t, `{"host":"smtp.test","from":"a@b.test","to":["c@d.test"]}`)

	message := string(n.compose(Alert{
		Severity:  "CRITICAL",
		Topic:     "ca.expiry_alert\r\nX-Injected: yes",
		Title:     "Evil CA\r\nBcc: attacker@example.com",
		Summary:   "It expires soon.",
		Timestamp: time.Now(),
	}))

	headers, body, found := strings.Cut(message, "\r\n\r\n")
	if !found {
		t.Fatal("the message has no header/body separator")
	}

	// Injection means a *new header line*, not the text appearing somewhere.
	// "Subject: ... Bcc: attacker@..." is inert — it is one header whose value
	// happens to contain a colon — so the assertion is on line starts, which is
	// the only thing a mail server parses as a header.
	for _, line := range strings.Split(headers, "\r\n") {
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			t.Errorf("header block contains a line that is not a header: %q", line)
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "bcc", "cc", "x-injected":
			t.Errorf("a %q header was injected through alert text:\n%s", name, headers)
		}
	}

	// The block must end where compose intends. A CRLF surviving into a header
	// value would close it early and push the remaining real headers into the
	// body, which is the other shape this attack takes.
	if !strings.HasSuffix(headers, "Content-Transfer-Encoding: 8bit") {
		t.Errorf("the header block ended early, so headers leaked into the body:\n%s", headers)
	}

	// The content still has to survive — sanitising must not mean discarding.
	if !strings.Contains(headers, "Evil CA") {
		t.Errorf("the CA name was lost entirely:\n%s", headers)
	}
	if !strings.Contains(body, "It expires soon.") {
		t.Errorf("the body was lost:\n%s", body)
	}
}

func TestEmailMessageIsWellFormed(t *testing.T) {
	n := buildEmail(t, `{"host":"smtp.test","from":"pki@example.test","to":["a@example.test","b@example.test"]}`)

	message := string(n.compose(Alert{
		Severity: "WARNING", Topic: "ca.expiry_alert",
		Title: "CA expiring: Corporate Root", Summary: "It expires in 30 days.",
		EntityID:  "ca-9",
		Fields:    []Field{{Label: "Days remaining", Value: "30 days"}},
		Timestamp: time.Unix(1_700_000_000, 0),
	}))

	for _, want := range []string{
		"From: CertPilot <pki@example.test>",
		"To: a@example.test, b@example.test",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"X-CertPilot-Severity: WARNING",
		"X-CertPilot-Topic: ca.expiry_alert",
		"Message-ID: <",
		"Days remaining:",
		"ca-9",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("message is missing %q:\n%s", want, message)
		}
	}
	if !strings.Contains(message, "Subject: ") {
		t.Error("no Subject header")
	}
	// Severity in the subject lets a mail rule route without parsing anything.
	if !strings.Contains(message, "CertPilot WARNING") {
		t.Errorf("subject does not carry the severity:\n%s", message)
	}
}

// A non-ASCII CA name has to survive, or the alert arrives as mojibake and the
// name is the thing the reader needs.
func TestEmailSubjectIsEncodedForNonASCII(t *testing.T) {
	n := buildEmail(t, `{"host":"smtp.test","from":"a@b.test","to":["c@d.test"]}`)
	message := string(n.compose(Alert{
		Severity: "INFO", Title: "Zertifizierungsstelle läuft ab", Timestamp: time.Now(),
	}))

	subject := ""
	for _, line := range strings.Split(message, "\r\n") {
		if strings.HasPrefix(line, "Subject: ") {
			subject = line
			break
		}
	}
	if subject == "" {
		t.Fatal("no Subject header")
	}
	if !strings.Contains(subject, "=?utf-8?") {
		t.Errorf("Subject is not encoded, so it will arrive corrupted: %q", subject)
	}
}

// A relay that cannot be reached must fail promptly and say what it was trying
// to reach, rather than hanging until the process exits.
func TestEmailSendFailsPromptlyWhenTheRelayIsUnreachable(t *testing.T) {
	// Port 1 on loopback refuses immediately.
	n := buildEmail(t, `{"host":"127.0.0.1","port":1,"from":"a@b.test","to":["c@d.test"],"encryption":"none"}`)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	err := n.Send(ctx, TestAlert("probe"))
	if err == nil {
		t.Fatal("sending to a closed port reported success")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("took %s to fail", took)
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("error = %q, want it to name the address it could not reach", err)
	}
}
