package notifications

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// emailConfig is the sealed configuration for an SMTP channel.
type emailConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// Username and Password are optional: a relay inside the network often
	// authenticates by source address instead.
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	// Encryption is "starttls" (default, port 587), "tls" for implicit TLS
	// (port 465), or "none" for a relay on a trusted network.
	Encryption string `json:"encryption,omitempty"`
	// InsecureSkipVerify disables certificate verification. Present because
	// internal relays with self-signed certificates are common, and an operator
	// who cannot turn this on will disable encryption entirely instead — which
	// is strictly worse.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}

// Encryption modes.
const (
	encStartTLS = "starttls"
	encTLS      = "tls"
	encNone     = "none"
)

type emailNotifier struct {
	cfg emailConfig
}

func newEmailNotifier(raw []byte) (Notifier, error) {
	var cfg emailConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("email configuration is not valid JSON: %w", err)
	}

	cfg.Host = strings.TrimSpace(cfg.Host)
	if cfg.Host == "" {
		return nil, fmt.Errorf("email needs an SMTP host")
	}

	cfg.Encryption = strings.ToLower(strings.TrimSpace(cfg.Encryption))
	if cfg.Encryption == "" {
		cfg.Encryption = encStartTLS
	}
	switch cfg.Encryption {
	case encStartTLS, encTLS, encNone:
	default:
		return nil, fmt.Errorf("encryption must be %q, %q, or %q (got %q)",
			encStartTLS, encTLS, encNone, cfg.Encryption)
	}

	if cfg.Port == 0 {
		switch cfg.Encryption {
		case encTLS:
			cfg.Port = 465
		case encNone:
			cfg.Port = 25
		default:
			cfg.Port = 587
		}
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("port %d is out of range", cfg.Port)
	}

	// Credentials over an unencrypted connection would be readable to anything
	// on the path. Go's smtp.PlainAuth refuses this at send time; refusing it
	// here means the operator learns while they are still looking at the form.
	if cfg.Password != "" && cfg.Encryption == encNone {
		return nil, fmt.Errorf(
			"a password cannot be sent over an unencrypted connection; use starttls or tls, or remove the credentials")
	}

	from, err := parseAddress(cfg.From, "from")
	if err != nil {
		return nil, err
	}
	cfg.From = from

	if len(cfg.To) == 0 {
		return nil, fmt.Errorf("email needs at least one recipient in to")
	}
	recipients := make([]string, 0, len(cfg.To))
	for _, addr := range cfg.To {
		parsed, err := parseAddress(addr, "to")
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, parsed)
	}
	cfg.To = recipients

	return &emailNotifier{cfg: cfg}, nil
}

// parseAddress validates one address and returns its bare form.
//
// net/mail accepts "Name <a@b>"; only the address itself goes into the SMTP
// envelope, and a malformed one would otherwise surface as a rejection from the
// relay long after anyone was looking at the configuration.
func parseAddress(value, field string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s address is required", field)
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil {
		return "", fmt.Errorf("%s address %q is not valid: %w", field, value, err)
	}
	return parsed.Address, nil
}

func (e *emailNotifier) Type() string { return TypeEmail }

func (e *emailNotifier) Send(ctx context.Context, alert Alert) error {
	message := e.compose(alert)
	addr := net.JoinHostPort(e.cfg.Host, fmt.Sprint(e.cfg.Port))

	// net/smtp predates context, so the deadline is applied to the dial and
	// then to the connection itself. Without this a wedged relay holds a worker
	// until the process exits.
	deadline, hasDeadline := ctx.Deadline()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if hasDeadline {
		dialer.Deadline = deadline
	}

	tlsConfig := &tls.Config{
		ServerName:         e.cfg.Host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: e.cfg.InsecureSkipVerify, //nolint:gosec // operator-configured, documented, and off by default
	}

	var conn net.Conn
	var err error
	if e.cfg.Encryption == encTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("could not connect to the SMTP server at %s: %w", addr, err)
	}
	defer conn.Close()

	if hasDeadline {
		_ = conn.SetDeadline(deadline)
	}

	client, err := smtp.NewClient(conn, e.cfg.Host)
	if err != nil {
		return fmt.Errorf("SMTP handshake failed: %w", err)
	}
	defer client.Close()

	if e.cfg.Encryption == encStartTLS {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			// Not silently downgraded. An operator who asked for STARTTLS and
			// got plaintext has a different problem from one who asked for
			// plaintext, and only one of them knows about it.
			return fmt.Errorf("the SMTP server does not offer STARTTLS; set encryption to \"none\" only if this relay is on a trusted network")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS failed: %w", err)
		}
	}

	if e.cfg.Username != "" {
		auth := smtp.PlainAuth("", e.cfg.Username, e.cfg.Password, e.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	if err := client.Mail(e.cfg.From); err != nil {
		return fmt.Errorf("the server rejected the sender %s: %w", e.cfg.From, err)
	}
	for _, to := range e.cfg.To {
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("the server rejected the recipient %s: %w", to, err)
		}
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("the server refused the message body: %w", err)
	}
	if _, err := writer.Write(message); err != nil {
		return fmt.Errorf("could not write the message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("the server rejected the message: %w", err)
	}

	return client.Quit()
}

// compose builds an RFC 5322 message.
//
// Everything that reaches a header goes through sanitizeHeaderValue first. Alert
// text is derived from certificates CertPilot did not issue, so a CA whose
// common name contains a newline would otherwise be able to inject headers —
// including a second Bcc — into every alert about it.
func (e *emailNotifier) compose(alert Alert) []byte {
	subject := sanitizeHeaderValue(fmt.Sprintf("[CertPilot %s] %s", normalizeSeverity(alert.Severity), alert.Title))

	var b strings.Builder
	fmt.Fprintf(&b, "From: CertPilot <%s>\r\n", e.cfg.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(e.cfg.To, ", "))
	// Q-encoded, so a non-ASCII CA name survives instead of arriving as mojibake.
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s>\r\n", messageID(alert, e.cfg.From))
	// Lets a receiving mail rule route on severity without parsing the body.
	fmt.Fprintf(&b, "X-CertPilot-Severity: %s\r\n", normalizeSeverity(alert.Severity))
	fmt.Fprintf(&b, "X-CertPilot-Topic: %s\r\n", sanitizeHeaderValue(alert.Topic))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")

	fmt.Fprintf(&b, "%s\r\n\r\n", alert.Summary)
	for _, f := range alert.Fields {
		fmt.Fprintf(&b, "%-20s %s\r\n", f.Label+":", f.Value)
	}
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "Event:     %s\r\n", alert.Topic)
	if alert.EntityID != "" {
		fmt.Fprintf(&b, "Entity:    %s\r\n", alert.EntityID)
	}
	fmt.Fprintf(&b, "Occurred:  %s\r\n", alert.Timestamp.UTC().Format(time.RFC1123Z))
	b.WriteString("\r\n-- \r\nSent by CertPilot.\r\n")

	return []byte(b.String())
}

// messageID gives each alert a stable, unique identifier so mail clients thread
// and deduplicate correctly rather than collapsing separate alerts into one.
func messageID(alert Alert, from string) string {
	domain := "certpilot.local"
	if at := strings.LastIndex(from, "@"); at != -1 && at+1 < len(from) {
		domain = from[at+1:]
	}
	return fmt.Sprintf("%d.%s@%s", alert.Timestamp.UnixNano(),
		strings.ReplaceAll(sanitizeHeaderValue(alert.Topic), " ", "-"), domain)
}
