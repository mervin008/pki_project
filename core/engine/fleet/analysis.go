package fleet

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

// Finding codes, stable across releases because dashboards and filters use them.
const (
	FindingUnmanaged        = "unmanaged"
	FindingExpired          = "expired"
	FindingExpiringSoon     = "expiring_soon"
	FindingKeyReadable      = "private_key_readable"
	FindingKeyMissing       = "private_key_missing"
	FindingKeyMismatch      = "private_key_mismatch"
	FindingSuperseded       = "superseded"
	FindingUnreferenced     = "unreferenced"
	FindingCertificateGroup = "certificate_group_writable"
)

// Windows used to decide how urgent an expiry finding is.
const (
	criticalWindow = 14 * 24 * time.Hour
	warningWindow  = 45 * 24 * time.Hour
)

// assess turns one file on one host into findings.
//
// Severity tracks consequence, not category. Two of these outrank everything
// else in this system and both are things no remote observer can see at all:
// a private key other accounts on the host can read, and a key that does not
// match the certificate beside it.
func assess(c *store.AgentCertificate, configScanWorked bool, superseded *store.Certificate, now time.Time) []store.Finding {
	findings := []store.Finding{}

	// A trust store is a fact, not a finding. The distribution manages those
	// roots and nobody in this organisation is responsible for them; producing
	// a hundred rows about them is how the real findings on this host stop
	// being read.
	if c.Kind == "bundle" {
		return findings
	}

	// The finding this whole component exists for.
	//
	// Mode 0644 on a key file means every account on that machine holds the key
	// to that certificate. Nothing that observes from the network can ever
	// report this — not a scan, not a transparency log, not a cloud API. It
	// takes one stat call from a process on the host, and until now nothing in
	// this system was on the host.
	if c.PrivateKeyPath != "" {
		if exposed, who := readableByOthers(c.PrivateKeyMode); exposed {
			where := c.PrivateKeyPath
			if c.PrivateKeyInSameFile {
				where = c.Path + " (the certificate and its key are in the same file)"
			}
			findings = append(findings, store.Finding{
				Code:     FindingKeyReadable,
				Severity: events.SeverityCritical,
				Detail: fmt.Sprintf(
					"The private key at %s is mode %s, which means %s can read it. Every account that can is holding the key to this certificate, and rotating the certificate does not undo that — it has to be reissued.",
					where, c.PrivateKeyMode, who),
			})
		}
	}

	// A pair that will not load. Quiet until something restarts the service —
	// a deploy, a kernel update, an unrelated outage at three in the morning —
	// and then it is an outage that looks like it came from nowhere.
	if c.PrivateKeyPath != "" && !c.PrivateKeyMatches {
		findings = append(findings, store.Finding{
			Code:     FindingKeyMismatch,
			Severity: events.SeverityCritical,
			Detail: fmt.Sprintf(
				"The key at %s does not match this certificate. Whatever is serving it is running on material it loaded earlier; the next restart will fail, and it will look like it came from nowhere.",
				c.PrivateKeyPath),
		})
	}

	// A leaf with no key is a certificate this host cannot serve. Worth saying
	// once, quietly: it is very often a copy somebody left behind.
	if c.Kind == "leaf" && c.PrivateKeyPath == "" {
		findings = append(findings, store.Finding{
			Code:     FindingKeyMissing,
			Severity: events.SeverityInfo,
			Detail: fmt.Sprintf(
				"No private key was found beside %s, so this host cannot serve this certificate. Most often it is a copy left behind by a migration.",
				c.Path),
		})
	}

	// The connective one. This file holds the certificate a renewal already
	// replaced — which is post-renewal verification's finding arriving from a
	// third direction, and unlike the verifier it needs no scan to have ever
	// reached this host.
	if superseded != nil {
		detail := fmt.Sprintf(
			"This file holds the certificate that %s was renewed away from. CertPilot has the new one; this host still has the old one on disk.",
			superseded.CommonName)
		if len(c.ReferencedBy) > 0 {
			detail += fmt.Sprintf(" It is named in %s, so whatever reads that configuration is serving the certificate this replaced.",
				strings.Join(c.ReferencedBy, ", "))
		}
		findings = append(findings, store.Finding{
			Code:     FindingSuperseded,
			Severity: severityForSuperseded(c),
			Detail:   detail,
		})
	}

	if c.NotAfter != nil {
		remaining := c.NotAfter.Sub(now)
		switch {
		case remaining <= 0:
			findings = append(findings, store.Finding{
				Code:     FindingExpired,
				Severity: expirySeverity(c, events.SeverityWarning),
				Detail: fmt.Sprintf("This certificate expired %s ago and is still at %s.",
					humanFor(-remaining), c.Path),
			})
		case remaining <= criticalWindow:
			findings = append(findings, store.Finding{
				Code:     FindingExpiringSoon,
				Severity: expirySeverity(c, events.SeverityWarning),
				Detail:   fmt.Sprintf("This certificate expires in %s.", humanFor(remaining)),
			})
		case remaining <= warningWindow:
			findings = append(findings, store.Finding{
				Code:     FindingExpiringSoon,
				Severity: events.SeverityInfo,
				Detail:   fmt.Sprintf("This certificate expires in %s.", humanFor(remaining)),
			})
		}
	}

	if c.ManagementState == store.DiscoveryUnmanaged && c.Kind == "leaf" {
		findings = append(findings, store.Finding{
			Code:     FindingUnmanaged,
			Severity: events.SeverityWarning,
			Detail: fmt.Sprintf(
				"CertPilot did not issue this certificate and is not tracking it. Nothing is scheduled to replace it before %s.",
				expiryText(c)),
		})
	}

	// Only when the heuristic worked somewhere on this host. Reporting every
	// file as unreferenced on a host where no configuration was matched would
	// be a finding about this code rather than about the host.
	if configScanWorked && c.Kind == "leaf" && len(c.ReferencedBy) == 0 && c.PrivateKeyPath != "" {
		findings = append(findings, store.Finding{
			Code:     FindingUnreferenced,
			Severity: events.SeverityInfo,
			Detail: fmt.Sprintf(
				"No server configuration on this host was found naming %s. It may be loaded some other way; nothing here proves it is unused.",
				c.Path),
		})
	}

	return findings
}

// expirySeverity raises an expiry finding when something is configured to serve
// the file.
//
// The same date means different things depending on whether anything reads the
// file. An expired certificate nobody references is clutter; an expired
// certificate named in nginx.conf is an outage, and they should not sort
// together.
func expirySeverity(c *store.AgentCertificate, base string) string {
	if len(c.ReferencedBy) > 0 {
		return events.SeverityCritical
	}
	return base
}

func severityForSuperseded(c *store.AgentCertificate) string {
	if len(c.ReferencedBy) > 0 {
		return events.SeverityCritical
	}
	return events.SeverityWarning
}

// readableByOthers reports whether a mode string lets anyone but the owner read
// the file, and says who in words.
//
// Group and world are separated because they are different conversations. World
// readable is indefensible; group readable is often a deliberate choice —
// nginx's worker group, a deploy group — and is still worth knowing about,
// because "deliberate" and "still holds your private key" are both true.
func readableByOthers(mode string) (bool, string) {
	perm, err := strconv.ParseUint(strings.TrimSpace(mode), 8, 32)
	if err != nil {
		return false, ""
	}
	// World subsumes group: saying "any account on the host, and its group"
	// reads as though the group were an additional exposure when it is a subset
	// of one already stated.
	switch {
	case perm&0o004 != 0:
		return true, "any account on the host"
	case perm&0o040 != 0:
		return true, "its group"
	}
	return false, ""
}

func expiryText(c *store.AgentCertificate) string {
	if c.NotAfter == nil {
		return "an unknown date"
	}
	return c.NotAfter.Format("2 January 2006")
}
