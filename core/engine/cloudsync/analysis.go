package cloudsync

import (
	"fmt"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
)

// Finding codes, stable across releases because dashboards and filters use them.
const (
	FindingWillNotRenew    = "will_not_renew"
	FindingRenewalOverdue  = "renewal_overdue"
	FindingExpired         = "expired"
	FindingExpiringSoon    = "expiring_soon"
	FindingUnattached      = "unattached"
	FindingNoBody          = "no_certificate_body"
	FindingDisabled        = "disabled"
	FindingWeakKey         = "weak_key"
	FindingInventoryFailed = "inventory_lookup_failed"
)

// Windows used to decide how urgent a finding is.
const (
	criticalWindow = 30 * 24 * time.Hour
	warningWindow  = 90 * 24 * time.Hour
	// overdueWindow is how close to expiry a provider that claims to renew a
	// certificate has to get before its claim stops being reassuring.
	overdueWindow = 7 * 24 * time.Hour
)

// assess turns what a provider reported into findings.
//
// Severity tracks *time*, not category. A self-managed certificate with three
// hundred days left is a note; the same certificate with three weeks left is an
// emergency, and it is the same row. Ranking them alike would put a page-worthy
// finding in a list of two hundred identical ones — and a finding that appears
// on every row is the noise that stops people reading the list at all.
func assess(cert *store.CloudCertificate, asset Asset, providerType string, now time.Time) []store.Finding {
	findings := []store.Finding{}

	remaining := time.Duration(0)
	known := cert.NotAfter != nil
	if known {
		remaining = cert.NotAfter.Sub(now)
	}
	expired := known && remaining <= 0

	if expired {
		findings = append(findings, store.Finding{
			Code:     FindingExpired,
			Severity: events.SeverityCritical,
			Detail: fmt.Sprintf("This certificate expired %s ago and is still in %s. Anything still pointed at it is failing now.",
				humanDuration(-remaining), describeLocation(cert)),
		})
	}

	switch {
	case asset.WillRenew != nil && !*asset.WillRenew:
		// The finding this whole package exists for — and raised alongside
		// `expired` rather than instead of it.
		//
		// Found by running this: an expired certificate that nothing renews
		// looked exactly like an expired certificate cert-manager is about to
		// replace on its own. Those need opposite responses, and collapsing
		// them into whichever finding happened to win a switch hid the one that
		// needs a person.
		severity := events.SeverityInfo
		switch {
		case expired || (known && remaining <= criticalWindow):
			severity = events.SeverityCritical
		case known && remaining <= warningWindow:
			severity = events.SeverityWarning
		}
		detail := fmt.Sprintf("Nothing renews this certificate: %s reports it as %q. ",
			providerLabel(providerType), asset.RenewalMode)
		switch {
		case expired:
			detail += "It has already expired, and nothing is going to replace it — somebody has to."
		case known:
			detail += fmt.Sprintf("It expires in %s, and it will simply stop working then unless somebody replaces it by hand.",
				humanDuration(remaining))
		default:
			detail += "It will simply stop working when it expires unless somebody replaces it by hand."
		}
		findings = append(findings, store.Finding{
			Code: FindingWillNotRenew, Severity: severity, Detail: detail,
		})

	case asset.WillRenew != nil && *asset.WillRenew && known && remaining > 0 && remaining <= overdueWindow:
		// The provider says it renews this, and it has not. Worse news than a
		// certificate nobody claimed to be renewing, because the thing
		// everybody is relying on has quietly stopped working.
		findings = append(findings, store.Finding{
			Code:     FindingRenewalOverdue,
			Severity: events.SeverityCritical,
			Detail: fmt.Sprintf("%s reports that it renews this certificate (%s), but it expires in %s and has not been replaced. Automatic renewal has failed and nothing has said so.",
				providerLabel(providerType), asset.RenewalMode, humanDuration(remaining)),
		})

	case asset.WillRenew == nil && known && !expired && remaining <= criticalWindow:
		// Nobody said whether this renews itself, so its expiry is the only
		// thing worth reporting.
		findings = append(findings, store.Finding{
			Code:     FindingExpiringSoon,
			Severity: events.SeverityWarning,
			Detail: fmt.Sprintf("This certificate expires in %s, and %s did not say whether anything renews it.",
				humanDuration(remaining), providerLabel(providerType)),
		})
	}

	// Nothing is using it. Not an emergency, and worth knowing: an unattached
	// certificate is the one nobody notices expiring, and it is also the one
	// somebody reaches for at 2am during an incident.
	if asset.Attached != nil && !*asset.Attached {
		findings = append(findings, store.Finding{
			Code:     FindingUnattached,
			Severity: events.SeverityInfo,
			Detail: fmt.Sprintf("Nothing in %s is using this certificate, so nobody will notice when it expires — and it is still there to be attached to something later.",
				describeLocation(cert)),
		})
	}

	if asset.Disabled {
		findings = append(findings, store.Finding{
			Code:     FindingDisabled,
			Severity: events.SeverityInfo,
			Detail:   "The provider has this certificate disabled. It is still stored, and its private key still exists.",
		})
	}

	// Without a body there is no fingerprint, and without a fingerprint the
	// managed/unmanaged verdict is a guess. Said plainly rather than left for
	// somebody to infer from a blank column.
	if asset.CertificatePEM == "" {
		findings = append(findings, store.Finding{
			Code:     FindingNoBody,
			Severity: events.SeverityWarning,
			Detail: fmt.Sprintf("%s did not return this certificate's body, so it could not be matched against inventory by fingerprint. It is reported as unmanaged because it could not be checked, which is not the same as being unknown.",
				providerLabel(providerType)),
		})
	}

	if cert.KeyType == "RSA" && cert.KeySize > 0 && cert.KeySize < 2048 {
		findings = append(findings, store.Finding{
			Code:     FindingWeakKey,
			Severity: events.SeverityCritical,
			Detail: fmt.Sprintf("RSA-%d is below the 2048-bit minimum every public trust store enforces. Browsers already reject this.",
				cert.KeySize),
		})
	}

	return findings
}

func describeLocation(cert *store.CloudCertificate) string {
	if cert.Location == "" {
		return "the cloud store it was found in"
	}
	return cert.Location
}

func providerLabel(providerType string) string {
	switch providerType {
	case store.CloudProviderAWSACM:
		return "AWS Certificate Manager"
	case store.CloudProviderAzureKeyVault:
		return "Azure Key Vault"
	case store.CloudProviderGCP:
		return "Google Cloud"
	case store.CloudProviderKubernetes:
		return "the cluster"
	default:
		return "the provider"
	}
}

// humanDuration says "3 weeks" rather than "504h0m0s". A finding people read in
// a hurry should not need arithmetic.
func humanDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case days >= 365:
		years := days / 365
		return pluralise(years, "year")
	case days >= 60:
		return pluralise(days/30, "month")
	case days >= 14:
		return pluralise(days/7, "week")
	case days >= 1:
		return pluralise(days, "day")
	default:
		hours := int(d.Hours())
		if hours < 1 {
			return "under an hour"
		}
		return pluralise(hours, "hour")
	}
}

func pluralise(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}
