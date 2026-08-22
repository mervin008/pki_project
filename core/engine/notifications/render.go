package notifications

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/events"
)

// AlertFromEvent turns a published event into something worth reading.
//
// Done once, centrally, so Slack, email, and a webhook receiver all describe the
// same event the same way. Three channels wording an alert differently is how an
// on-call engineer ends up comparing a Slack message with an email instead of
// acting on either of them.
//
// An unrecognised topic still produces an alert. Topics are added by producers
// over time, and a dispatcher that silently drops what it does not recognise
// would turn every new event type into a coverage gap that nothing reports.
func AlertFromEvent(evt events.Event) Alert {
	payload := payloadMap(evt.Payload)

	alert := Alert{
		Severity:  normalizeSeverity(evt.Severity),
		Topic:     evt.Topic,
		EntityID:  evt.EntityID,
		Timestamp: evt.Timestamp,
	}
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now()
	}

	switch evt.Topic {
	case events.TopicCAExpiryAlert:
		name := str(payload, "ca_name")
		days := num(payload, "days_remaining")
		alert.Title = fmt.Sprintf("CA expiring: %s", fallback(name, "unnamed authority"))
		alert.Summary = expirySentence(name, days, str(payload, "ca_type"))
		alert.Fields = []Field{
			{Label: "Authority", Value: fallback(name, "—")},
			{Label: "Type", Value: fallback(str(payload, "ca_type"), "—")},
			{Label: "Days remaining", Value: daysText(days)},
			{Label: "Expires", Value: dateText(str(payload, "not_after"))},
			{Label: "Threshold crossed", Value: thresholdText(payload)},
		}

	case events.TopicCAHealth:
		name := str(payload, "ca_name")
		from, to := str(payload, "previous_status"), str(payload, "status")
		alert.Title = fmt.Sprintf("CA health changed: %s is %s", fallback(name, "a CA"), fallback(to, "unknown"))
		alert.Summary = fmt.Sprintf("%s moved from %s to %s.",
			fallback(name, "A certificate authority"), fallback(from, "an earlier state"), fallback(to, "an unknown state"))
		alert.Fields = []Field{
			{Label: "Authority", Value: fallback(name, "—")},
			{Label: "Previous status", Value: fallback(from, "—")},
			{Label: "Current status", Value: fallback(to, "—")},
			{Label: "Days remaining", Value: daysText(num(payload, "days_remaining"))},
		}

	case events.TopicCertRenewFail:
		cn := str(payload, "common_name")
		alert.Title = fmt.Sprintf("Renewal failed: %s", fallback(cn, "a certificate"))
		// Named as the thing it will become, because that is the part that
		// matters: a failed renewal is an expiry with a delay on it.
		alert.Summary = fmt.Sprintf(
			"%s could not be renewed and will expire unless this is resolved.",
			fallback(cn, "A certificate"))

		// A renewal blocked by a quota that outlasts the certificate is a
		// different message, because it needs a different action. Nothing is
		// broken and retrying will not help — somebody has to raise the limit,
		// move the certificate to another account, or stop renewing something
		// else. Saying "renewal failed, retrying" would send them looking for
		// a fault that does not exist.
		if blocked := str(payload, "blocked_by"); blocked != "" {
			alert.Title = fmt.Sprintf("Renewal blocked until after expiry: %s", fallback(cn, "a certificate"))
			alert.Summary = fmt.Sprintf(
				"%s cannot be renewed because %s is full until %s, and it expires on %s. Retrying will not fix this: the limit has to be raised, or this certificate moved to another CA account.",
				fallback(cn, "A certificate"), blocked,
				dateText(str(payload, "blocked_until")), dateText(str(payload, "not_after")))
			alert.Fields = []Field{
				{Label: "Common name", Value: fallback(cn, "—")},
				{Label: "Expires", Value: dateText(str(payload, "not_after"))},
				{Label: "Limit frees up", Value: dateText(str(payload, "blocked_until"))},
				{Label: "Blocked by", Value: blocked},
			}
			break
		}

		alert.Fields = []Field{
			{Label: "Common name", Value: fallback(cn, "—")},
			{Label: "Days remaining", Value: daysText(num(payload, "days_remaining"))},
			{Label: "Error", Value: fallback(str(payload, "error"), "—")},
			// The queue's count, not the certificate's lifetime renewal_count.
			// This alert fires once when a renewal stops being a blip, so how
			// many times it has already failed is the fact that says whether
			// this is a hiccup or a fortnight of the same error.
			{Label: "Failed attempts", Value: countText(num(payload, "attempts"))},
		}

	case events.TopicCertRenewalWindowMoved:
		cn := str(payload, "common_name")
		hours := int(num(payload, "moved_by_hours"))
		alert.Title = fmt.Sprintf("%s: the CA wants this replaced sooner", fallback(cn, "A certificate"))
		// Worded as what it means, not what changed. "The renewal window moved"
		// is a fact about a JSON field; a CA bringing a window forward is the
		// CA telling you something is wrong with a certificate it issued, and
		// during a mass revocation it is the only automated warning there is.
		alert.Summary = fmt.Sprintf(
			"%s has brought this certificate's renewal window forward by about %s. A CA does that when something is wrong with a certificate it issued — most often a bulk revocation. CertPilot has rescheduled the renewal; check the explanation before assuming it is routine.",
			fallback(issuerShortName(str(payload, "issuer_dn")), "The CA"),
			humanHours(hours))
		alert.Fields = []Field{
			{Label: "Common name", Value: fallback(cn, "—")},
			{Label: "Renewing at", Value: momentText(str(payload, "renew_at"))},
			{Label: "Brought forward by", Value: humanHours(hours)},
			{Label: "Explanation", Value: fallback(str(payload, "explanation_url"), "the CA gave none")},
		}

	case events.TopicCertNotDeployed:
		cn := str(payload, "common_name")
		alert.Title = fmt.Sprintf("Renewed, but not deployed: %s", fallback(cn, "a certificate"))
		// Named as the consequence, not as a failed check. "Verification
		// failed" is a fact about a checker; this is the outage a renewal
		// engine exists to prevent, arriving through one — the inventory says
		// the certificate is fine and the server is still on the old one.
		alert.Summary = fmt.Sprintf(
			"%s was renewed successfully, and the server is still presenting the certificate it replaced. CertPilot's record looks healthy; what users get expires on the old schedule. The new certificate has to be installed.",
			fallback(cn, "A certificate"))
		alert.Fields = []Field{
			{Label: "Common name", Value: fallback(cn, "—")},
			{Label: "Still on the old certificate", Value: fallback(listText(payload, "endpoints"), "—")},
			{Label: "New certificate expires", Value: dateText(str(payload, "not_after"))},
		}

	case events.TopicCertDeployed:
		cn := str(payload, "common_name")
		target := fallback(str(payload, "target"), "a target")
		alert.Title = fmt.Sprintf("Certificate deployed: %s", fallback(cn, "unnamed"))
		// Says what happened and not one word more. The target accepted the
		// certificate; whether the process in front of the users has picked it
		// up is a different question, and a message that blurred the two would
		// be this product telling the reassuring half of the story.
		alert.Summary = fmt.Sprintf("%s was installed at %s and accepted.",
			fallback(cn, "A certificate"), target)
		alert.Fields = []Field{
			{Label: "Common name", Value: fallback(cn, "—")},
			{Label: "Target", Value: target},
			{Label: "Where", Value: fallback(str(payload, "where"), "—")},
		}

	case events.TopicCertDeployFailed:
		cn := str(payload, "common_name")
		target := fallback(str(payload, "target"), "a target")
		alert.Title = fmt.Sprintf("Cannot install %s at %s", fallback(cn, "a certificate"), target)
		// Phrased around the certificate's clock, because that is what makes
		// this urgent. A deployment that keeps failing is not an integration
		// annoyance; it is a certificate that exists, is valid, and is not
		// where it needs to be, running down the same schedule as one that was
		// never renewed at all.
		alert.Summary = fmt.Sprintf(
			"%s has failed to install at %s %s. The certificate is fine; what is serving it is not being updated, so it expires on the schedule of whatever is there now.",
			fallback(cn, "A certificate"), target, attemptsText(num(payload, "attempts")))
		alert.Fields = []Field{
			{Label: "Common name", Value: fallback(cn, "—")},
			{Label: "Target", Value: target},
			{Label: "Certificate expires", Value: dateText(str(payload, "not_after"))},
			{Label: "Last error", Value: fallback(str(payload, "error"), "—")},
		}

	case events.TopicAgentStale:
		name := fallback(str(payload, "name"), "a host")
		alert.Title = fmt.Sprintf("Agent has gone quiet: %s", name)
		// Named as the consequence, not the observation. "Agent offline" is a
		// fact about a process; what somebody has to act on is that a machine
		// still has certificates on it, still has them expiring, and now has
		// nothing maintaining them — while looking exactly like a healthy host
		// on any screen that counts enrolled agents.
		alert.Summary = fmt.Sprintf(
			"%s has not reported for %s, having promised every %s. Whatever certificates are on that host are still being served and are no longer being maintained; they expire on their own schedule with nothing scheduled to replace them.",
			name, fallback(str(payload, "missing_for"), "some time"),
			fallback(str(payload, "promised"), "its configured interval"))
		alert.Fields = []Field{
			{Label: "Agent", Value: name},
			{Label: "Hostname", Value: fallback(str(payload, "hostname"), "—")},
			{Label: "Last reported", Value: fallback(str(payload, "last_seen"), "—")},
			{Label: "Last seen from", Value: fallback(str(payload, "last_seen_ip"), "—")},
		}

	case events.TopicAgentEnrolled:
		name := fallback(str(payload, "name"), "a host")
		alert.Title = fmt.Sprintf("Agent enrolled: %s", name)
		// Routine, and worth saying anyway. The abnormal case is identical
		// until somebody reads it: an agent joining from an address nobody
		// recognises, on a token issued for a different rollout, is what a
		// stolen bootstrap credential looks like.
		alert.Summary = fmt.Sprintf("%s joined from %s using the enrolment token %q.",
			name, fallback(str(payload, "from"), "an unknown address"),
			fallback(str(payload, "token"), "unknown"))
		alert.Fields = []Field{
			{Label: "Agent", Value: name},
			{Label: "Platform", Value: fallback(str(payload, "platform"), "—")},
			{Label: "Enrolled from", Value: fallback(str(payload, "from"), "—")},
			{Label: "Key", Value: fallback(str(payload, "key_id"), "—")},
		}

	case events.TopicAgentKeyExposed:
		host := fallback(str(payload, "agent"), "a host")
		count := int(num(payload, "count"))
		alert.Title = fmt.Sprintf("Private key readable on %s", host)
		// The one finding in this system that no remote observer could ever
		// have made, and the one where rotating the certificate does not fix
		// it. Said in those terms, because the instinct on reading "key
		// exposure" is to renew, and renewing leaves the exposure exactly
		// where it was.
		subject, verb := "A certificate file", "has"
		if count > 1 {
			subject, verb = fmt.Sprintf("%d certificate files", count), "have"
		}
		alert.Summary = fmt.Sprintf(
			"%s on %s %s a private key that other accounts on that host can read. Every account that can is holding that key: reissuing is the fix, and renewing is not — nor is changing the file mode after the fact.",
			subject, host, verb)
		alert.Fields = []Field{
			{Label: "Host", Value: host},
			{Label: "Hostname", Value: fallback(str(payload, "hostname"), "—")},
			{Label: "Files", Value: fallback(listText(payload, "paths"), "—")},
			{Label: "Detail", Value: fallback(str(payload, "detail"), "—")},
		}

	case events.TopicAgentKeyMismatch:
		host := fallback(str(payload, "agent"), "a host")
		count := int(num(payload, "count"))
		alert.Title = fmt.Sprintf("Certificate and key do not match on %s", host)
		// Not a security problem, and not urgent in the way an expiry is. It is
		// an outage waiting for an unrelated restart — which is why it reads as
		// a prediction rather than an observation.
		if count > 1 {
			alert.Summary = fmt.Sprintf(
				"%d certificate files on %s have private keys that do not belong to them. Whatever is serving them is running on material it loaded earlier; the next restart will fail, and it will look like it came from nowhere.",
				count, host)
		} else {
			alert.Summary = fmt.Sprintf(
				"A certificate file on %s has a private key that does not belong to it. Whatever is serving it is running on material it loaded earlier; the next restart will fail, and it will look like it came from nowhere.",
				host)
		}
		alert.Fields = []Field{
			{Label: "Host", Value: host},
			{Label: "Hostname", Value: fallback(str(payload, "hostname"), "—")},
			{Label: "Files", Value: fallback(listText(payload, "paths"), "—")},
		}

	case events.TopicAgentUnmanaged:
		host := fallback(str(payload, "agent"), "a host")
		count := int(num(payload, "count"))
		alert.Title = fmt.Sprintf("Certificates on %s that CertPilot did not issue", host)
		if count > 1 {
			alert.Summary = fmt.Sprintf(
				"%d certificate files on %s were not issued by CertPilot and are not being tracked. Nothing is scheduled to replace them.",
				count, host)
		} else {
			alert.Summary = fmt.Sprintf(
				"A certificate file on %s was not issued by CertPilot and is not being tracked. Nothing is scheduled to replace it.",
				host)
		}
		alert.Fields = []Field{
			{Label: "Host", Value: host},
			{Label: "Names", Value: fallback(listText(payload, "names"), "—")},
			{Label: "Files", Value: fallback(listText(payload, "paths"), "—")},
		}

	case events.TopicAgentRequestRefused:
		host := fallback(str(payload, "agent"), "a host")
		names := fallback(listText(payload, "names"), "a name")
		alert.Title = fmt.Sprintf("%s asked for a certificate it is not allowed", host)
		// Phrased as two possibilities on purpose, because from inside the
		// process they are indistinguishable and only a person can tell them
		// apart. Picking one — "misconfiguration" — would be the reassuring
		// half of the story, and picking the other would cry wolf every time
		// somebody typoed a hostname.
		alert.Summary = fmt.Sprintf(
			"%s requested %s and no grant permits it. Either the grant is wrong and somebody has a deployment that will not come up, or this host's credential is being used by somebody who should not have it.",
			host, names)
		alert.Fields = []Field{
			{Label: "Host", Value: host},
			{Label: "Hostname", Value: fallback(str(payload, "hostname"), "—")},
			{Label: "Asked for", Value: names},
			{Label: "Refused because", Value: fallback(str(payload, "reason"), "—")},
		}

	case events.TopicAgentInstallFailed:
		host := fallback(str(payload, "agent"), "a host")
		where := fallback(str(payload, "destination"), "a destination")
		cn := fallback(str(payload, "common_name"), "a certificate")
		alert.Title = fmt.Sprintf("Could not install %s on %s", cn, host)
		// Two sentences, and which second sentence appears is the whole point.
		// A rollback means the listener is still serving what it was; no
		// rollback means nobody knows what it is serving.
		if boolean(payload, "rolled_back") {
			alert.Summary = fmt.Sprintf(
				"%s could not install %s at %s, and put back what was there before. That destination is still serving the older certificate, so this is a deployment to fix rather than an outage to attend to.",
				host, cn, where)
		} else {
			alert.Summary = fmt.Sprintf(
				"%s could not install %s at %s and could not put back what was there before. Whatever reads those files may now be serving material this host did not intend to install.",
				host, cn, where)
		}
		alert.Fields = []Field{
			{Label: "Host", Value: host},
			{Label: "Destination", Value: where},
			{Label: "Certificate", Value: cn},
			{Label: "Previous certificate restored", Value: yesNo(boolean(payload, "rolled_back"))},
			{Label: "Failed because", Value: fallback(str(payload, "error"), "—")},
		}

	case events.TopicAgentInstallUnfulfilled:
		host := fallback(str(payload, "agent"), "a host")
		names := fallback(listText(payload, "names"), "a certificate")
		alert.Title = fmt.Sprintf("%s is configured to install a certificate it does not have", host)
		alert.Summary = fmt.Sprintf(
			"%s declares somewhere to install %s and holds no such certificate. Nothing is failing yet, and nothing will happen when the renewal it is waiting for arrives — check the name against the grant, because this is usually one character.",
			host, names)
		alert.Fields = []Field{
			{Label: "Host", Value: host},
			{Label: "Hostname", Value: fallback(str(payload, "hostname"), "—")},
			{Label: "Declared for", Value: names},
			{Label: "Destinations", Value: fallback(listText(payload, "destinations"), "—")},
		}

	case events.TopicCertExpiring:
		cn := str(payload, "common_name")
		alert.Title = fmt.Sprintf("Certificate expiring: %s", fallback(cn, "unnamed"))
		alert.Summary = fmt.Sprintf("%s expires in %s.",
			fallback(cn, "A certificate"), daysText(num(payload, "days_remaining")))
		alert.Fields = []Field{
			{Label: "Common name", Value: fallback(cn, "—")},
			{Label: "Days remaining", Value: daysText(num(payload, "days_remaining"))},
			{Label: "Expires", Value: dateText(str(payload, "not_after"))},
		}

	case events.TopicCertIssued, events.TopicCertRenewed:
		cn := str(payload, "common_name")
		verb := "issued"
		if evt.Topic == events.TopicCertRenewed {
			verb = "renewed"
		}
		alert.Title = fmt.Sprintf("Certificate %s: %s", verb, fallback(cn, "unnamed"))
		alert.Summary = fmt.Sprintf("%s was %s.", fallback(cn, "A certificate"), verb)
		alert.Fields = []Field{
			{Label: "Common name", Value: fallback(cn, "—")},
			{Label: "Expires", Value: dateText(str(payload, "not_after"))},
			{Label: "Gateway", Value: fallback(str(payload, "gateway"), "—")},
		}

	case events.TopicDiscoveryUnmanaged:
		count := int(num(payload, "unmanaged_count"))
		alert.Title = fmt.Sprintf("Discovery found %d unmanaged certificate(s)", count)
		// Says what the finding means rather than what happened. "A scan
		// completed" is not actionable; "nothing renews these" is.
		alert.Summary = fmt.Sprintf(
			"A scan of %s endpoints found %d serving certificates CertPilot does not manage. Nothing renews them and nobody is watching them expire.",
			countText(num(payload, "scanned_count")), count)
		alert.Fields = []Field{
			{Label: "Unmanaged", Value: countText(num(payload, "unmanaged_count"))},
			{Label: "Endpoints scanned", Value: countText(num(payload, "scanned_count"))},
			{Label: "Hosts", Value: fallback(listText(payload, "hosts"), "—")},
		}

	case events.TopicDiscoveryChanged:
		changed := int(num(payload, "changed_count"))
		gone := int(num(payload, "disappeared_count"))

		// Composed from the parts that actually happened.
		//
		// A fixed sentence covering both would open "0 endpoints are serving a
		// different certificate … so something is renewing certificates outside
		// this system", which asserts a claim about zero things and then draws
		// a conclusion from it. Reading one of those teaches people that this
		// alert's words do not mean anything.
		var titleParts, summaryParts []string
		if changed > 0 {
			titleParts = append(titleParts, fmt.Sprintf("%d certificate(s) changed", changed))
			// Says who, not what: a certificate rotating on an endpoint nobody
			// manages means somebody out there knows how to replace it, and
			// that person is the point of the alert.
			summaryParts = append(summaryParts, fmt.Sprintf(
				"%d endpoint(s) are serving a different certificate than last time and CertPilot manages none of them, so something is renewing certificates outside this system.",
				changed))
		}
		if gone > 0 {
			titleParts = append(titleParts, fmt.Sprintf("%d endpoint(s) gone", gone))
			summaryParts = append(summaryParts, fmt.Sprintf(
				"%d endpoint(s) that used to answer no longer do — either they moved and the scan no longer covers them, or they are down.",
				gone))
		}
		alert.Title = "Discovery: " + strings.Join(titleParts, ", ")
		alert.Summary = strings.Join(summaryParts, " ")

		alert.Fields = []Field{{Label: "Endpoints scanned", Value: countText(num(payload, "scanned_count"))}}
		if changed > 0 {
			alert.Fields = append(alert.Fields,
				Field{Label: "Changed", Value: fallback(listText(payload, "changed_hosts"), "—")})
		}
		if gone > 0 {
			alert.Fields = append(alert.Fields,
				Field{Label: "No longer answering", Value: fallback(listText(payload, "disappeared_hosts"), "—")})
		}

	case events.TopicCTUnmanaged:
		domain := str(payload, "domain")
		count := int(num(payload, "unmanaged_count"))
		alert.Title = fmt.Sprintf("Certificate issued for %s that you do not manage", fallback(domain, "a watched domain"))
		// The strongest wording in the system, because this is the strongest
		// signal in it. An unmanaged certificate on an endpoint may be one
		// somebody forgot to register; an unmanaged certificate in a public log
		// is one that exists, is valid for your domain, and whose private key
		// is held by somebody who did not get it from here.
		alert.Summary = fmt.Sprintf(
			"%d certificate(s) valid for %s appeared in Certificate Transparency and CertPilot did not issue them. Somebody holds their private keys. Either an internal team obtained them outside this system, or they were not obtained by your organisation at all.",
			count, fallback(domain, "a watched domain"))
		alert.Fields = []Field{
			{Label: "Domain", Value: fallback(domain, "—")},
			{Label: "Unmanaged", Value: countText(num(payload, "unmanaged_count"))},
			{Label: "Certificates", Value: fallback(listText(payload, "certificates"), "—")},
			{Label: "Source", Value: fallback(str(payload, "source"), "—")},
		}

	case events.TopicCloudUnmanaged:
		count := int(num(payload, "unmanaged_count"))
		conn := fallback(str(payload, "connection"), "a cloud account")
		alert.Title = fmt.Sprintf("%d certificate(s) in %s that you do not manage", count, conn)
		alert.Summary = fmt.Sprintf(
			"%d certificate(s) are stored in %s and CertPilot did not put them there. They are not being served on anything it scans, so nothing else would have found them.",
			count, conn)
		alert.Fields = []Field{
			{Label: "Connection", Value: conn},
			{Label: "Provider", Value: providerText(str(payload, "provider"))},
			{Label: "Unmanaged", Value: countText(num(payload, "unmanaged_count"))},
			{Label: "Certificates", Value: fallback(listText(payload, "certificates"), "—")},
		}

	case events.TopicCloudWillNotRenew:
		count := int(num(payload, "count"))
		conn := fallback(str(payload, "connection"), "a cloud account")
		provider := providerText(str(payload, "provider"))
		alert.Title = fmt.Sprintf("%d certificate(s) in %s that nothing will renew", count, conn)
		// The point is the mismatch between what the provider does and what
		// everybody assumes it does. Saying "expiring soon" would describe a
		// certificate; saying this describes a belief that is about to fail.
		alert.Summary = fmt.Sprintf(
			"%s itself reports that it does not renew %d certificate(s) in %s. They expire on their own schedule and stop working, and the console shows them as healthy until they do.",
			provider, count, conn)
		alert.Fields = []Field{
			{Label: "Connection", Value: conn},
			{Label: "Provider", Value: provider},
			{Label: "Not renewing", Value: countText(num(payload, "count"))},
			{Label: "Certificates", Value: fallback(listText(payload, "certificates"), "—")},
		}

	case events.TopicGatewayStatus:
		name := str(payload, "name")
		alert.Title = fmt.Sprintf("Gateway %s", fallback(str(payload, "status"), "status changed"))
		alert.Summary = fmt.Sprintf("Gateway %s reported %s.",
			fallback(name, "—"), fallback(str(payload, "status"), "a status change"))
		alert.Fields = []Field{
			{Label: "Gateway", Value: fallback(name, "—")},
			{Label: "Status", Value: fallback(str(payload, "status"), "—")},
			{Label: "Error", Value: fallback(str(payload, "error"), "—")},
		}

	default:
		alert.Title = fmt.Sprintf("CertPilot event: %s", evt.Topic)
		alert.Summary = fmt.Sprintf(
			"An event of type %q was published. CertPilot has no specific wording for it yet, so the raw detail follows.",
			evt.Topic)
		alert.Fields = unknownFields(payload)
	}

	alert.Title = sanitizeHeaderValue(alert.Title)
	alert.Fields = dropEmpty(alert.Fields)
	return alert
}

// expirySentence states the consequence, not just the fact.
//
// "Corporate Issuing CA expires in 9 days" is a fact. An issuing CA expiring
// invalidates every certificate it ever signed, and the person reading this at
// 2am should not have to remember that.
func expirySentence(name string, days float64, caType string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s expires in %s.", fallback(name, "A certificate authority"), daysText(days))

	switch strings.ToUpper(caType) {
	case "ISSUING", "INTERMEDIATE":
		b.WriteString(" Every certificate it has issued stops validating when it does.")
	case "ROOT":
		b.WriteString(" Everything beneath it in the hierarchy stops validating when it does.")
	}
	return b.String()
}

// payloadMap normalises a payload to a map regardless of how it was published.
//
// In-process the broker carries the producer's original struct, but the same
// event reaches an SSE client as JSON. Round-tripping means this code reads one
// shape and cannot drift from what a webhook receiver sees.
func payloadMap(payload any) map[string]any {
	if payload == nil {
		return map[string]any{}
	}
	if m, ok := payload.(map[string]any); ok {
		return m
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func str(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func num(m map[string]any, key string) float64 {
	switch v := m[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case json.Number:
		f, _ := v.Float64()
		return f
	default:
		// NaN rather than 0, so "the payload had no days_remaining" stays
		// distinguishable from "it expires today". Rendering the second when
		// the truth is the first would be a fabricated alert.
		return math.NaN()
	}
}

func isNumber(f float64) bool { return !math.IsNaN(f) }

func daysText(days float64) string {
	if !isNumber(days) {
		return "unknown"
	}
	n := int(days)
	switch {
	case n < 0:
		return fmt.Sprintf("expired %d days ago", -n)
	case n == 0:
		return "today"
	case n == 1:
		return "1 day"
	default:
		return fmt.Sprintf("%d days", n)
	}
}

func countText(v float64) string {
	if !isNumber(v) {
		return "—"
	}
	return fmt.Sprintf("%d", int(v))
}

func thresholdText(payload map[string]any) string {
	t := num(payload, "threshold")
	if !isNumber(t) {
		return "—"
	}
	return fmt.Sprintf("%d-day threshold", int(t))
}

// dateText renders an RFC 3339 timestamp as a date, or passes it through when it
// is not one. Showing the raw value beats showing "—" for a field that clearly
// held something.
func dateText(value string) string {
	if value == "" {
		return "—"
	}
	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return value
	}
	return ts.Format("2 January 2006")
}

// listText renders a payload field that holds a list of strings, which is how
// a discovery alert names the hosts it found. Truncated rather than dropped: a
// Slack message listing four hundred hosts is one nobody reads to the end.
// boolean reads a flag out of a payload that has been through JSON, where a
// bool may arrive as a bool or as the string "true".
func boolean(m map[string]any, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	}
	return false
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func listText(payload map[string]any, key string) string {
	raw, ok := payload[key].([]any)
	if !ok {
		if strs, ok := payload[key].([]string); ok {
			return joinTruncated(strs, 8)
		}
		return ""
	}
	items := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			items = append(items, s)
		}
	}
	return joinTruncated(items, 8)
}

func joinTruncated(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:max], ", "), len(items)-max)
}

func fallback(value, or string) string {
	if strings.TrimSpace(value) == "" {
		return or
	}
	return value
}

// unknownFields renders an unrecognised payload in a stable order, so the same
// event does not produce differently ordered alerts on different runs.
func unknownFields(payload map[string]any) []Field {
	keys := make([]string, 0, len(payload))
	for k := range payload {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fields := make([]Field, 0, len(keys))
	for _, k := range keys {
		fields = append(fields, Field{Label: k, Value: fmt.Sprint(payload[k])})
	}
	return fields
}

// dropEmpty removes fields whose value carries nothing.
//
// A wall of "Error: —" makes the fields that do hold something harder to find,
// and an alert nobody reads carefully is an alert that fails at its one job.
func dropEmpty(fields []Field) []Field {
	kept := make([]Field, 0, len(fields))
	for _, f := range fields {
		v := strings.TrimSpace(f.Value)
		if v == "" || v == "—" {
			continue
		}
		f.Value = sanitizeHeaderValue(v)
		kept = append(kept, f)
	}
	return kept
}

// providerText turns a stored provider identifier into the name people use for
// it. "aws_acm" in a Slack message reads as a database column, not a product.
func providerText(provider string) string {
	switch provider {
	case "aws_acm":
		return "AWS Certificate Manager"
	case "azure_key_vault":
		return "Azure Key Vault"
	case "gcp":
		return "Google Cloud"
	case "kubernetes":
		return "Kubernetes"
	case "":
		return "—"
	default:
		return provider
	}
}

// humanHours says "3 days" rather than "72 hours".
func humanHours(hours int) string {
	switch {
	case hours >= 48:
		return fmt.Sprintf("%d days", hours/24)
	case hours == 1:
		return "1 hour"
	default:
		return fmt.Sprintf("%d hours", hours)
	}
}

// issuerShortName pulls the CA's common name out of a full issuer DN, so an
// alert reads "R11" rather than "C=US, O=Let's Encrypt, CN=R11".
func issuerShortName(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return strings.TrimSpace(part[3:])
		}
	}
	return dn
}

// momentText renders a date *and* time.
//
// dateText is right for an expiry, which is a day. It is wrong for a renewal a
// CA has just brought forward: rendering "18 August 2026" for something
// happening in fifty-five minutes makes an imminent action read like a
// whole-day one, which during a revocation is the difference between acting now
// and acting tomorrow.
func momentText(value string) string {
	if value == "" {
		return "—"
	}
	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return value
	}
	return ts.Local().Format("2 January 2006, 15:04 MST")
}

// attemptsText phrases a repeat count the way somebody would say it.
//
// "failed 1 times" is the kind of sentence that makes a reader stop trusting
// everything else in the message.
func attemptsText(attempts float64) string {
	n := int(attempts)
	switch {
	case n <= 1:
		return "once"
	case n == 2:
		return "twice"
	default:
		return fmt.Sprintf("%d times", n)
	}
}
