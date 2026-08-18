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
		alert.Fields = []Field{
			{Label: "Common name", Value: fallback(cn, "—")},
			{Label: "Days remaining", Value: daysText(num(payload, "days_remaining"))},
			{Label: "Error", Value: fallback(str(payload, "error"), "—")},
			{Label: "Attempts", Value: countText(num(payload, "renewal_count"))},
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
