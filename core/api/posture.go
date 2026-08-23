package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/engine/posture"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// PostureHandler exposes cryptographic posture and the CBOM export.
type PostureHandler struct {
	store   store.Store
	version string
}

// NewPostureHandler creates the handler.
func NewPostureHandler(s store.Store, version string) *PostureHandler {
	return &PostureHandler{store: s, version: version}
}

// Summary handles GET /api/v1/posture.
//
// The one screen this phase exists to produce, and the ordering of it is the
// whole argument: what is losing something today comes first, and what needs a
// plan for the 2030s comes second. Most reporting on this subject does the
// reverse, because certificate algorithms are easy to collect and negotiated
// key exchanges are not.
func (h *PostureHandler) Summary(c *gin.Context) {
	ctx := c.Request.Context()

	byVerdict, err := h.store.CountTLSPostureByVerdict(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	certs, total, err := h.store.ListCertificates(ctx, store.CertificateFilter{Limit: 1000})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	certVerdicts := map[string]int{}
	weakNow := []gin.H{}
	for _, cert := range certs {
		verdict := cert.PostureVerdict
		if verdict == "" {
			verdict = "UNASSESSED"
		}
		certVerdicts[verdict]++
		if verdict == posture.VerdictWeak {
			weakNow = append(weakNow, gin.H{
				"id": cert.ID, "common_name": cert.CommonName,
				"signature_algorithm": cert.SignatureAlgorithm,
				"detail":              cert.PostureSummary,
			})
		}
	}

	exposed := byVerdict[posture.VerdictExposed]
	hybrid := byVerdict[posture.VerdictHybrid]

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"endpoints":          byVerdict,
			"certificates":       certVerdicts,
			"total_certificates": total,
			// Named for what it is rather than "at risk". These are
			// certificates with a problem today that has nothing to do with
			// quantum computing, and burying them under the post-quantum
			// material would be this product's founding complaint committed by
			// this product.
			"weak_now": weakNow,
		},
		"headline": headline(exposed, hybrid, len(weakNow)),
	})
}

// headline is the sentence.
//
// Deliberately about key exchange rather than certificates. Nobody forges a
// handshake that already happened, so an estate of RSA certificates is a plan;
// an estate of endpoints negotiating X25519 is traffic being recorded now.
func headline(exposed, hybrid int64, weak int) string {
	parts := []string{}

	switch {
	case exposed+hybrid == 0:
		parts = append(parts, "No endpoint has been scanned yet, so nothing is known about what this estate negotiates.")
	case exposed == 0:
		parts = append(parts, fmt.Sprintf(
			"All %d scanned %s negotiate a post-quantum key exchange, so traffic to them cannot be recorded now and decrypted later.",
			hybrid, pick(hybrid, "endpoint", "endpoints")))
	default:
		parts = append(parts, fmt.Sprintf(
			"%d of %d scanned %s do not negotiate a post-quantum key exchange. Traffic to them can be recorded today and decrypted whenever a quantum computer arrives — and unlike certificate algorithms, that is a cost being paid now rather than a deadline in the 2030s.",
			exposed, exposed+hybrid, pick(exposed+hybrid, "endpoint", "endpoints")))
	}

	if weak > 0 {
		parts = append(parts, fmt.Sprintf(
			"Separately, %d %s a signature or key that is weak against ordinary computers today; that is not a quantum problem and should be fixed first.",
			weak, pick(int64(weak), "certificate has", "certificates have")))
	}
	return strings.Join(parts, " ")
}

// Endpoints handles GET /api/v1/posture/endpoints.
//
// `?exposed=true` is the list somebody acts on: endpoints that were offered a
// post-quantum group and did not take it.
func (h *PostureHandler) Endpoints(c *gin.Context) {
	filter := store.EndpointTLSPostureFilter{
		Host:    c.Query("host"),
		Verdict: strings.ToUpper(strings.TrimSpace(c.Query("verdict"))),
		Limit:   100,
	}
	if c.Query("exposed") == "true" {
		filter.ExposedOnly = true
	}
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 {
		filter.Limit = v
	}
	if v, err := strconv.Atoi(c.Query("offset")); err == nil && v > 0 {
		filter.Offset = v
	}

	rows, total, err := h.store.ListEndpointTLSPosture(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "total": total})
}

// CBOM handles GET /api/v1/posture/cbom.
//
// CycloneDX 1.6, because the point of a CBOM is that something other than
// CertPilot reads it. Algorithms are emitted once and referenced by every
// certificate that uses them, so "what does moving off SHA-256 touch" is a
// graph query rather than a search.
func (h *PostureHandler) CBOM(c *gin.Context) {
	ctx := c.Request.Context()

	certs, _, err := h.store.ListCertificates(ctx, store.CertificateFilter{Limit: 1000})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	endpoints, _, err := h.store.ListEndpointTLSPosture(ctx, store.EndpointTLSPostureFilter{Limit: 500})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Where each certificate has actually been observed. A CBOM listing a
	// certificate says you have it; a CBOM saying which load balancer is
	// serving it says what has to change.
	locations := map[string][]string{}
	for _, e := range endpoints {
		if e.CertificateID != nil {
			locations[*e.CertificateID] = append(locations[*e.CertificateID],
				fmt.Sprintf("%s:%d", e.Host, e.Port))
		}
	}

	inputs := make([]posture.CertificateInput, 0, len(certs))
	for _, cert := range certs {
		input := posture.CertificateInput{
			ID: cert.ID, CommonName: cert.CommonName,
			IssuerDN:           cert.IssuerDN,
			KeyType:            cert.KeyType,
			KeySize:            cert.KeySize,
			SignatureAlgorithm: cert.SignatureAlgorithm,
			Verdict:            cert.PostureVerdict,
			Locations:          locations[cert.ID],
		}
		if cert.NotBefore != nil {
			input.NotBefore = *cert.NotBefore
		}
		if cert.NotAfter != nil {
			input.NotAfter = *cert.NotAfter
		}
		inputs = append(inputs, input)
	}

	observed := make([]posture.EndpointInput, 0, len(endpoints))
	for _, e := range endpoints {
		observed = append(observed, posture.EndpointInput{
			Host: e.Host, Port: e.Port,
			TLSVersion: e.TLSVersion, CipherSuite: e.CipherSuite,
			KeyExchangeGroup: e.KeyExchangeGroup, Hybrid: e.HybridKeyExchange,
			Verdict: e.Verdict,
		})
	}

	bom := posture.Build(h.version, inputs, observed, time.Now())
	c.Header("Content-Disposition", `attachment; filename="certpilot-cbom.cdx.json"`)
	c.JSON(http.StatusOK, bom)
}
