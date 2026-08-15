package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/engine/renewal"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/store"
	providerv1 "github.com/certpilot/certpilot/pkg/pb/provider/v1"
	"github.com/certpilot/certpilot/pkg/x509util"
	"github.com/gin-gonic/gin"
)

// CertificateHandler handles certificate management endpoints.
type CertificateHandler struct {
	store     store.Store
	pluginMgr *pluginmgr.Manager
	executor  *renewal.Executor
	policyEng *policy.Engine
}

// NewCertificateHandler creates a new handler.
func NewCertificateHandler(s store.Store, pm *pluginmgr.Manager, exec *renewal.Executor, pe *policy.Engine) *CertificateHandler {
	return &CertificateHandler{
		store:     s,
		pluginMgr: pm,
		executor:  exec,
		policyEng: pe,
	}
}

// List handles GET /api/v1/certificates.
func (h *CertificateHandler) List(c *gin.Context) {
	var filter store.CertificateFilter
	filter.Status = c.Query("status")
	filter.Environment = c.Query("environment")
	filter.CommonName = c.Query("common_name")
	filter.CAAccountID = c.Query("ca_account_id")

	certs, total, err := h.store.ListCertificates(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  certs,
		"total": total,
	})
}

// Get handles GET /api/v1/certificates/:id.
func (h *CertificateHandler) Get(c *gin.Context) {
	id := c.Param("id")
	cert, err := h.store.GetCertificate(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, cert)
}

// RequestCertificateInput defines the payload to request a new certificate.
type RequestCertificateInput struct {
	CommonName      string   `json:"common_name" binding:"required"`
	SANs            []string `json:"sans"`
	CAAccountID     string   `json:"ca_account_id" binding:"required"`
	KeyType         string   `json:"key_type"`
	KeySize         int      `json:"key_size"`
	ValidityDays    int      `json:"validity_days"`
	Environment     string   `json:"environment"`
	Team            string   `json:"team"`
	AutoRenew       bool     `json:"auto_renew"`
	RenewalLeadDays int      `json:"renewal_lead_days"`
}

// Create handles POST /api/v1/certificates (Requests and issues a new certificate).
func (h *CertificateHandler) Create(c *gin.Context) {
	var input RequestCertificateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if input.KeyType == "" {
		input.KeyType = "RSA"
	}
	if input.KeySize <= 0 {
		input.KeySize = 2048
	}
	if input.ValidityDays <= 0 {
		input.ValidityDays = 90
	}
	if input.RenewalLeadDays <= 0 {
		input.RenewalLeadDays = 30
	}

	allDomains := append([]string{input.CommonName}, input.SANs...)

	// 1. Fetch CA account
	caAccount, err := h.store.GetCAAccount(c.Request.Context(), input.CAAccountID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid ca_account_id: %v", err)})
		return
	}

	// 2. Evaluate Policy
	violations, err := h.policyEng.EvaluateRequest(c.Request.Context(), allDomains, input.KeyType, input.KeySize, input.ValidityDays, caAccount.ProviderType)
	if err == nil && len(violations) > 0 {
		for _, v := range violations {
			if v.Severity == "BLOCK" {
				c.JSON(http.StatusForbidden, gin.H{
					"error":      "Certificate request blocked by security policy",
					"violations": violations,
				})
				return
			}
		}
	}

	// 3. Find Gateway
	gw, err := h.pluginMgr.GetGateway(caAccount.Name)
	if err != nil {
		gw, err = h.pluginMgr.GetGateway(caAccount.ProviderType)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("gateway for CA %s is not connected", caAccount.Name)})
			return
		}
	}

	// 4. Request Issuance from Gateway
	issueReq := &providerv1.IssueCertificateRequest{
		Domains:        allDomains,
		KeyType:        input.KeyType,
		KeySize:        int32(input.KeySize),
		ValidityDays:   int32(input.ValidityDays),
		ProviderConfig: caAccount.ConfigEncrypted,
	}

	resp, err := gw.Client.IssueCertificate(c.Request.Context(), issueReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("gateway issuance failed: %v", err)})
		return
	}

	// 5. Store Issued Certificate
	var notBefore, notAfter *time.Time
	var certPEM, chainPEM *string
	serial := ""
	fingerprint := ""
	issuerDN := ""

	if resp.Certificate != nil {
		p := string(resp.Certificate.CertificatePem)
		certPEM = &p
		if len(resp.Certificate.ChainPem) > 0 {
			ch := string(resp.Certificate.ChainPem)
			chainPEM = &ch
		}
		if resp.Certificate.NotBefore != nil {
			nb := resp.Certificate.NotBefore.AsTime()
			notBefore = &nb
		}
		if resp.Certificate.NotAfter != nil {
			na := resp.Certificate.NotAfter.AsTime()
			notAfter = &na
		}
		serial = resp.Certificate.SerialNumber
		issuerDN = resp.Certificate.IssuerDn

		if info, err := x509util.ParseCertificatePEM(resp.Certificate.CertificatePem); err == nil {
			fingerprint = info.FingerprintSHA256
		}
	}

	userID := c.GetString("user_id")
	var createdBy *string
	if userID != "" {
		createdBy = &userID
	}

	certRecord := &store.Certificate{
		FingerprintSHA256: fingerprint,
		CommonName:        input.CommonName,
		SANs:              input.SANs,
		SerialNumber:      serial,
		IssuerDN:          issuerDN,
		NotBefore:         notBefore,
		NotAfter:          notAfter,
		KeyType:           input.KeyType,
		KeySize:           input.KeySize,
		Status:            "ISSUED",
		AutoRenew:         input.AutoRenew,
		RenewalLeadDays:   input.RenewalLeadDays,
		CAAccountID:       &input.CAAccountID,
		CertificatePEM:    certPEM,
		ChainPEM:          chainPEM,
		DiscoveredVia:     "REQUESTED",
		Environment:       input.Environment,
		Team:              input.Team,
		CreatedBy:         createdBy,
	}

	if err := h.store.CreateCertificate(c.Request.Context(), certRecord); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to save certificate to store: %v", err)})
		return
	}

	// 6. Audit Log
	userEmail := c.GetString("user_email")
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "cert.issued",
		EntityType: "certificate",
		EntityID:   &certRecord.ID,
		ActorID:    createdBy,
		ActorEmail: &userEmail,
		Details:    fmt.Sprintf(`{"cn": %q, "gateway": %q}`, input.CommonName, gw.Name),
	})

	c.JSON(http.StatusCreated, certRecord)
}

// Renew handles POST /api/v1/certificates/:id/renew.
func (h *CertificateHandler) Renew(c *gin.Context) {
	id := c.Param("id")
	renewed, err := h.executor.RenewCertificate(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, renewed)
}

// Delete handles DELETE /api/v1/certificates/:id.
func (h *CertificateHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.DeleteCertificate(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "certificate deleted"})
}
