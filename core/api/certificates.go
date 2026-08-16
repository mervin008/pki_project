package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/certpilot/certpilot/core/engine/policy"
	"github.com/certpilot/certpilot/core/engine/renewal"
	"github.com/certpilot/certpilot/core/pluginmgr"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	providerv1 "github.com/certpilot/certpilot/pkg/pb/provider/v1"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/certpilot/certpilot/pkg/x509util"
	"github.com/gin-gonic/gin"
)

// CertificateHandler handles certificate management endpoints.
type CertificateHandler struct {
	store     store.Store
	pluginMgr *pluginmgr.Manager
	executor  *renewal.Executor
	policyEng *policy.Engine
	keyring   *secrets.Keyring
}

// NewCertificateHandler creates a new handler.
func NewCertificateHandler(s store.Store, pm *pluginmgr.Manager, exec *renewal.Executor, pe *policy.Engine, kr *secrets.Keyring) *CertificateHandler {
	return &CertificateHandler{
		store:     s,
		pluginMgr: pm,
		executor:  exec,
		policyEng: pe,
		keyring:   kr,
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

	// 2. Evaluate Policy.
	// A policy engine that cannot be consulted must block the request. Treating
	// an evaluation failure as "no violations" means a database blip silently
	// disables every security policy at once.
	violations, err := h.policyEng.EvaluateRequest(c.Request.Context(), allDomains, input.KeyType, input.KeySize, input.ValidityDays, caAccount.ProviderType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("could not evaluate security policy, refusing to issue: %v", err),
		})
		return
	}
	for _, v := range violations {
		if v.Severity == "BLOCK" {
			c.JSON(http.StatusForbidden, gin.H{
				"error":      "Certificate request blocked by security policy",
				"violations": violations,
			})
			return
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

	// 4. Request Issuance from Gateway.
	// The CA account configuration is stored sealed and is decrypted only here,
	// to populate a single mutually-authenticated gRPC call.
	providerConfig, err := h.decryptCAConfig(caAccount)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	issueReq := &providerv1.IssueCertificateRequest{
		Domains:        allDomains,
		KeyType:        input.KeyType,
		KeySize:        int32(input.KeySize),
		ValidityDays:   int32(input.ValidityDays),
		ProviderConfig: providerConfig,
	}

	resp, err := gw.Client.IssueCertificate(c.Request.Context(), issueReq)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("gateway issuance failed: %v", err)})
		return
	}
	if resp.Certificate == nil || len(resp.Certificate.CertificatePem) == 0 {
		c.JSON(http.StatusBadGateway, gin.H{"error": "gateway reported success but returned no certificate"})
		return
	}

	// 5. Parse what the gateway returned rather than trusting its metadata.
	// A gateway that returns something other than a certificate must fail here,
	// not be recorded as ISSUED — that failure mode is exactly how a CSR ended
	// up stored as a certificate before.
	info, err := x509util.ParseCertificatePEM(resp.Certificate.CertificatePem)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"error": fmt.Sprintf("gateway returned data that is not a valid X.509 certificate: %v", err),
		})
		return
	}

	var chainPEM *string
	if len(resp.Certificate.ChainPem) > 0 {
		ch := string(resp.Certificate.ChainPem)
		chainPEM = &ch
	}

	// The private key is sealed before it touches the database. Without this
	// the certificate is unusable, since a certificate is only useful to
	// whoever holds the matching key.
	var privateKey *string
	if len(resp.Certificate.PrivateKeyPem) > 0 {
		sealed, err := h.keyring.Encrypt(resp.Certificate.PrivateKeyPem, secrets.ContextCertificatePrivKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("failed to encrypt the private key; refusing to store it in the clear: %v", err),
			})
			return
		}
		privateKey = &sealed
	}

	userID := c.GetString(middleware.ContextUserID)
	var createdBy *string
	if userID != "" {
		createdBy = &userID
	}

	certPEM := string(resp.Certificate.CertificatePem)
	notBefore, notAfter := info.NotBefore, info.NotAfter

	certRecord := &store.Certificate{
		FingerprintSHA256:   info.FingerprintSHA256,
		CommonName:          info.CommonName,
		SANs:                info.SANs,
		SerialNumber:        info.SerialNumber,
		IssuerDN:            info.IssuerDN,
		NotBefore:           &notBefore,
		NotAfter:            &notAfter,
		DaysRemaining:       info.DaysRemaining,
		KeyType:             info.KeyType,
		KeySize:             info.KeySize,
		Status:              "ISSUED",
		AutoRenew:           input.AutoRenew,
		RenewalLeadDays:     input.RenewalLeadDays,
		CAAccountID:         &input.CAAccountID,
		PrivateKeyEncrypted: privateKey,
		CertificatePEM:      &certPEM,
		ChainPEM:            chainPEM,
		DiscoveredVia:       "REQUESTED",
		Environment:         input.Environment,
		Team:                input.Team,
		CreatedBy:           createdBy,
	}

	if err := h.store.CreateCertificate(c.Request.Context(), certRecord); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to save certificate to store: %v", err)})
		return
	}

	// 6. Audit Log
	userEmail := c.GetString(middleware.ContextUserEmail)
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "cert.issued",
		EntityType: "certificate",
		EntityID:   &certRecord.ID,
		ActorID:    createdBy,
		ActorEmail: &userEmail,
		Details: fmt.Sprintf(`{"cn": %q, "gateway": %q, "serial": %q, "not_after": %q}`,
			certRecord.CommonName, gw.Name, certRecord.SerialNumber, notAfter.Format(time.RFC3339)),
	})

	if len(violations) > 0 {
		// Non-blocking violations were allowed through, so the response has to
		// say so — silently discarding them makes a policy that reports
		// nothing indistinguishable from a policy that found nothing.
		c.JSON(http.StatusCreated, gin.H{"certificate": certRecord, "policy_violations": violations})
		return
	}
	c.JSON(http.StatusCreated, certRecord)
}

// Renew handles POST /api/v1/certificates/:id/renew.
func (h *CertificateHandler) Renew(c *gin.Context) {
	id := c.Param("id")
	renewed, err := h.executor.RenewCertificate(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, renewed)
}

// PrivateKey handles GET /api/v1/certificates/:id/private-key.
//
// Retrieving a private key is deliberately a separate, admin-only, audited
// operation rather than a field on the certificate record. Listing certificates
// is something a dashboard does constantly; exporting a key is something a
// human should have to ask for and an auditor should be able to see.
func (h *CertificateHandler) PrivateKey(c *gin.Context) {
	id := c.Param("id")

	cert, err := h.store.GetCertificate(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	if cert.PrivateKeyEncrypted == nil || *cert.PrivateKeyEncrypted == "" {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "no private key is stored for this certificate — it was either imported, discovered, or issued from a CSR whose key never left its host",
		})
		return
	}

	keyPEM, err := h.keyring.DecryptString(*cert.PrivateKeyEncrypted, secrets.ContextCertificatePrivKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("failed to decrypt the stored private key: %v", err),
		})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	ip := c.ClientIP()
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "cert.private_key_exported",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		IPAddress:  &ip,
		Details:    fmt.Sprintf(`{"cn": %q, "serial": %q}`, cert.CommonName, cert.SerialNumber),
	})

	c.JSON(http.StatusOK, gin.H{
		"common_name":     cert.CommonName,
		"private_key_pem": keyPEM,
	})
}

// Delete handles DELETE /api/v1/certificates/:id.
func (h *CertificateHandler) Delete(c *gin.Context) {
	id := c.Param("id")

	cert, err := h.store.GetCertificate(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	if err := h.store.DeleteCertificate(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	actorID := c.GetString(middleware.ContextUserID)
	actorEmail := c.GetString(middleware.ContextUserEmail)
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "cert.deleted",
		EntityType: "certificate",
		EntityID:   &cert.ID,
		ActorID:    &actorID,
		ActorEmail: &actorEmail,
		Details:    fmt.Sprintf(`{"cn": %q, "serial": %q}`, cert.CommonName, cert.SerialNumber),
	})

	c.JSON(http.StatusOK, gin.H{"message": "certificate deleted"})
}

// decryptCAConfig unseals a CA account configuration for a single outbound call.
//
// Records written before encryption existed are stored as plaintext JSON; those
// are passed through so an upgrade does not break every existing account, and
// they are re-sealed the next time the account is written.
func (h *CertificateHandler) decryptCAConfig(acc *store.CAAccount) (string, error) {
	return decryptCAConfig(h.keyring, acc)
}

func decryptCAConfig(kr *secrets.Keyring, acc *store.CAAccount) (string, error) {
	if acc.ConfigEncrypted == "" {
		return "", nil
	}
	if !secrets.IsEnvelope(acc.ConfigEncrypted) {
		return acc.ConfigEncrypted, nil
	}
	plaintext, err := kr.DecryptString(acc.ConfigEncrypted, secrets.ContextCAAccountConfig)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt the configuration for CA account %q: %w", acc.Name, err)
	}
	return plaintext, nil
}
