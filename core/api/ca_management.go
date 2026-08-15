package api

import (
	"fmt"
	"net/http"

	"github.com/certpilot/certpilot/core/engine/pki"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/x509util"
	"github.com/gin-gonic/gin"
)

// CAHandler handles CA inventory, health inspection, and trust chain resolution.
type CAHandler struct {
	store         store.Store
	caMonitor     *pki.CAMonitor
	chainResolver *pki.ChainResolver
}

// NewCAHandler creates a new CAHandler.
func NewCAHandler(s store.Store, mon *pki.CAMonitor, cr *pki.ChainResolver) *CAHandler {
	return &CAHandler{
		store:         s,
		caMonitor:     mon,
		chainResolver: cr,
	}
}

// List handles GET /api/v1/pki/authorities.
func (h *CAHandler) List(c *gin.Context) {
	cas, err := h.store.ListCAAuthorities(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": cas, "total": len(cas)})
}

// Get handles GET /api/v1/pki/authorities/:id.
func (h *CAHandler) Get(c *gin.Context) {
	id := c.Param("id")
	ca, err := h.store.GetCAAuthority(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, ca)
}

// HierarchyTree handles GET /api/v1/pki/tree.
func (h *CAHandler) HierarchyTree(c *gin.Context) {
	tree, err := h.chainResolver.BuildHierarchyTree(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": tree})
}

// Chain handles GET /api/v1/pki/authorities/:id/chain.
func (h *CAHandler) Chain(c *gin.Context) {
	id := c.Param("id")
	chain, err := h.store.GetCAChain(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": chain})
}

// CreateCAInput represents the payload to register a new CA Authority.
type CreateCAInput struct {
	Name                 string  `json:"name" binding:"required"`
	CertificatePEM       string  `json:"certificate_pem" binding:"required"`
	ParentCAID           *string `json:"parent_ca_id"`
	CAAccountID          *string `json:"ca_account_id"`
	CRLDistributionURL   string  `json:"crl_distribution_url"`
	OCSPResponderURL     string  `json:"ocsp_responder_url"`
	Notes                string  `json:"notes"`
}

// Create handles POST /api/v1/pki/authorities.
func (h *CAHandler) Create(c *gin.Context) {
	var input CreateCAInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Parse CA certificate
	certInfo, err := x509util.ParseCertificatePEM([]byte(input.CertificatePEM))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid certificate PEM: %v", err)})
		return
	}

	caType := "ROOT"
	if input.ParentCAID != nil && *input.ParentCAID != "" {
		caType = "INTERMEDIATE"
	}

	crlURL := input.CRLDistributionURL
	if crlURL == "" && len(certInfo.CRLURLs) > 0 {
		crlURL = certInfo.CRLURLs[0]
	}

	ocspURL := input.OCSPResponderURL
	if ocspURL == "" && len(certInfo.OCSPURLs) > 0 {
		ocspURL = certInfo.OCSPURLs[0]
	}

	ca := &store.CAAuthority{
		Name:               input.Name,
		CAType:             caType,
		SubjectDN:          certInfo.SubjectDN,
		IssuerDN:           certInfo.IssuerDN,
		SerialNumber:       certInfo.SerialNumber,
		NotBefore:          certInfo.NotBefore,
		NotAfter:           certInfo.NotAfter,
		DaysRemaining:      certInfo.DaysRemaining,
		KeyType:            certInfo.KeyType,
		KeySize:            certInfo.KeySize,
		FingerprintSHA256:  certInfo.FingerprintSHA256,
		CertificatePEM:     input.CertificatePEM,
		ParentCAID:         input.ParentCAID,
		CRLDistributionURL: crlURL,
		OCSPResponderURL:   ocspURL,
		CAAccountID:        input.CAAccountID,
		Status:             "HEALTHY",
		Notes:              input.Notes,
	}

	if certInfo.DaysRemaining <= 30 {
		ca.Status = "CRITICAL"
	} else if certInfo.DaysRemaining <= 180 {
		ca.Status = "WARNING"
	}

	if err := h.store.CreateCAAuthority(c.Request.Context(), ca); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to save CA authority: %v", err)})
		return
	}

	// Trigger initial health check asynchronously
	go func() {
		_ = h.caMonitor.CheckCA(c.Request.Context(), ca)
	}()

	c.JSON(http.StatusCreated, ca)
}

// CheckHealth handles POST /api/v1/pki/authorities/:id/check.
func (h *CAHandler) CheckHealth(c *gin.Context) {
	id := c.Param("id")
	ca, err := h.store.GetCAAuthority(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	if err := h.caMonitor.CheckCA(c.Request.Context(), ca); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, ca)
}

// Delete handles DELETE /api/v1/pki/authorities/:id.
func (h *CAHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.DeleteCAAuthority(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "CA authority removed"})
}
