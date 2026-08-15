package api

import (
	"net/http"

	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// PolicyHandler handles policy rule management.
type PolicyHandler struct {
	store store.Store
}

// NewPolicyHandler creates a new PolicyHandler.
func NewPolicyHandler(s store.Store) *PolicyHandler {
	return &PolicyHandler{store: s}
}

// List handles GET /api/v1/policies.
func (h *PolicyHandler) List(c *gin.Context) {
	policies, err := h.store.ListPolicies(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": policies, "total": len(policies)})
}

// Get handles GET /api/v1/policies/:id.
func (h *PolicyHandler) Get(c *gin.Context) {
	id := c.Param("id")
	p, err := h.store.GetPolicy(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, p)
}

// Create handles POST /api/v1/policies.
func (h *PolicyHandler) Create(c *gin.Context) {
	var p store.Policy
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if p.Severity == "" {
		p.Severity = "WARNING"
	}

	if err := h.store.CreatePolicy(c.Request.Context(), &p); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, p)
}

// Update handles PUT /api/v1/policies/:id.
func (h *PolicyHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var p store.Policy
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p.ID = id

	if err := h.store.UpdatePolicy(c.Request.Context(), &p); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, p)
}

// Delete handles DELETE /api/v1/policies/:id.
func (h *PolicyHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.DeletePolicy(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "policy deleted"})
}
