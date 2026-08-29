package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// AuditHandler answers questions about the integrity of the audit record
// itself, as opposed to what is in it — that is /dashboard/activity.
type AuditHandler struct {
	store store.Store
}

// NewAuditHandler creates a new AuditHandler.
func NewAuditHandler(s store.Store) *AuditHandler {
	return &AuditHandler{store: s}
}

// maxVerifyLimit caps one verification walk.
//
// Verification reads and re-hashes every entry it covers, so an uncapped call
// against a mature audit table is a way to make the core do unbounded work from
// a single request. A caller that wants the whole chain walks it in pages using
// `from`.
const maxVerifyLimit = 20000

// defaultVerifyLimit is what an operator gets when they just press the button.
//
// Deliberately a partial walk. The full one is available and is the answer to
// "has this record ever been altered", but the common question is "has anything
// happened to it lately", and that must not require reading a million rows.
const defaultVerifyLimit = 5000

// Verify handles GET /api/v1/audit/verify.
//
// Admin only. The result is a statement about whether the audit record can
// still be trusted, and the honest answer to "who is allowed to ask" is the
// people who would be implicated by it being false.
//
// Supports `from` (a sequence number, default 1) and `limit`.
func (h *AuditHandler) Verify(c *gin.Context) {
	if unknown := unexpectedQuery(c, "from", "limit"); unknown != "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("%s is not a parameter of this endpoint; supported: from, limit", unknown),
		})
		return
	}

	var from int64 = 1
	if raw := c.Query("from"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 1 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "from must be a sequence number of 1 or greater",
			})
			return
		}
		from = parsed
	}

	limit := defaultVerifyLimit
	if raw := c.Query("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maxVerifyLimit {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("limit must be a whole number between 1 and %d", maxVerifyLimit),
			})
			return
		}
		limit = parsed
	}

	report, err := h.store.VerifyAuditChain(c.Request.Context(), from, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 200 even when the chain is broken. A failed verification is a successful
	// answer to the question that was asked, and returning 5xx would make it
	// indistinguishable from the core being unable to answer at all — which is
	// exactly the confusion an operator cannot afford here.
	c.JSON(http.StatusOK, report)
}
