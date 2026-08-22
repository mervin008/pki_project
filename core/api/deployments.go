package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/engine/deploy"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/secrets"
	"github.com/gin-gonic/gin"
)

// DeploymentHandler exposes deployment targets, the places certificates go, and
// the queue that puts them there.
type DeploymentHandler struct {
	store   store.Store
	keyring *secrets.Keyring
}

// NewDeploymentHandler creates the handler.
func NewDeploymentHandler(s store.Store, kr *secrets.Keyring) *DeploymentHandler {
	return &DeploymentHandler{store: s, keyring: kr}
}

// ── Targets ─────────────────────────────────────────────────

// ListTargets handles GET /api/v1/deployment-targets.
//
// The response never carries the sealed configuration; the model drops it at
// the JSON boundary. What it does carry is deploys_private_key, which is the
// answer to a question a security team should be able to ask without holding
// the KEK: where does this organisation send key material.
func (h *DeploymentHandler) ListTargets(c *gin.Context) {
	targets, err := h.store.ListDeploymentTargets(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	keyCarrying := 0
	for _, t := range targets {
		if t.DeploysPrivateKey {
			keyCarrying++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":                 targets,
		"count":                len(targets),
		"supported_types":      deploy.Types(),
		"carrying_private_key": keyCarrying,
	})
}

type targetRequest struct {
	Name        string         `json:"name" binding:"required"`
	Description string         `json:"description"`
	TargetType  string         `json:"target_type" binding:"required"`
	Config      map[string]any `json:"config"`
	IsEnabled   *bool          `json:"is_enabled"`
}

// CreateTarget handles POST /api/v1/deployment-targets.
//
// The configuration is validated by constructing the deployer before anything
// is stored, so a bad URL or a missing signing secret is a 400 now rather than
// a failed deployment discovered during an incident.
func (h *DeploymentHandler) CreateTarget(c *gin.Context) {
	var req targetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sealed, deploysKey, err := h.sealConfig(req.TargetType, req.Config)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	enabled := true
	if req.IsEnabled != nil {
		enabled = *req.IsEnabled
	}

	actor, _ := actorOf(c)
	target := &store.DeploymentTarget{
		Name:              strings.TrimSpace(req.Name),
		Description:       strings.TrimSpace(req.Description),
		TargetType:        strings.ToLower(strings.TrimSpace(req.TargetType)),
		ConfigEncrypted:   sealed,
		IsEnabled:         enabled,
		DeploysPrivateKey: deploysKey,
		CreatedBy:         actor,
	}
	if err := h.store.CreateDeploymentTarget(c.Request.Context(), target); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Audited with the key-carrying flag, because "we started sending private
	// keys to a new place on Tuesday" is exactly the sentence an audit log
	// exists to be able to produce.
	h.audit(c, "deployment_target.created", target.ID, fmt.Sprintf(
		`{"name":%q,"target_type":%q,"deploys_private_key":%t}`,
		target.Name, target.TargetType, target.DeploysPrivateKey))

	c.JSON(http.StatusCreated, gin.H{"data": target})
}

// UpdateTarget handles PUT /api/v1/deployment-targets/:id.
//
// Omitting config leaves the stored credentials alone. Requiring them on every
// edit would mean an operator renaming a target has to re-enter a secret they
// may not have, and the usual result of that is the secret being kept somewhere
// convenient.
func (h *DeploymentHandler) UpdateTarget(c *gin.Context) {
	existing, err := h.store.GetDeploymentTarget(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var req targetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	existing.Name = strings.TrimSpace(req.Name)
	existing.Description = strings.TrimSpace(req.Description)
	existing.TargetType = strings.ToLower(strings.TrimSpace(req.TargetType))
	if req.IsEnabled != nil {
		existing.IsEnabled = *req.IsEnabled
	}

	if len(req.Config) > 0 {
		sealed, deploysKey, err := h.sealConfig(existing.TargetType, req.Config)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		existing.ConfigEncrypted = sealed
		existing.DeploysPrivateKey = deploysKey
	} else if _, err := deploy.Build(existing.TargetType, ""); err != nil && existing.ConfigEncrypted == "" {
		// Changing the type without supplying a configuration would leave a
		// target whose stored config belongs to the old type.
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "changing target_type needs a config for the new type",
		})
		return
	}

	if err := h.store.UpdateDeploymentTarget(c.Request.Context(), existing); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "deployment_target.updated", existing.ID, fmt.Sprintf(
		`{"name":%q,"deploys_private_key":%t}`, existing.Name, existing.DeploysPrivateKey))

	c.JSON(http.StatusOK, gin.H{"data": existing})
}

// DeleteTarget handles DELETE /api/v1/deployment-targets/:id.
func (h *DeploymentHandler) DeleteTarget(c *gin.Context) {
	target, err := h.store.GetDeploymentTarget(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err := h.store.DeleteDeploymentTarget(c.Request.Context(), target.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "deployment_target.deleted", target.ID, fmt.Sprintf(`{"name":%q}`, target.Name))

	// Said out loud, because the bindings cascade with it. Everything that was
	// being deployed there stops being deployed anywhere, silently, and the
	// certificates keep renewing — which is the shape of problem that is only
	// noticed when something expires.
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf(
			"Target %q deleted. Any certificate that was being deployed there is no longer deployed anywhere by CertPilot; renewals will continue and will not reach it.",
			target.Name),
	})
}

// sealConfig validates a target configuration and encrypts it.
func (h *DeploymentHandler) sealConfig(targetType string, config map[string]any) (string, bool, error) {
	raw, deploysKey, err := deploy.ValidateConfig(strings.ToLower(strings.TrimSpace(targetType)), config)
	if err != nil {
		return "", false, err
	}
	sealed, err := h.keyring.Encrypt(raw, secrets.ContextDeploymentConfig)
	if err != nil {
		return "", false, fmt.Errorf("failed to encrypt the target configuration, refusing to store it in the clear: %w", err)
	}
	return sealed, deploysKey, nil
}

// ── Bindings ────────────────────────────────────────────────

// ListBindings handles GET /api/v1/certificates/:id/targets.
func (h *DeploymentHandler) ListBindings(c *gin.Context) {
	cert, err := h.store.GetCertificate(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	bindings, err := h.store.ListCertificateDeployments(c.Request.Context(), cert.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":    bindings,
		"count":   len(bindings),
		"summary": summarizeBindings(cert, bindings),
	})
}

// summarizeBindings says where this certificate stands, in one sentence.
//
// The interesting case is neither "all deployed" nor "none": it is a
// certificate whose targets are holding an older fingerprint than the one
// CertPilot has. That is the same failure post-renewal verification exists to
// catch, seen from the other end — and unlike verification it can be answered
// without opening a single connection.
func summarizeBindings(cert *store.Certificate, bindings []*store.CertificateDeployment) string {
	if len(bindings) == 0 {
		return "This certificate is not bound to any deployment target, so a renewal will update CertPilot's record and reach nothing."
	}

	current, behind, never, failing := 0, 0, 0, 0
	for _, b := range bindings {
		if b.LastStatus == store.DeploymentFailed {
			failing++
		}
		switch {
		case b.DeployedFingerprint == "":
			never++
		case b.DeployedFingerprint == cert.FingerprintSHA256:
			current++
		default:
			behind++
		}
	}

	// What each place is holding, and whether the last attempt to change it
	// worked, are two different facts and both belong in the sentence.
	//
	// This first shipped reporting only the first, and a live run produced
	// "All 1 target hold the current certificate" over a deployment that had
	// failed three times and escalated — true, reassuring, and exactly the
	// half-told story this product exists to stop other tools telling.
	var state string
	switch {
	case behind == 0 && never == 0 && current == 1:
		// Its own branch rather than a plural helper, because "All 1 target
		// hold the current certificate" is what the general form produces and
		// it reads as a machine talking.
		state = "The one place this goes is holding the current certificate"
	case behind == 0 && never == 0:
		state = fmt.Sprintf("All %s hold the current certificate", placesText(current))
	case current == 0 && behind == 0:
		state = fmt.Sprintf("Bound to %s, and nothing has been deployed yet", placesText(never))
	default:
		parts := []string{}
		if current > 0 {
			parts = append(parts, fmt.Sprintf("%d up to date", current))
		}
		if behind > 0 {
			parts = append(parts, fmt.Sprintf("%d holding an older certificate", behind))
		}
		if never > 0 {
			parts = append(parts, fmt.Sprintf("%d never deployed", never))
		}
		state = fmt.Sprintf("%s: %s", placesText(len(bindings)), strings.Join(parts, ", "))
	}

	if failing > 0 {
		return fmt.Sprintf("%s. The last deployment to %s failed.", state, placesText(failing))
	}
	return state + "."
}

func placesText(n int) string {
	if n == 1 {
		return "1 target"
	}
	return fmt.Sprintf("%d targets", n)
}

type bindingRequest struct {
	TargetID  string         `json:"target_id" binding:"required"`
	Options   map[string]any `json:"options"`
	IsEnabled *bool          `json:"is_enabled"`
}

// CreateBinding handles POST /api/v1/certificates/:id/targets.
func (h *DeploymentHandler) CreateBinding(c *gin.Context) {
	cert, err := h.store.GetCertificate(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var req bindingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	target, err := h.store.GetDeploymentTarget(c.Request.Context(), req.TargetID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Refused here rather than at deploy time. A target that needs the private
	// key and a certificate that has none can be bound together quite happily
	// and will then fail on every renewal, forever, which is the kind of
	// misconfiguration that is only found the week it matters.
	if target.DeploysPrivateKey {
		key, err := h.store.GetCertificatePrivateKey(c.Request.Context(), cert.ID)
		if err == nil && key == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf(
					"target %q sends the private key, and CertPilot holds no private key for %s. A certificate that was discovered or imported has no key here until it is reissued through CertPilot",
					target.Name, cert.CommonName),
			})
			return
		}
	}

	enabled := true
	if req.IsEnabled != nil {
		enabled = *req.IsEnabled
	}

	actor, _ := actorOf(c)
	binding := &store.CertificateDeployment{
		CertificateID: cert.ID,
		TargetID:      target.ID,
		IsEnabled:     enabled,
		Options:       req.Options,
		CreatedBy:     actor,
	}
	if err := h.store.CreateCertificateDeployment(c.Request.Context(), binding); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "deployment.bound", binding.ID, fmt.Sprintf(
		`{"cn":%q,"target":%q,"carries_private_key":%t}`, cert.CommonName, target.Name, target.DeploysPrivateKey))

	c.JSON(http.StatusCreated, gin.H{
		"data": binding,
		"message": fmt.Sprintf(
			"%s will be deployed to %s. Binding does not install it — POST /certificates/%s/deploy does.",
			cert.CommonName, target.Name, cert.ID),
	})
}

// DeleteBinding handles DELETE /api/v1/certificates/:id/targets/:bindingId.
func (h *DeploymentHandler) DeleteBinding(c *gin.Context) {
	binding, err := h.store.GetCertificateDeployment(c.Request.Context(), c.Param("bindingId"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if binding.CertificateID != c.Param("id") {
		// The binding exists but belongs to a different certificate. Refused
		// rather than followed, so a mistyped id cannot detach something else.
		c.JSON(http.StatusNotFound, gin.H{"error": "that deployment does not belong to this certificate"})
		return
	}

	if err := h.store.DeleteCertificateDeployment(c.Request.Context(), binding.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "deployment.unbound", binding.ID, fmt.Sprintf(`{"target":%q}`, binding.TargetName))

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf(
			"No longer deploying to %s. Whatever certificate is installed there stays there and stops being updated.",
			fallbackText(binding.TargetName, "that target")),
	})
}

// ── Deploying ───────────────────────────────────────────────

// Deploy handles POST /api/v1/certificates/:id/deploy.
//
// Queues rather than deploys. A certificate on eight targets is eight outbound
// calls to eight machines that may each take a reload to finish, and a
// synchronous handler would be cut off by the server's write timeout somewhere
// in the middle — leaving half an estate updated and an HTTP client with no
// idea which half.
func (h *DeploymentHandler) Deploy(c *gin.Context) {
	cert, err := h.store.GetCertificate(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	bindings, err := h.store.ListCertificateDeployments(c.Request.Context(), cert.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(bindings) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "this certificate is not bound to any deployment target. Bind one with POST /certificates/:id/targets first",
		})
		return
	}

	actor, email := actorOf(c)
	queued, existing, skipped := 0, 0, 0
	jobs := make([]*store.DeploymentJob, 0, len(bindings))

	for _, binding := range bindings {
		if !binding.IsEnabled {
			skipped++
			continue
		}
		job := &store.DeploymentJob{
			DeploymentID:  binding.ID,
			CertificateID: cert.ID,
			TargetID:      binding.TargetID,
			Reason:        store.DeployReasonManual,
			Status:        store.DeployPending,
			RunAfter:      time.Now(),
			Fingerprint:   cert.FingerprintSHA256,
			NotAfter:      cert.NotAfter,
			TriggeredBy:   actor,
			ActorEmail:    email,
		}
		created, err := h.store.EnqueueDeployment(c.Request.Context(), job)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if created {
			queued++
		} else {
			existing++
		}
		jobs = append(jobs, job)
	}

	h.audit(c, "cert.deploy_requested", cert.ID, fmt.Sprintf(
		`{"cn":%q,"queued":%d,"already_queued":%d}`, cert.CommonName, queued, existing))

	c.JSON(http.StatusAccepted, gin.H{
		"data":    jobs,
		"queued":  queued,
		"message": deployQueuedMessage(cert.CommonName, queued, existing, skipped),
	})
}

// deployQueuedMessage says what actually happened, including the parts that did
// not happen. A response of "queued" over an estate where three of five targets
// were switched off is the kind of half-truth that gets believed.
func deployQueuedMessage(commonName string, queued, existing, skipped int) string {
	parts := []string{}
	if queued > 0 {
		parts = append(parts, fmt.Sprintf("queued for %s", placesText(queued)))
	}
	if existing > 0 {
		parts = append(parts, fmt.Sprintf("%s already had a deployment outstanding", placesText(existing)))
	}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%s switched off and skipped", placesText(skipped)))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("Nothing to do for %s.", commonName)
	}
	return fmt.Sprintf("%s: %s.", commonName, strings.Join(parts, "; "))
}

// ListJobs handles GET /api/v1/deployments.
func (h *DeploymentHandler) ListJobs(c *gin.Context) {
	filter := store.DeploymentJobFilter{
		CertificateID: c.Query("certificate_id"),
		TargetID:      c.Query("target_id"),
		Status:        strings.ToUpper(c.Query("status")),
		Limit:         50,
	}
	if c.Query("outstanding") == "true" {
		filter.OutstandingOnly = true
	}
	if c.Query("escalated") == "true" {
		filter.EscalatedOnly = true
	}
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 && v <= 200 {
		filter.Limit = v
	}
	if v, err := strconv.Atoi(c.Query("offset")); err == nil && v >= 0 {
		filter.Offset = v
	}

	jobs, total, err := h.store.ListDeploymentJobs(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Counted separately from the page above, because they mean different
	// things: a queue with work in it is the ordinary steady state of an estate
	// that deploys, and a queue with escalated jobs in it is somebody's morning.
	_, outstanding, _ := h.store.ListDeploymentJobs(c.Request.Context(),
		store.DeploymentJobFilter{OutstandingOnly: true, Limit: 1})
	stuck, stuckTotal, _ := h.store.ListDeploymentJobs(c.Request.Context(),
		store.DeploymentJobFilter{EscalatedOnly: true, OutstandingOnly: true, Limit: 20})

	c.JSON(http.StatusOK, gin.H{
		"data":        jobs,
		"total":       total,
		"outstanding": outstanding,
		"escalated":   stuckTotal,
		"summary":     h.summarizeQueue(c, stuck, stuckTotal),
	})
}

// GetJob handles GET /api/v1/deployments/:id.
func (h *DeploymentHandler) GetJob(c *gin.Context) {
	job, err := h.store.GetDeploymentJob(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": job})
}

// CancelJob handles DELETE /api/v1/deployments/:id.
func (h *DeploymentHandler) CancelJob(c *gin.Context) {
	job, err := h.store.GetDeploymentJob(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err := h.store.CancelDeploymentJob(c.Request.Context(), job.ID); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "deployment.cancelled", job.ID, fmt.Sprintf(`{"certificate_id":%q}`, job.CertificateID))

	c.JSON(http.StatusOK, gin.H{
		"message": "Deployment cancelled. The target keeps whatever certificate it already has, and nothing will update it.",
	})
}

// summarizeQueue turns the escalated jobs into a sentence naming what is stuck
// and where, so a dashboard does not have to render an array to be useful.
func (h *DeploymentHandler) summarizeQueue(c *gin.Context, stuck []*store.DeploymentJob, total int64) string {
	if total == 0 {
		return "No deployment is stuck."
	}

	names := make([]string, 0, len(stuck))
	for _, job := range stuck {
		name := job.CertificateID
		if cert, err := h.store.GetCertificate(c.Request.Context(), job.CertificateID); err == nil {
			name = cert.CommonName
		}
		where := ""
		if target, err := h.store.GetDeploymentTarget(c.Request.Context(), job.TargetID); err == nil {
			where = " at " + target.Name
		}
		names = append(names, fmt.Sprintf("%s%s (%d attempts)", name, where, job.Attempts))
		if len(names) == 3 {
			break
		}
	}

	subject := "1 deployment is failing"
	if total > 1 {
		subject = fmt.Sprintf("%d deployments are failing", total)
	}
	return fmt.Sprintf("%s: %s. The certificates are fine; what serves them is not being updated.",
		subject, strings.Join(names, ", "))
}

// ── Helpers ─────────────────────────────────────────────────

// actorOf pulls the acting user out of the request context.
func actorOf(c *gin.Context) (*string, *string) {
	var actor, email *string
	if id := c.GetString(middleware.ContextUserID); id != "" {
		actor = &id
	}
	if addr := c.GetString(middleware.ContextUserEmail); addr != "" {
		email = &addr
	}
	return actor, email
}

func (h *DeploymentHandler) audit(c *gin.Context, action, entityID, details string) {
	actor, email := actorOf(c)
	entity := entityID
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     action,
		EntityType: "deployment",
		EntityID:   &entity,
		ActorID:    actor,
		ActorEmail: email,
		Details:    details,
	})
}

func fallbackText(value, alt string) string {
	if strings.TrimSpace(value) == "" {
		return alt
	}
	return value
}
