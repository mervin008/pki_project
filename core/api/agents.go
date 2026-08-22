package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/server/middleware"
	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/agentauth"
	"github.com/gin-gonic/gin"
)

// Bounds on an enrolment token.
//
// Short by default and capped hard. An enrolment token is the credential handed
// to a machine that has never spoken to CertPilot, and it only has to survive
// the length of a provisioning run. One that outlives the rollout is a live
// credential sitting in whatever template it was pasted into.
const (
	defaultEnrolTokenMinutes = 60
	maxEnrolTokenMinutes     = 7 * 24 * 60
	maxEnrolTokenUses        = 500

	// defaultHeartbeatSeconds is what an agent reports at unless it says
	// otherwise. Five minutes: often enough that a dead host is noticed within
	// a quarter of an hour, rare enough that a thousand agents are twelve
	// requests a second between them.
	defaultHeartbeatSeconds = 300
	minHeartbeatSeconds     = 30
	maxHeartbeatSeconds     = 3600
)

// AgentHandler manages agents and the tokens that enrol them.
type AgentHandler struct {
	store  store.Store
	broker *events.Broker
}

// NewAgentHandler creates the handler.
func NewAgentHandler(s store.Store, broker *events.Broker) *AgentHandler {
	return &AgentHandler{store: s, broker: broker}
}

// ── Management, for people ──────────────────────────────────

// ListAgents handles GET /api/v1/agents.
func (h *AgentHandler) ListAgents(c *gin.Context) {
	filter := store.AgentFilter{
		Status: strings.ToUpper(c.Query("status")),
		Limit:  100,
	}
	if c.Query("stale") == "true" {
		filter.StaleOnly = true
	}
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 && v <= 500 {
		filter.Limit = v
	}
	if v, err := strconv.Atoi(c.Query("offset")); err == nil && v >= 0 {
		filter.Offset = v
	}

	agents, total, err := h.store.ListAgents(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	_, stale, err := h.store.ListAgents(c.Request.Context(),
		store.AgentFilter{Status: store.AgentActive, StaleOnly: true, Limit: 1})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":    agents,
		"total":   total,
		"stale":   stale,
		"summary": summarizeAgents(total, stale),
	})
}

// summarizeAgents says what the fleet amounts to.
//
// The number that matters is not how many agents are enrolled. It is how many
// of them have stopped reporting — because those hosts still have certificates
// on them, still have them expiring, and now have nothing maintaining them,
// while looking exactly like healthy hosts on a list that only counts rows.
func summarizeAgents(total, stale int64) string {
	switch {
	case total == 0:
		return "No agents are enrolled."
	// "none have stopped reporting" rather than "all reporting", which is what
	// this first said. The number this sentence is built from is the stale
	// count, so it may only make claims about staleness: an agent that enrolled
	// a minute ago and has never said a word is not yet late, and reporting it
	// as reporting is the summary asserting something nothing has observed.
	case stale == 0 && total == 1:
		return "1 agent, and it has not gone quiet."
	case stale == 0:
		return fmt.Sprintf("%d agents, none of which have gone quiet.", total)
	case stale == 1:
		return fmt.Sprintf("%d agents, and 1 has stopped reporting. That host still has certificates on it and nothing is maintaining them.", total)
	default:
		return fmt.Sprintf("%d agents, and %d have stopped reporting. Those hosts still have certificates on them and nothing is maintaining them.", total, stale)
	}
}

// GetAgent handles GET /api/v1/agents/:id.
func (h *AgentHandler) GetAgent(c *gin.Context) {
	agent, err := h.store.GetAgent(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":    agent,
		"missing": missingText(agent, time.Now()),
	})
}

func missingText(agent *store.Agent, now time.Time) string {
	if agent.Status != store.AgentActive {
		return "This agent's credential has been revoked. It can no longer speak to CertPilot."
	}
	promised := time.Duration(agent.HeartbeatIntervalSeconds) * time.Second
	if agent.LastSeenAt == nil && agent.MissingFor(now) <= 0 {
		// Enrolled and not yet heard from. Said as its own state rather than
		// folded into "reporting as expected", which would be this record
		// vouching for something that has not happened.
		return fmt.Sprintf(
			"Enrolled at %s and has not reported yet. It promised every %s; if nothing arrives it will be flagged.",
			agent.EnrolledAt.Format(time.RFC3339), promised)
	}
	if over := agent.MissingFor(now); over > 0 {
		last := "since it enrolled"
		if agent.LastSeenAt != nil {
			last = "since " + agent.LastSeenAt.Format(time.RFC3339)
		}
		return fmt.Sprintf(
			"This agent has not reported %s. It promised every %s; whatever certificates are on that host are not being maintained.",
			last, promised)
	}
	return "Reporting as expected."
}

// RevokeAgent handles POST /api/v1/agents/:id/revoke.
//
// Revocation, not deletion. The record stays: an agent that had to be revoked
// is exactly the one somebody will want to read the history of afterwards.
func (h *AgentHandler) RevokeAgent(c *gin.Context) {
	agent, err := h.store.GetAgent(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	actor, _ := actorOf(c)
	if err := h.store.RevokeAgent(c.Request.Context(), agent.ID, actor); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "agent.revoked", agent.ID, fmt.Sprintf(`{"name":%q,"key_id":%q}`, agent.Name, agent.KeyID))

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf(
			"%s can no longer speak to CertPilot. Whatever certificates are on that host stay where they are and stop being maintained.",
			agent.Name),
	})
}

// DeleteAgent handles DELETE /api/v1/agents/:id.
//
// Refused while the agent is active. Deleting the row would not stop the
// credential — the agent would simply be an unknown id — but it would remove
// every record that it ever existed, which is the wrong order to do those two
// things in.
func (h *AgentHandler) DeleteAgent(c *gin.Context) {
	agent, err := h.store.GetAgent(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if agent.Status == store.AgentActive {
		c.JSON(http.StatusConflict, gin.H{
			"error": "revoke this agent before deleting it, so the credential is withdrawn before the record of it is",
		})
		return
	}
	if err := h.store.DeleteAgent(c.Request.Context(), agent.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "agent.deleted", agent.ID, fmt.Sprintf(`{"name":%q}`, agent.Name))
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Agent %q deleted.", agent.Name)})
}

// ── Enrolment tokens ────────────────────────────────────────

// ListEnrolTokens handles GET /api/v1/agent-enrol-tokens.
func (h *AgentHandler) ListEnrolTokens(c *gin.Context) {
	tokens, err := h.store.ListAgentEnrolTokens(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now()
	views := make([]gin.H, 0, len(tokens))
	live := 0
	for _, t := range tokens {
		usable, why := t.Usable(now)
		if usable {
			live++
			why = "usable"
		}
		views = append(views, gin.H{"token": t, "state": why})
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  views,
		"total": len(views),
		// The count that matters: how many doors are open right now.
		"usable": live,
	})
}

type createEnrolTokenRequest struct {
	Name string `json:"name" binding:"required"`
	// ExpiresInMinutes defaults to 60 and is capped at a week.
	ExpiresInMinutes int `json:"expires_in_minutes"`
	// MaxUses defaults to 1.
	MaxUses int               `json:"max_uses"`
	Labels  map[string]string `json:"labels"`
}

// CreateEnrolToken handles POST /api/v1/agent-enrol-tokens.
//
// The raw token is returned exactly once, here. A credential the server can
// hand out again is a credential the server is storing.
func (h *AgentHandler) CreateEnrolToken(c *gin.Context) {
	var req createEnrolTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "a name is required — it is what identifies which rollout to revoke",
		})
		return
	}

	minutes := req.ExpiresInMinutes
	if minutes <= 0 {
		minutes = defaultEnrolTokenMinutes
	}
	if minutes > maxEnrolTokenMinutes {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf(
				"an enrolment token may live at most %d minutes (a week). It only has to survive a provisioning run, and one that outlives the rollout is a live credential in whatever template it was pasted into",
				maxEnrolTokenMinutes),
		})
		return
	}

	uses := req.MaxUses
	if uses <= 0 {
		uses = 1
	}
	if uses > maxEnrolTokenUses {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("max_uses may be at most %d", maxEnrolTokenUses),
		})
		return
	}

	raw, err := newEnrolToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	actor, _ := actorOf(c)
	token := &store.AgentEnrolToken{
		Name:      req.Name,
		TokenHash: hashEnrolToken(raw),
		ExpiresAt: time.Now().Add(time.Duration(minutes) * time.Minute),
		MaxUses:   uses,
		Labels:    req.Labels,
		CreatedBy: actor,
	}
	if err := h.store.CreateAgentEnrolToken(c.Request.Context(), token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "agent_enrol_token.created", token.ID,
		fmt.Sprintf(`{"name":%q,"max_uses":%d,"expires_at":%q}`,
			token.Name, token.MaxUses, token.ExpiresAt.Format(time.RFC3339)))

	c.JSON(http.StatusCreated, gin.H{
		"data":  token,
		"token": raw,
		"message": fmt.Sprintf(
			"This token is shown once and cannot be recovered. It enrols %s and expires at %s.",
			usesText(uses), token.ExpiresAt.Format(time.RFC3339)),
	})
}

func usesText(n int) string {
	if n == 1 {
		return "one agent"
	}
	return fmt.Sprintf("up to %d agents", n)
}

// RevokeEnrolToken handles DELETE /api/v1/agent-enrol-tokens/:id.
func (h *AgentHandler) RevokeEnrolToken(c *gin.Context) {
	actor, _ := actorOf(c)
	if err := h.store.RevokeAgentEnrolToken(c.Request.Context(), c.Param("id"), actor); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, "agent_enrol_token.revoked", c.Param("id"), `{}`)
	c.JSON(http.StatusOK, gin.H{
		"message": "Revoked. Agents already enrolled with it are unaffected — their credential is their own key, not this token.",
	})
}

// ── The agent's own endpoints ───────────────────────────────

type enrolRequest struct {
	Token string `json:"token" binding:"required"`
	// PublicKey is the agent's own, generated on its host. The private half is
	// not sent, not asked for, and has no field to arrive in.
	PublicKey string `json:"public_key" binding:"required"`

	Name                     string `json:"name"`
	Hostname                 string `json:"hostname"`
	Platform                 string `json:"platform"`
	Version                  string `json:"version"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
}

// Enrol handles POST /api/v1/agent/enrol.
//
// The only agent endpoint that is not signed, because the agent has no identity
// yet — this is the request that gives it one. It is authenticated by the
// enrolment token instead, which is why that token is one-use and short-lived.
func (h *AgentHandler) Enrol(c *gin.Context) {
	var req enrolRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// The key is parsed before the token is spent. A malformed key would
	// otherwise consume a one-use token and leave the operator with nothing to
	// retry with.
	key, err := agentauth.ParsePublicKey(req.PublicKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("public_key must be a PEM Ed25519 public key: %v", err),
		})
		return
	}

	now := time.Now()
	token, err := h.store.GetAgentEnrolTokenByHash(c.Request.Context(), hashEnrolToken(req.Token))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if token == nil {
		// Nothing more specific for a token that does not exist. A holder of a
		// real token gets told why it failed below; a guesser gets one
		// sentence, and guessing a 256-bit token is not a strategy anyway.
		c.JSON(http.StatusUnauthorized, gin.H{"error": "this enrolment token is not valid"})
		return
	}
	if usable, why := token.Usable(now); !usable {
		c.JSON(http.StatusUnauthorized, gin.H{"error": why})
		return
	}

	// Spent conditionally in the database. Two hosts booting from the same
	// image enrol in the same second, and a check followed by a write would let
	// a one-use token enrol both — which is the one property it exists to have.
	spent, err := h.store.ConsumeAgentEnrolToken(c.Request.Context(), token.ID, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !spent {
		c.JSON(http.StatusConflict, gin.H{
			"error": "this enrolment token was used up while this request was in flight",
		})
		return
	}

	interval := req.HeartbeatIntervalSeconds
	switch {
	case interval <= 0:
		interval = defaultHeartbeatSeconds
	case interval < minHeartbeatSeconds:
		interval = minHeartbeatSeconds
	case interval > maxHeartbeatSeconds:
		interval = maxHeartbeatSeconds
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = strings.TrimSpace(req.Hostname)
	}
	if name == "" {
		name = "unnamed agent"
	}

	agent := &store.Agent{
		Name:                     name,
		Hostname:                 strings.TrimSpace(req.Hostname),
		Platform:                 strings.TrimSpace(req.Platform),
		Version:                  strings.TrimSpace(req.Version),
		PublicKey:                req.PublicKey,
		KeyID:                    agentauth.KeyID(key),
		Status:                   store.AgentActive,
		Labels:                   token.Labels,
		EnrolTokenID:             &token.ID,
		EnrolledFrom:             c.ClientIP(),
		HeartbeatIntervalSeconds: interval,
	}
	if err := h.store.CreateAgent(c.Request.Context(), agent); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     "agent.enrolled",
		EntityType: "agent",
		EntityID:   &agent.ID,
		Details: fmt.Sprintf(`{"name":%q,"key_id":%q,"from":%q,"token":%q}`,
			agent.Name, agent.KeyID, agent.EnrolledFrom, token.Name),
	})

	if h.broker != nil {
		h.broker.Publish(events.Event{
			Topic:    events.TopicAgentEnrolled,
			Severity: events.SeverityInfo,
			EntityID: agent.ID,
			Payload: map[string]any{
				"name":     agent.Name,
				"hostname": agent.Hostname,
				"platform": agent.Platform,
				"key_id":   agent.KeyID,
				"from":     agent.EnrolledFrom,
				"token":    token.Name,
			},
		})
	}

	c.JSON(http.StatusCreated, gin.H{
		"agent_id":                   agent.ID,
		"name":                       agent.Name,
		"key_id":                     agent.KeyID,
		"heartbeat_interval_seconds": agent.HeartbeatIntervalSeconds,
		"server_time":                now.UTC().Format(time.RFC3339),
	})
}

type heartbeatRequest struct {
	Version         string `json:"version"`
	Platform        string `json:"platform"`
	Hostname        string `json:"hostname"`
	IntervalSeconds int    `json:"interval_seconds"`
}

// Heartbeat handles POST /api/v1/agent/heartbeat.
//
// Signed with the agent's own key, like everything an agent does after
// enrolment. The response carries the server's clock: drift is far and away the
// commonest reason a signature will not verify, and an agent that can see the
// difference can say so instead of reporting "unauthorized" forever.
func (h *AgentHandler) Heartbeat(c *gin.Context) {
	agentID := c.GetString(middleware.ContextAgentID)

	var req heartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	interval := req.IntervalSeconds
	if interval > 0 && interval < minHeartbeatSeconds {
		interval = minHeartbeatSeconds
	}
	if interval > maxHeartbeatSeconds {
		interval = maxHeartbeatSeconds
	}

	now := time.Now()
	if err := h.store.RecordAgentHeartbeat(c.Request.Context(), agentID, store.AgentHeartbeat{
		Version:         strings.TrimSpace(req.Version),
		Platform:        strings.TrimSpace(req.Platform),
		Hostname:        strings.TrimSpace(req.Hostname),
		IntervalSeconds: interval,
		SeenAt:          now,
		SeenIP:          c.ClientIP(),
	}); err != nil {
		// The middleware already checked the agent is active, so getting here
		// means it was revoked between then and now — which is exactly when a
		// revocation is most worth taking effect.
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"agent_id":    agentID,
		"server_time": now.UTC().Format(time.RFC3339),
	})
}

// ── Helpers ─────────────────────────────────────────────────

// newEnrolToken mints 256 bits of randomness, base64url without padding.
func newEnrolToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("could not generate an enrolment token: %w", err)
	}
	return "cpe_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashEnrolToken(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

func (h *AgentHandler) audit(c *gin.Context, action, entityID, details string) {
	actor, email := actorOf(c)
	entity := entityID
	_ = h.store.CreateAuditLog(c.Request.Context(), &store.AuditLog{
		Action:     action,
		EntityType: "agent",
		EntityID:   &entity,
		ActorID:    actor,
		ActorEmail: email,
		Details:    details,
	})
}
