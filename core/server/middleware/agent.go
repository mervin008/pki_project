package middleware

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/certpilot/certpilot/core/store"
	"github.com/certpilot/certpilot/pkg/agentauth"
	"github.com/gin-gonic/gin"
)

// Context key set by AgentAuth.
const (
	// ContextAgentID identifies the agent that signed the request.
	//
	// Deliberately not ContextUserID and deliberately not accompanied by a
	// role. An agent is not a user with fewer permissions; it is a different
	// kind of caller entirely, and giving it a role would make it eligible for
	// every route that gates on one.
	ContextAgentID = "agent_id"
	// AuthMethodAgent is recorded on audit entries an agent caused.
	AuthMethodAgent = "agent"
)

// maxAgentBody bounds a signed request.
//
// The body has to be buffered whole before the signature over its hash can be
// checked, so an unbounded one is a way to make the core allocate as much
// memory as an attacker likes before it has proved anything at all.
const maxAgentBody = 1 << 20

// AgentAuth authenticates a request signed by an agent's own key.
//
// This middleware is mounted only on the agent route group and never on the
// human API, and the human authenticator is never mounted here. The two kinds
// of caller are kept completely apart on purpose: an agent credential must not
// be usable to read the estate, and a person's bearer token must not be usable
// to speak as a host.
//
// Every refusal is a flat 401 with one sentence. The reason goes to the log,
// where an operator can see it, and not onto the wire, where it would tell a
// caller which of the four checks to work on next.
func AgentAuth(st store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		refuse := func(reason string, args ...any) {
			slog.Warn("refused an agent request: "+reason,
				append(args, "path", c.Request.URL.Path, "ip", c.ClientIP())...)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "this request was not accepted as coming from an enrolled agent",
			})
		}

		agentID := c.GetHeader(agentauth.AgentHeader)
		signature := c.GetHeader(agentauth.SignatureHeader)
		rawTS := c.GetHeader(agentauth.TimestampHeader)
		if agentID == "" || signature == "" || rawTS == "" {
			refuse("the signature headers were not all present")
			return
		}

		timestamp, err := strconv.ParseInt(rawTS, 10, 64)
		if err != nil {
			refuse("the timestamp header is not a number", "value", rawTS)
			return
		}

		body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxAgentBody+1))
		if err != nil {
			refuse("the request body could not be read", "error", err)
			return
		}
		if len(body) > maxAgentBody {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "request body is too large",
			})
			return
		}
		// Put it back for the handler. The signature covers a hash of these
		// exact bytes, so the handler must decode the same ones — re-reading
		// from the network is not an option and re-encoding would be a
		// different body.
		c.Request.Body = io.NopCloser(bytes.NewReader(body))

		agent, err := st.GetAgent(c.Request.Context(), agentID)
		if err != nil {
			refuse("no such agent", "agent", agentID)
			return
		}

		key, err := agentauth.ParsePublicKey(agent.PublicKey)
		if err != nil {
			refuse("the stored public key could not be parsed", "agent", agentID, "error", err)
			return
		}

		// The signature is checked before the agent's status, and the order is
		// load-bearing in both directions.
		//
		// Checking status first would make a revoked agent distinguishable from
		// an unknown one to anybody who can guess an id, turning this endpoint
		// into a way to enumerate the fleet. Checking it second means the only
		// caller who ever learns "you were revoked" is the one holding the
		// private key — which is the agent itself, and precisely who needs to
		// be told, because otherwise it retries a withdrawn credential every
		// few minutes for as long as the host stays up.
		//
		// The path signed is the path requested, so a signature made for one
		// route cannot be replayed against another.
		if err := agentauth.Verify(key, c.Request.Method, c.Request.URL.Path,
			timestamp, signature, body, agentauth.DefaultTolerance); err != nil {
			refuse("the signature did not verify", "agent", agentID, "error", err)
			return
		}

		if agent.Status != store.AgentActive {
			// 403 rather than 401, and the one place this middleware says what
			// is actually wrong. The caller has proved it holds the key, so
			// there is nothing left to withhold from it: the agent binary reads
			// this and stops, instead of knocking every five minutes forever.
			slog.Info("a revoked agent is still calling",
				"agent", agentID, "revoked_at", agent.RevokedAt,
				"path", c.Request.URL.Path, "ip", c.ClientIP())
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "this agent's credential has been revoked",
			})
			return
		}

		c.Set(ContextAgentID, agent.ID)
		c.Set(ContextAuthMethod, AuthMethodAgent)
		c.Next()
	}
}

// AgentClock is what the core tells an agent about its own time.
//
// Returned on every accepted request, because clock drift is the single
// commonest cause of a signature that will not verify, and an agent that can
// see the difference can say so instead of reporting "unauthorized" forever.
func AgentClock() time.Time { return time.Now() }
