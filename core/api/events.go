package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

// heartbeatInterval is how often a comment is written to an idle stream.
//
// It serves two purposes: it holds open intermediaries that would otherwise
// reap a quiet connection, and it is how the client distinguishes "nothing is
// happening" from "I have stopped receiving". Without it a wall display cannot
// tell a calm PKI from a dead connection, which is the failure this whole
// feature exists to prevent.
// A var rather than a const so tests can shorten it; nothing else reassigns it.
var heartbeatInterval = 15 * time.Second

// streamBuffer is how many events a single connected client may fall behind by
// before it starts losing the oldest. A browser absorbing a burst wants depth;
// beyond this the client is told to resynchronise instead.
const streamBuffer = 512

// EventsHandler streams changes to connected dashboards.
type EventsHandler struct {
	store  store.Store
	broker *events.Broker
}

// NewEventsHandler creates the handler.
func NewEventsHandler(s store.Store, b *events.Broker) *EventsHandler {
	return &EventsHandler{store: s, broker: b}
}

// caSummary is the per-CA payload in a snapshot.
//
// Deliberately not the full store.CAAuthority: that carries certificate_pem,
// which is several kilobytes per CA and useless to a dashboard. A snapshot is
// sent on every connect and every resynchronise, so it stays lean.
type caSummary struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	CAType             string    `json:"ca_type"`
	Status             string    `json:"status"`
	DaysRemaining      int       `json:"days_remaining"`
	NotAfter           time.Time `json:"not_after"`
	IsCRLFresh         bool      `json:"is_crl_fresh"`
	HasCRL             bool      `json:"has_crl"`
	CertificatesIssued int64     `json:"certificates_issued_count"`
	LastAlertThreshold *int      `json:"last_alert_threshold,omitempty"`
	ParentCAID         *string   `json:"parent_ca_id,omitempty"`
}

// snapshot is the complete current state, sent when a client connects so it
// never renders from an empty store.
type snapshot struct {
	Stats *store.DashboardStats `json:"stats"`
	CAs   []caSummary           `json:"cas"`
	// ServerTime lets a client detect clock skew before it starts computing
	// how stale its own data is.
	ServerTime time.Time `json:"server_time"`
	// LastEventID is where the live stream picks up from.
	LastEventID uint64 `json:"last_event_id"`
}

// Stream handles GET /api/v1/events.
//
// Server-Sent Events rather than WebSockets: the traffic is one-way, it
// survives ordinary HTTP proxies, and browsers reconnect on their own.
func (h *EventsHandler) Stream(c *gin.Context) {
	w := c.Writer

	// The server enforces a 30s WriteTimeout for ordinary requests, which would
	// otherwise sever every stream after exactly thirty seconds. Clearing the
	// deadline for this one connection is right; weakening it globally would
	// remove a useful protection from every other handler.
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		slog.Error("cannot clear the write deadline; the event stream would be cut short", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "this server cannot hold a streaming connection open",
		})
		return
	}

	header := w.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	header.Set("Connection", "keep-alive")
	// nginx buffers proxied responses by default, which would deliver the
	// stream in chunks and make a live dashboard look frozen. This asks it not
	// to; deploy/docker/nginx.conf disables buffering for this route as well,
	// since not every proxy honours the header.
	header.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Subscribe before sending the snapshot, so a change landing between the
	// two is queued rather than lost.
	sub := h.broker.SubscribeWithBuffer(streamBuffer)
	defer sub.Close()

	ctx := c.Request.Context()

	// Tell the browser how long to wait before reconnecting.
	if !writeRetry(c, 3*time.Second) {
		return
	}

	// A reconnecting client echoes back the last event it saw. Resume from
	// there when the gap is still in the broker's history; otherwise fall back
	// to a full snapshot, because silently skipping events would leave the
	// dashboard confidently wrong.
	resumeFrom, resuming := parseLastEventID(c)
	if resuming {
		replayed, complete := h.broker.Replay(resumeFrom)
		if complete {
			for _, evt := range replayed {
				if !writeEvent(c, evt) {
					return
				}
			}
			h.run(ctx, c, sub)
			return
		}
		slog.Debug("event stream gap too large to replay, sending a snapshot",
			"last_event_id", resumeFrom)
	}

	if !h.writeSnapshot(ctx, c) {
		return
	}

	h.run(ctx, c, sub)
}

// run pumps events until the client disconnects or the broker stops.
func (h *EventsHandler) run(ctx context.Context, c *gin.Context, sub *events.Subscription) {
	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case evt, ok := <-sub.Events():
			if !ok {
				// The broker stopped — the server is shutting down. Close the
				// stream cleanly so the browser reconnects to the new process
				// rather than sitting on a dead socket.
				return
			}
			if !writeEvent(c, evt) {
				return
			}

			// A client that fell behind has an incomplete view. Telling it to
			// resynchronise is the only honest option: continuing to stream
			// deltas onto a stale base produces a dashboard that looks live
			// and is wrong.
			if sub.Lossy() {
				slog.Warn("event stream client fell behind; requesting resync",
					"dropped", sub.Dropped())
				if !writeNamed(c, "resync", map[string]any{
					"reason":  "events were dropped because this client fell behind",
					"dropped": sub.Dropped(),
				}) {
					return
				}
				if !h.writeSnapshot(ctx, c) {
					return
				}
			}

		case <-heartbeat.C:
			// A comment: valid SSE, ignored by EventSource, and enough to prove
			// the connection is alive.
			if !writeRaw(c, ": heartbeat\n\n") {
				return
			}
		}
	}
}

// writeSnapshot sends the full current state.
func (h *EventsHandler) writeSnapshot(ctx context.Context, c *gin.Context) bool {
	stats, err := h.store.GetDashboardStats(ctx)
	if err != nil {
		slog.Error("failed to build event stream snapshot", "error", err)
		return writeNamed(c, "error", map[string]string{
			"message": "could not read current state",
		})
	}

	// Urgency order, without the PEM. The snapshot is re-sent on every connect
	// and every resynchronise, so it carries only what a dashboard draws.
	cas, err := h.store.ListCAAuthorities(ctx, store.CAFilter{Sort: store.CASortUrgency})
	if err != nil {
		slog.Error("failed to list CAs for event stream snapshot", "error", err)
		return writeNamed(c, "error", map[string]string{
			"message": "could not read certificate authorities",
		})
	}

	summaries := make([]caSummary, 0, len(cas))
	for _, ca := range cas {
		summaries = append(summaries, caSummary{
			ID:                 ca.ID,
			Name:               ca.Name,
			CAType:             ca.CAType,
			Status:             ca.Status,
			DaysRemaining:      ca.DaysRemaining,
			NotAfter:           ca.NotAfter,
			IsCRLFresh:         ca.IsCRLFresh,
			HasCRL:             ca.CRLDistributionURL != "",
			CertificatesIssued: ca.CertificatesIssuedCount,
			LastAlertThreshold: ca.LastAlertThreshold,
			ParentCAID:         ca.ParentCAID,
		})
	}

	return writeNamed(c, "snapshot", snapshot{
		Stats:       stats,
		CAs:         summaries,
		ServerTime:  time.Now(),
		LastEventID: h.broker.LastID(),
	})
}

// parseLastEventID reads the resume point from the Last-Event-ID header, or
// from a query parameter for clients that cannot set headers.
func parseLastEventID(c *gin.Context) (uint64, bool) {
	raw := c.GetHeader("Last-Event-ID")
	if raw == "" {
		raw = c.Query("last_event_id")
	}
	if raw == "" {
		return 0, false
	}
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

// ── SSE framing ───────────────────────────────────────────
//
// Each helper reports whether the write succeeded. A failure means the client
// has gone, and the caller returns rather than looping on a dead connection.

func writeEvent(c *gin.Context, evt events.Event) bool {
	payload, err := json.Marshal(evt)
	if err != nil {
		slog.Error("failed to encode event", "topic", evt.Topic, "error", err)
		return true // Skip this one; the stream itself is still fine.
	}
	return writeRaw(c, fmt.Sprintf("id: %s\nevent: %s\ndata: %s\n\n", evt.StringID(), evt.Topic, payload))
}

func writeNamed(c *gin.Context, name string, data any) bool {
	payload, err := json.Marshal(data)
	if err != nil {
		slog.Error("failed to encode stream message", "event", name, "error", err)
		return true
	}
	return writeRaw(c, fmt.Sprintf("event: %s\ndata: %s\n\n", name, payload))
}

func writeRetry(c *gin.Context, d time.Duration) bool {
	return writeRaw(c, fmt.Sprintf("retry: %d\n\n", d.Milliseconds()))
}

func writeRaw(c *gin.Context, s string) bool {
	if _, err := c.Writer.WriteString(s); err != nil {
		return false
	}
	// Without an explicit flush the data sits in Go's buffer and the client
	// sees nothing until it fills.
	c.Writer.Flush()
	return true
}
