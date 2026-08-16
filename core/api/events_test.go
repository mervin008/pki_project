package api

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certpilot/certpilot/core/events"
	"github.com/certpilot/certpilot/core/store"
	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

// streamServer starts a real HTTP server carrying the SSE route.
//
// httptest.NewServer rather than httptest.NewRecorder: a recorder buffers
// everything and returns only when the handler exits, which cannot show that a
// stream delivers incrementally, and cannot exercise the write deadline at all
// — the property this endpoint most needs to prove.
func streamServer(t *testing.T, writeTimeout time.Duration) (*httptest.Server, *events.Broker, store.Store) {
	t.Helper()

	st := store.NewMemoryStore()
	broker := events.NewBroker()

	r := gin.New()
	h := NewEventsHandler(st, broker)
	r.GET("/api/v1/events", h.Stream)

	srv := httptest.NewUnstartedServer(r)
	srv.Config.WriteTimeout = writeTimeout
	srv.Start()

	t.Cleanup(func() {
		srv.Close()
		broker.Stop()
		st.Close()
	})
	return srv, broker, st
}

// sseFrame is one parsed `event:` / `data:` block.
type sseFrame struct {
	ID      string
	Event   string
	Data    string
	Comment string
}

// readFrames reads frames until n are collected or the deadline passes.
func readFrames(t *testing.T, body *bufio.Reader, n int, timeout time.Duration) []sseFrame {
	t.Helper()

	done := make(chan []sseFrame, 1)
	go func() {
		var frames []sseFrame
		var cur sseFrame
		for len(frames) < n {
			line, err := body.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimRight(line, "\r\n")

			switch {
			case line == "":
				if cur.Event != "" || cur.Data != "" || cur.Comment != "" {
					frames = append(frames, cur)
					cur = sseFrame{}
				}
			case strings.HasPrefix(line, ":"):
				cur.Comment = strings.TrimSpace(line[1:])
				frames = append(frames, cur)
				cur = sseFrame{}
			case strings.HasPrefix(line, "id: "):
				cur.ID = strings.TrimPrefix(line, "id: ")
			case strings.HasPrefix(line, "event: "):
				cur.Event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				cur.Data = strings.TrimPrefix(line, "data: ")
			}
		}
		done <- frames
	}()

	select {
	case frames := <-done:
		return frames
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %d SSE frames", n)
		return nil
	}
}

func connect(t *testing.T, srv *httptest.Server, lastEventID string) (*bufio.Reader, func()) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/events", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	return bufio.NewReader(resp.Body), func() { resp.Body.Close() }
}

func TestStreamSendsSnapshotOnConnect(t *testing.T) {
	srv, _, _ := streamServer(t, 0)

	body, closeBody := connect(t, srv, "")
	defer closeBody()

	frames := readFrames(t, body, 1, 5*time.Second)
	if len(frames) == 0 {
		t.Fatal("no frames received")
	}
	if frames[0].Event != "snapshot" {
		t.Fatalf("first frame is %q, want snapshot — a client must never render from an empty store", frames[0].Event)
	}

	var snap snapshot
	if err := json.Unmarshal([]byte(frames[0].Data), &snap); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
	if snap.Stats == nil {
		t.Error("snapshot carries no stats")
	}
	if snap.ServerTime.IsZero() {
		t.Error("snapshot carries no server time; a client cannot detect clock skew")
	}
	// The in-memory store seeds sample CAs.
	if len(snap.CAs) == 0 {
		t.Error("snapshot carries no CAs")
	}
}

// The snapshot must not carry certificate PEM: several kilobytes per CA, sent
// on every connect and every resync, and useless to a dashboard.
func TestSnapshotOmitsCertificatePEM(t *testing.T) {
	srv, _, _ := streamServer(t, 0)

	body, closeBody := connect(t, srv, "")
	defer closeBody()

	frames := readFrames(t, body, 1, 5*time.Second)
	if strings.Contains(frames[0].Data, "BEGIN CERTIFICATE") ||
		strings.Contains(frames[0].Data, "certificate_pem") {
		t.Fatal("snapshot includes certificate PEM")
	}
}

func TestStreamDeliversPublishedEvents(t *testing.T) {
	srv, broker, _ := streamServer(t, 0)

	body, closeBody := connect(t, srv, "")
	defer closeBody()

	// Consume the snapshot first.
	readFrames(t, body, 1, 5*time.Second)

	go func() {
		time.Sleep(100 * time.Millisecond)
		broker.PublishTopic(events.TopicCAExpiryAlert, events.SeverityCritical, "ca-1",
			map[string]any{"ca_name": "Issuing CA", "days_remaining": 10})
	}()

	frames := readFrames(t, body, 1, 5*time.Second)
	if len(frames) == 0 {
		t.Fatal("no event received")
	}
	if frames[0].Event != events.TopicCAExpiryAlert {
		t.Fatalf("event = %q, want %q", frames[0].Event, events.TopicCAExpiryAlert)
	}
	// The id: field is what a browser echoes back as Last-Event-ID.
	if frames[0].ID == "" {
		t.Error("event has no id, so a reconnecting client cannot resume")
	}

	var evt events.Event
	if err := json.Unmarshal([]byte(frames[0].Data), &evt); err != nil {
		t.Fatalf("event data is not valid JSON: %v", err)
	}
	if evt.Severity != events.SeverityCritical {
		t.Errorf("severity = %q", evt.Severity)
	}
}

// The regression test for the blocker this step existed to fix: the server's
// 30s WriteTimeout severed every stream after exactly thirty seconds. A short
// timeout here proves the per-connection deadline is cleared, without making
// the suite wait half a minute.
func TestStreamOutlivesTheServerWriteTimeout(t *testing.T) {
	const writeTimeout = 600 * time.Millisecond
	srv, broker, _ := streamServer(t, writeTimeout)

	body, closeBody := connect(t, srv, "")
	defer closeBody()

	readFrames(t, body, 1, 5*time.Second)

	// Publish well after the write timeout would have killed the connection.
	go func() {
		time.Sleep(writeTimeout * 3)
		broker.PublishTopic(events.TopicCAHealth, events.SeverityWarning, "ca-1", nil)
	}()

	frames := readFrames(t, body, 1, 10*time.Second)
	if len(frames) == 0 {
		t.Fatalf("stream died before %v elapsed; the write deadline was not cleared", writeTimeout*3)
	}
	if frames[0].Event != events.TopicCAHealth {
		t.Fatalf("event = %q, want the event published after the timeout window", frames[0].Event)
	}
}

// Without a heartbeat a wall display cannot tell a calm PKI from a dead
// connection, which is the failure this feature exists to prevent.
func TestHeartbeatKeepsAnIdleStreamAlive(t *testing.T) {
	srv, _, _ := streamServer(t, 0)

	// Shorten the interval for the test rather than waiting fifteen seconds.
	original := heartbeatInterval
	heartbeatInterval = 150 * time.Millisecond
	defer func() { heartbeatInterval = original }()

	body, closeBody := connect(t, srv, "")
	defer closeBody()

	readFrames(t, body, 1, 5*time.Second)

	frames := readFrames(t, body, 2, 5*time.Second)
	for _, f := range frames {
		if f.Comment == "" {
			t.Fatalf("expected heartbeat comments on an idle stream, got event %q", f.Event)
		}
	}
}

func TestProxyBufferingIsDisabled(t *testing.T) {
	srv, _, _ := streamServer(t, 0)

	resp, err := http.Get(srv.URL + "/api/v1/events")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer resp.Body.Close()

	// nginx buffers proxied responses by default, which delivers the stream in
	// chunks and makes a live dashboard look frozen.
	if got := resp.Header.Get("X-Accel-Buffering"); got != "no" {
		t.Errorf("X-Accel-Buffering = %q, want \"no\"", got)
	}
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-cache") {
		t.Errorf("Cache-Control = %q, want no-cache", got)
	}
}

func TestReconnectResumesFromLastEventID(t *testing.T) {
	srv, broker, _ := streamServer(t, 0)

	for i := 0; i < 5; i++ {
		broker.PublishTopic(events.TopicCertIssued, events.SeverityInfo, "c", i)
	}

	// Reconnect claiming to have seen event 2.
	body, closeBody := connect(t, srv, "2")
	defer closeBody()

	frames := readFrames(t, body, 3, 5*time.Second)
	if len(frames) < 3 {
		t.Fatalf("received %d frames, want the 3 missed events replayed", len(frames))
	}
	// A resumed stream replays events rather than re-sending a snapshot.
	if frames[0].Event == "snapshot" {
		t.Fatal("a resumable reconnect should replay events, not re-send the whole snapshot")
	}
	if frames[0].ID != "3" {
		t.Fatalf("first replayed id = %q, want 3", frames[0].ID)
	}
}

// When the gap predates the retained history the client cannot be made whole,
// and must get a fresh snapshot rather than deltas applied to a stale base.
func TestReconnectFallsBackToSnapshotWhenGapIsTooLarge(t *testing.T) {
	st := store.NewMemoryStore()
	broker := events.NewBroker(events.WithHistorySize(4))

	r := gin.New()
	r.GET("/api/v1/events", NewEventsHandler(st, broker).Stream)
	srv := httptest.NewServer(r)
	defer func() { srv.Close(); broker.Stop(); st.Close() }()

	for i := 0; i < 50; i++ {
		broker.PublishTopic(events.TopicCertIssued, events.SeverityInfo, "c", i)
	}

	body, closeBody := connect(t, srv, "1")
	defer closeBody()

	frames := readFrames(t, body, 1, 5*time.Second)
	if frames[0].Event != "snapshot" {
		t.Fatalf("first frame is %q, want snapshot — an unfillable gap must not be papered over", frames[0].Event)
	}
}

func TestBrokerShutdownClosesTheStream(t *testing.T) {
	srv, broker, _ := streamServer(t, 0)

	body, closeBody := connect(t, srv, "")
	defer closeBody()

	readFrames(t, body, 1, 5*time.Second)

	// Stopping the broker must end the handler, so the browser reconnects to a
	// new process instead of holding a dead socket. If it did not, the server's
	// graceful shutdown would block for its whole grace period.
	broker.Stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := body.ReadString('\n'); err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream stayed open after the broker stopped")
	}
}

func TestClientDisconnectReleasesTheSubscription(t *testing.T) {
	srv, broker, _ := streamServer(t, 0)

	body, closeBody := connect(t, srv, "")
	readFrames(t, body, 1, 5*time.Second)

	if got := broker.SubscriberCount(); got != 1 {
		t.Fatalf("subscriber count = %d, want 1 while connected", got)
	}

	closeBody()

	// The handler notices via the request context and unsubscribes.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if broker.SubscriberCount() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("subscription leaked after the client disconnected (count = %d)", broker.SubscriberCount())
}

func TestParseLastEventID(t *testing.T) {
	cases := []struct {
		header, query string
		wantID        uint64
		wantOK        bool
	}{
		{header: "42", wantID: 42, wantOK: true},
		{query: "17", wantID: 17, wantOK: true},
		{header: "42", query: "17", wantID: 42, wantOK: true}, // header wins
		{wantOK: false},
		{header: "not-a-number", wantOK: false},
		{header: "-1", wantOK: false},
	}

	for _, tc := range cases {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		url := "/api/v1/events"
		if tc.query != "" {
			url += "?last_event_id=" + tc.query
		}
		c.Request = httptest.NewRequest(http.MethodGet, url, nil)
		if tc.header != "" {
			c.Request.Header.Set("Last-Event-ID", tc.header)
		}

		gotID, gotOK := parseLastEventID(c)
		if gotID != tc.wantID || gotOK != tc.wantOK {
			t.Errorf("header=%q query=%q: got (%d, %v), want (%d, %v)",
				tc.header, tc.query, gotID, gotOK, tc.wantID, tc.wantOK)
		}
	}
}
