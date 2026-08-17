package events

import (
	"sync"
	"testing"
	"time"
)

// drain reads whatever is currently queued without blocking.
func drain(sub *Subscription) []Event {
	var out []Event
	for {
		select {
		case evt, ok := <-sub.Events():
			if !ok {
				return out
			}
			out = append(out, evt)
		default:
			return out
		}
	}
}

func TestPublishReachesSubscriber(t *testing.T) {
	b := NewBroker()
	defer b.Stop()

	sub := b.Subscribe()
	defer sub.Close()

	b.PublishTopic(TopicCAExpiryAlert, SeverityCritical, "ca-1", map[string]any{"days": 10})

	got := drain(sub)
	if len(got) != 1 {
		t.Fatalf("received %d events, want 1", len(got))
	}
	if got[0].Topic != TopicCAExpiryAlert {
		t.Errorf("topic = %q", got[0].Topic)
	}
	if got[0].Severity != SeverityCritical {
		t.Errorf("severity = %q", got[0].Severity)
	}
	if got[0].EntityID != "ca-1" {
		t.Errorf("entity = %q", got[0].EntityID)
	}
	if got[0].Timestamp.IsZero() {
		t.Error("timestamp should be filled in by the broker")
	}
}

func TestEventIDsAreMonotonic(t *testing.T) {
	b := NewBroker()
	defer b.Stop()

	sub := b.Subscribe()
	defer sub.Close()

	for i := 0; i < 5; i++ {
		b.PublishTopic(TopicCertIssued, SeverityInfo, "c", nil)
	}

	got := drain(sub)
	if len(got) != 5 {
		t.Fatalf("received %d events, want 5", len(got))
	}
	for i, evt := range got {
		if evt.ID != uint64(i+1) {
			t.Fatalf("event %d has ID %d, want %d", i, evt.ID, i+1)
		}
	}
	if b.LastID() != 5 {
		t.Errorf("LastID = %d, want 5", b.LastID())
	}
}

func TestTopicFiltering(t *testing.T) {
	b := NewBroker()
	defer b.Stop()

	all := b.Subscribe()
	caOnly := b.Subscribe(TopicCAExpiryAlert)
	caWildcard := b.Subscribe("ca.*")
	certOnly := b.Subscribe(TopicCertIssued, TopicCertRenewed)
	defer all.Close()
	defer caOnly.Close()
	defer caWildcard.Close()
	defer certOnly.Close()

	b.PublishTopic(TopicCAExpiryAlert, SeverityCritical, "ca-1", nil)
	b.PublishTopic(TopicCAHealth, SeverityInfo, "ca-1", nil)
	b.PublishTopic(TopicCertIssued, SeverityInfo, "c-1", nil)

	cases := map[string]struct {
		sub  *Subscription
		want int
	}{
		"no filter receives all":     {all, 3},
		"exact topic":                {caOnly, 1},
		"prefix wildcard covers two": {caWildcard, 2},
		"multiple topics":            {certOnly, 1},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := len(drain(tc.sub)); got != tc.want {
				t.Fatalf("received %d events, want %d", got, tc.want)
			}
		})
	}
}

// The property the whole design rests on: a consumer that has stopped reading
// must not be able to block the CA health sweep.
func TestSlowSubscriberNeverBlocksPublish(t *testing.T) {
	b := NewBroker(WithBufferSize(4))
	defer b.Stop()

	stalled := b.Subscribe()
	defer stalled.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			b.PublishTopic(TopicCAHealth, SeverityInfo, "ca-1", i)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Publish blocked on a subscriber that stopped reading")
	}

	if !stalled.Lossy() {
		t.Error("a subscriber that fell 1000 events behind on a 4-slot buffer should be flagged lossy")
	}
}

// Falling behind must cost the oldest events, not the newest: a dashboard
// showing a CA as healthy after it has gone critical is the failure mode.
func TestDropsOldestNotNewest(t *testing.T) {
	b := NewBroker(WithBufferSize(4))
	defer b.Stop()

	sub := b.Subscribe()
	defer sub.Close()

	for i := 1; i <= 10; i++ {
		b.PublishTopic(TopicCAHealth, SeverityInfo, "ca-1", i)
	}

	got := drain(sub)
	if len(got) == 0 {
		t.Fatal("expected some events to survive")
	}

	// Whatever survived must include the most recent event.
	last := got[len(got)-1]
	if last.ID != 10 {
		t.Fatalf("newest retained event has ID %d, want 10 — the newest state was dropped", last.ID)
	}
	if !sub.Lossy() {
		t.Error("expected the subscription to be flagged lossy")
	}
}

// Losses must stay confined to the subscriber that caused them. A stalled wall
// display must not cost the notification dispatcher an alert.
func TestOneSlowSubscriberDoesNotCostAnother(t *testing.T) {
	b := NewBroker()
	defer b.Stop()

	stalled := b.SubscribeWithBuffer(4)
	healthy := b.SubscribeWithBuffer(4)
	defer stalled.Close()
	defer healthy.Close()

	// Drain the healthy subscriber synchronously after each publish, so it is
	// never behind. Reading on another goroutine would make this test depend
	// on the scheduler rather than on the broker's isolation guarantee.
	const total = 50
	received := 0
	for i := 0; i < total; i++ {
		b.PublishTopic(TopicCertIssued, SeverityInfo, "c", i)
		select {
		case <-healthy.Events():
			received++
		default:
			t.Fatalf("event %d never reached the attentive subscriber", i)
		}
	}

	if received != total {
		t.Fatalf("attentive subscriber received %d of %d events", received, total)
	}
	if healthy.Lossy() {
		t.Errorf("a subscriber that kept up was flagged lossy (%d dropped)", healthy.Dropped())
	}
	if !stalled.Lossy() {
		t.Error("the stalled subscriber should be flagged lossy")
	}
}

func TestPerSubscriptionBufferSizes(t *testing.T) {
	b := NewBroker(WithBufferSize(4))
	defer b.Stop()

	small := b.SubscribeWithBuffer(2)
	large := b.SubscribeWithBuffer(64)
	defer small.Close()
	defer large.Close()

	for i := 0; i < 32; i++ {
		b.PublishTopic(TopicCAHealth, SeverityInfo, "ca", i)
	}

	if !small.Lossy() {
		t.Error("a 2-slot subscriber should have dropped events after 32 publishes")
	}
	if large.Lossy() {
		t.Errorf("a 64-slot subscriber should have absorbed 32 events, dropped %d", large.Dropped())
	}
	if got := len(drain(large)); got != 32 {
		t.Fatalf("deep-buffered subscriber holds %d events, want 32", got)
	}
}

func TestReplayAfterReconnect(t *testing.T) {
	b := NewBroker(WithHistorySize(10))
	defer b.Stop()

	for i := 0; i < 5; i++ {
		b.PublishTopic(TopicCAHealth, SeverityInfo, "ca-1", i)
	}

	// A client that last saw event 2 should get 3, 4 and 5.
	replayed, complete := b.Replay(2)
	if !complete {
		t.Fatal("replay should be complete when the gap is inside the retained history")
	}
	if len(replayed) != 3 {
		t.Fatalf("replayed %d events, want 3", len(replayed))
	}
	if replayed[0].ID != 3 || replayed[2].ID != 5 {
		t.Fatalf("replayed IDs %d..%d, want 3..5", replayed[0].ID, replayed[2].ID)
	}
}

// When the gap is bigger than the retained history the caller cannot be made
// whole, and must be told to re-fetch rather than silently miss events.
func TestReplayReportsIncompleteWhenHistoryRolledOver(t *testing.T) {
	b := NewBroker(WithHistorySize(4))
	defer b.Stop()

	for i := 0; i < 20; i++ {
		b.PublishTopic(TopicCAHealth, SeverityInfo, "ca-1", i)
	}

	if _, complete := b.Replay(1); complete {
		t.Fatal("expected an incomplete replay: event 2 has long since rolled out of a 4-event ring")
	}

	// A client that is nearly current can still be resumed.
	if _, complete := b.Replay(18); !complete {
		t.Fatal("expected a complete replay for a client that is only one event behind")
	}
}

func TestReplayFiltersByTopic(t *testing.T) {
	b := NewBroker(WithHistorySize(20))
	defer b.Stop()

	b.PublishTopic(TopicCAExpiryAlert, SeverityCritical, "ca-1", nil)
	b.PublishTopic(TopicCertIssued, SeverityInfo, "c-1", nil)
	b.PublishTopic(TopicCAHealth, SeverityInfo, "ca-1", nil)

	replayed, _ := b.Replay(0, "ca.*")
	if len(replayed) != 2 {
		t.Fatalf("replayed %d events, want 2 matching ca.*", len(replayed))
	}
}

func TestReplayOnEmptyBroker(t *testing.T) {
	b := NewBroker()
	defer b.Stop()

	replayed, complete := b.Replay(0)
	if len(replayed) != 0 {
		t.Fatalf("replayed %d events from an empty broker", len(replayed))
	}
	if !complete {
		t.Error("a caller at ID 0 against an empty broker is already current")
	}
}

func TestHistoryIsBounded(t *testing.T) {
	b := NewBroker(WithHistorySize(5))
	defer b.Stop()

	for i := 0; i < 100; i++ {
		b.PublishTopic(TopicCertIssued, SeverityInfo, "c", i)
	}

	replayed, _ := b.Replay(0)
	if len(replayed) > 5 {
		t.Fatalf("history holds %d events, want at most 5", len(replayed))
	}
	// The retained window must be the most recent one.
	if replayed[len(replayed)-1].ID != 100 {
		t.Fatalf("newest retained ID is %d, want 100", replayed[len(replayed)-1].ID)
	}
}

func TestCloseStopsDelivery(t *testing.T) {
	b := NewBroker()
	defer b.Stop()

	sub := b.Subscribe()
	sub.Close()

	// The channel must be closed so `for range` terminates.
	if _, ok := <-sub.Events(); ok {
		t.Fatal("expected a closed channel after Close")
	}

	// Publishing to a broker with no live subscribers must not panic.
	b.PublishTopic(TopicCertIssued, SeverityInfo, "c", nil)

	if b.SubscriberCount() != 0 {
		t.Fatalf("subscriber count = %d, want 0", b.SubscriberCount())
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	b := NewBroker()
	defer b.Stop()

	sub := b.Subscribe()
	sub.Close()
	sub.Close() // must not panic on a re-closed channel
}

func TestStopClosesEverySubscription(t *testing.T) {
	b := NewBroker()

	subs := []*Subscription{b.Subscribe(), b.Subscribe(), b.Subscribe()}
	b.Stop()

	for i, sub := range subs {
		if _, ok := <-sub.Events(); ok {
			t.Fatalf("subscription %d was not closed by Stop", i)
		}
	}

	// Stop must be idempotent, matching CAMonitor's sync.Once contract.
	b.Stop()

	// Publishing after Stop is a no-op rather than a panic.
	b.PublishTopic(TopicCertIssued, SeverityInfo, "c", nil)
}

// Subscribing after Stop must hand back something that terminates, or a
// consumer's `for range` would hang for the life of the process.
func TestSubscribeAfterStopReturnsClosed(t *testing.T) {
	b := NewBroker()
	b.Stop()

	sub := b.Subscribe()
	if _, ok := <-sub.Events(); ok {
		t.Fatal("a subscription taken after Stop should already be closed")
	}
	sub.Close()
}

func TestConcurrentPublishAndSubscribe(t *testing.T) {
	b := NewBroker(WithBufferSize(16))
	defer b.Stop()

	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				b.PublishTopic(TopicCAHealth, SeverityInfo, "ca", j)
			}
		}()
	}

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sub := b.Subscribe("ca.*")
			defer sub.Close()
			deadline := time.After(2 * time.Second)
			for {
				select {
				case _, ok := <-sub.Events():
					if !ok {
						return
					}
				case <-deadline:
					return
				}
			}
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent publish/subscribe did not settle")
	}

	if got := b.LastID(); got != 1600 {
		t.Fatalf("LastID = %d, want 1600 — IDs must stay unique under concurrency", got)
	}
}

func TestStringID(t *testing.T) {
	if got := (Event{ID: 42}).StringID(); got != "42" {
		t.Fatalf("StringID = %q, want \"42\"", got)
	}
}

// Progress is state, not news. A channel left at INFO would otherwise receive
// one message every few seconds for the length of a range scan — and a team
// that mutes that channel has also muted the CA expiry alerts sharing it.
func TestScanProgressIsStreamOnly(t *testing.T) {
	if IsNotifiable(TopicDiscoveryProgress) {
		t.Error("scan progress may be delivered to notification channels")
	}
	if !IsNotifiable(TopicDiscoveryUnmanaged) {
		t.Error("the finding a scan exists to produce is not notifiable")
	}
	if !IsNotifiable(TopicCAExpiryAlert) {
		t.Error("CA expiry alerts are not notifiable")
	}
	// An unrecognised topic is notifiable. Producers add topics over time, and
	// a rule that silently suppressed anything it did not recognise would turn
	// every new event type into a coverage gap nobody sees.
	if !IsNotifiable("something.new") {
		t.Error("an unknown topic was suppressed")
	}

	// A topic that can be selected in a channel filter and will never arrive is
	// the same failure as a typo'd one: configured on screen, silent in fact.
	for _, topic := range AllTopics() {
		if !IsNotifiable(topic) {
			t.Errorf("AllTopics offers %q, which is never delivered", topic)
		}
	}

	// The stream still carries it: that is the whole point.
	broker := NewBroker()
	defer broker.Stop()
	sub := broker.Subscribe()
	broker.PublishTopic(TopicDiscoveryProgress, SeverityInfo, "scan-1", map[string]any{"scanned_count": 4})

	select {
	case evt := <-sub.Events():
		if evt.Topic != TopicDiscoveryProgress {
			t.Errorf("got topic %q", evt.Topic)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("progress never reached a stream subscriber")
	}
}
