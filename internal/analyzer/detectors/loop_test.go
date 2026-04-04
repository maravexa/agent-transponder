package detectors_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/agent-transponder/agent-transponder/internal/analyzer/detectors"
	"github.com/agent-transponder/agent-transponder/internal/types"
)

// ---------------------------------------------------------------------------
// Helpers (mirror Python test helpers)
// ---------------------------------------------------------------------------

func toolEvent(eventID, toolName string, ts float64) *types.Event {
	return &types.Event{
		ID:        eventID,
		SessionID: "sess-1",
		AgentID:   "agent-1",
		TenantID:  "tenant-1",
		Type:      types.EventToolCall,
		Severity:  types.SeverityInfo,
		Timestamp: time.Unix(0, 0).Add(time.Duration(ts * float64(time.Second))),
		ToolCall: &types.ToolCallData{
			ToolName:   toolName,
			Success:    true,
			RetryCount: 0,
		},
	}
}

func makeRepeatingSequence(toolNames []string, repetitions int) []*types.Event {
	var events []*types.Event
	idx := 0
	for rep := 0; rep < repetitions; rep++ {
		for _, name := range toolNames {
			events = append(events, toolEvent(
				fmt.Sprintf("e-%d", idx),
				name,
				float64(idx),
			))
			idx++
		}
	}
	return events
}

// newLoopDetector creates a detector with the given threshold/window,
// using the Python reference defaults (min_sequence_len=2, min_repetitions=3).
//
//nolint:unparam // threshold is always 3 in tests; kept as a parameter for readability
func newLoopDetector(threshold, windowSeconds int) *detectors.LoopDetector {
	return detectors.NewLoopDetector(threshold, windowSeconds)
}

// runLoop feeds all events into the detector and returns accumulated findings.
func runLoop(t *testing.T, det *detectors.LoopDetector, events []*types.Event) []string {
	t.Helper()
	var findingTypes []string
	for _, e := range events {
		fs, err := det.Analyze(e)
		if err != nil {
			t.Fatalf("Analyze error: %v", err)
		}
		for _, f := range fs {
			findingTypes = append(findingTypes, f.Type)
		}
	}
	return findingTypes
}

// ---------------------------------------------------------------------------
// Test cases (mirror Python TestLoopDetector)
// ---------------------------------------------------------------------------

// test_detects_clear_loop: [search, write] repeated 4 times should trigger.
func TestLoopDetector_DetectsClearLoop(t *testing.T) {
	det := newLoopDetector(3, 0) // threshold=3, no window
	events := makeRepeatingSequence([]string{"search", "write"}, 4)

	// Feed all events and collect findings.
	var findings []struct {
		ftype    string
		eventIDs []string
		message  string
		conf     float64
	}
	for _, e := range events {
		fs, err := det.Analyze(e)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fs {
			findings = append(findings, struct {
				ftype    string
				eventIDs []string
				message  string
				conf     float64
			}{f.Type, f.EventIDs, f.Message, f.Confidence})
		}
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ftype != string(types.DetectionLoop) {
		t.Errorf("expected type %s, got %s", types.DetectionLoop, f.ftype)
	}
	if f.conf <= 0 {
		t.Errorf("expected confidence > 0, got %f", f.conf)
	}
	// In streaming mode the detector fires when the threshold (3 reps = 6 IDs)
	// is first reached.  The Python batch processor would see all 4 reps = 8 IDs,
	// but per-event streaming emits as soon as min_repetitions is satisfied.
	if len(f.eventIDs) < 6 {
		t.Errorf("expected at least 6 event IDs (threshold 3 reps × 2 tools), got %d", len(f.eventIDs))
	}
}

// test_detects_loop_at_minimum_threshold: exactly 3 repetitions should fire.
func TestLoopDetector_DetectsAtMinimumThreshold(t *testing.T) {
	det := newLoopDetector(3, 0)
	events := makeRepeatingSequence([]string{"fetch", "parse"}, 3)

	types_ := runLoop(t, det, events)
	if len(types_) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(types_))
	}
	if types_[0] != string(types.DetectionLoop) {
		t.Errorf("expected task_loop, got %s", types_[0])
	}
}

// test_below_threshold_no_detection: only 2 reps (< 3) should NOT fire.
func TestLoopDetector_BelowThresholdNoDetection(t *testing.T) {
	det := newLoopDetector(3, 0)
	events := makeRepeatingSequence([]string{"search", "write"}, 2)

	types_ := runLoop(t, det, events)
	if len(types_) != 0 {
		t.Errorf("expected no findings, got %d", len(types_))
	}
}

// test_no_loop_in_random_sequence: unique tool names should produce no detection.
func TestLoopDetector_NoLoopInRandomSequence(t *testing.T) {
	det := newLoopDetector(3, 0)
	var events []*types.Event
	for i := 0; i < 10; i++ {
		events = append(events, toolEvent(
			fmt.Sprintf("e-%d", i),
			fmt.Sprintf("tool_%d", i),
			float64(i),
		))
	}

	types_ := runLoop(t, det, events)
	if len(types_) != 0 {
		t.Errorf("expected no findings, got %d", len(types_))
	}
}

// test_no_loop_when_tools_vary: ABCABD pattern should not fire.
func TestLoopDetector_NoLoopWhenToolsVary(t *testing.T) {
	det := newLoopDetector(3, 0)
	seq := []string{"alpha", "beta", "gamma", "alpha", "beta", "delta"}
	events := make([]*types.Event, 0, len(seq))
	for i, name := range seq {
		events = append(events, toolEvent(fmt.Sprintf("e-%d", i), name, float64(i)))
	}

	types_ := runLoop(t, det, events)
	if len(types_) != 0 {
		t.Errorf("expected no findings, got %d", len(types_))
	}
}

// test_empty_events: empty input returns no findings.
func TestLoopDetector_EmptyEvents(t *testing.T) {
	det := newLoopDetector(3, 0)
	types_ := runLoop(t, det, nil)
	if len(types_) != 0 {
		t.Errorf("expected no findings for empty input, got %d", len(types_))
	}
}

// test_single_event: a single event cannot form a loop.
func TestLoopDetector_SingleEvent(t *testing.T) {
	det := newLoopDetector(3, 0)
	types_ := runLoop(t, det, []*types.Event{toolEvent("e-0", "search", 0)})
	if len(types_) != 0 {
		t.Errorf("expected no findings for single event, got %d", len(types_))
	}
}

// test_ignores_non_tool_events: prompt events should be invisible to the detector.
func TestLoopDetector_IgnoresNonToolEvents(t *testing.T) {
	det := newLoopDetector(3, 0)
	toolEvents := makeRepeatingSequence([]string{"read", "write"}, 3)

	// Build mixed event list with interleaved prompt events.
	events := make([]*types.Event, 0, len(toolEvents)*2)
	for i, te := range toolEvents {
		events = append(events, te)
		if i%2 == 0 {
			events = append(events, &types.Event{
				ID:        fmt.Sprintf("p-%d", i),
				SessionID: "sess-1",
				AgentID:   "agent-1",
				TenantID:  "tenant-1",
				Type:      types.EventPrompt,
				Severity:  types.SeverityInfo,
				Timestamp: time.Unix(int64(i), 0),
				Prompt:    &types.PromptData{Content: fmt.Sprintf("do something %d", i), Role: "user"},
			})
		}
	}

	types_ := runLoop(t, det, events)
	if len(types_) != 1 {
		t.Errorf("expected 1 finding (prompt events should be ignored), got %d", len(types_))
	}
	if types_[0] != string(types.DetectionLoop) {
		t.Errorf("expected task_loop, got %s", types_[0])
	}
}

// test_confidence_increases_with_repetitions: more reps → higher confidence.
func TestLoopDetector_ConfidenceIncreasesWithRepetitions(t *testing.T) {
	// Use min_sequence_len=1, min_repetitions=3 (same as the Python test which
	// uses LoopDetectorConfig(min_sequence_len=1, min_repetitions=3)).
	detFew := detectors.NewLoopDetectorFull(3, 0, 1)
	detMany := detectors.NewLoopDetectorFull(3, 0, 1)

	fewEvents := makeRepeatingSequence([]string{"ping"}, 3)
	manyEvents := makeRepeatingSequence([]string{"ping"}, 7)

	collectConf := func(det *detectors.LoopDetector, events []*types.Event) float64 {
		var maxConf float64
		for _, e := range events {
			fs, err := det.Analyze(e)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range fs {
				if f.Confidence > maxConf {
					maxConf = f.Confidence
				}
			}
		}
		return maxConf
	}

	confFew := collectConf(detFew, fewEvents)
	confMany := collectConf(detMany, manyEvents)

	if confFew == 0 {
		t.Error("expected a finding for few repetitions")
	}
	if confMany < confFew {
		t.Errorf("expected more reps → higher confidence: few=%f many=%f", confFew, confMany)
	}
}

// TestLoopDetector_CrossSessionIsolation: events from different sessions must
// not interfere with each other.
func TestLoopDetector_CrossSessionIsolation(t *testing.T) {
	det := newLoopDetector(3, 0)

	// Session A: only 2 repetitions (below threshold).
	eventsA := makeRepeatingSequence([]string{"search", "write"}, 2)

	// Session B: 3 repetitions with different session ID.
	eventsB := makeRepeatingSequence([]string{"search", "write"}, 3)
	for _, e := range eventsB {
		e.SessionID = "sess-2"
	}

	// Feed session A — should produce no findings.
	typesA := runLoop(t, det, eventsA)
	if len(typesA) != 0 {
		t.Errorf("session A: expected no findings (only 2 reps), got %d", len(typesA))
	}

	// Feed session B — should produce a finding for its own session.
	var typesB []string
	for _, e := range eventsB {
		fs, err := det.Analyze(e)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fs {
			typesB = append(typesB, f.Type)
		}
	}
	if len(typesB) != 1 {
		t.Errorf("session B: expected 1 finding, got %d", len(typesB))
	}
}
