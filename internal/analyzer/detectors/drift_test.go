package detectors_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/agent-transponder/agent-transponder/internal/analyzer/detectors"
	"github.com/agent-transponder/agent-transponder/internal/types"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func promptEvent(eventID, content string, ts float64) *types.Event {
	return &types.Event{
		ID:        eventID,
		SessionID: "sess-drift",
		AgentID:   "agent-1",
		TenantID:  "tenant-1",
		Type:      types.EventPrompt,
		Severity:  types.SeverityInfo,
		Timestamp: time.Unix(0, 0).Add(time.Duration(ts * float64(time.Second))),
		Prompt:    &types.PromptData{Content: content, Role: "user"},
	}
}

func runDrift(t *testing.T, det *detectors.DriftDetector, events []*types.Event) []struct {
	ftype    string
	message  string
	conf     float64
	severity string
	ids      []string
} {
	t.Helper()
	var all []struct {
		ftype    string
		message  string
		conf     float64
		severity string
		ids      []string
	}
	for _, e := range events {
		fs, err := det.Analyze(e)
		if err != nil {
			t.Fatalf("Analyze error: %v", err)
		}
		for _, f := range fs {
			all = append(all, struct {
				ftype    string
				message  string
				conf     float64
				severity string
				ids      []string
			}{f.Type, f.Message, f.Confidence, f.Severity, f.EventIDs})
		}
	}
	return all
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

// Similar prompts should produce no drift detection.
// We use prompts with high word overlap so Jaccard similarity >> threshold (0.3).
func TestDriftDetector_NoDriftForSimilarPrompts(t *testing.T) {
	det := detectors.NewDriftDetector(0.3) // threshold=0.3 (Python default)
	// All three prompts share most tokens → Jaccard well above 0.3.
	events := []*types.Event{
		promptEvent("p-0", "search for machine learning papers on neural networks deep learning", 0),
		promptEvent("p-1", "search for machine learning papers on neural networks deep learning models", 1),
		promptEvent("p-2", "search for machine learning research papers on neural networks deep learning", 2),
	}

	findings := runDrift(t, det, events)
	if len(findings) != 0 {
		t.Errorf("expected no drift findings for similar prompts, got %d: %v", len(findings), findings[0].message)
	}
}

// Completely different prompts should trigger drift.
func TestDriftDetector_DetectsDrift(t *testing.T) {
	det := detectors.NewDriftDetector(0.3)
	events := []*types.Event{
		promptEvent("p-0", "search for machine learning papers", 0),
		promptEvent("p-1", "cook pasta with tomato sauce and basil", 1),
		promptEvent("p-2", "book a flight to paris france", 2),
	}

	findings := runDrift(t, det, events)
	if len(findings) == 0 {
		t.Fatal("expected drift detection for completely different prompts, got 0")
	}
	if findings[0].ftype != string(types.DetectionGoalDrift) {
		t.Errorf("expected goal_drift, got %s", findings[0].ftype)
	}
	if findings[0].conf <= 0 {
		t.Error("expected confidence > 0")
	}
}

// Below minPrompts (3), no detection should be emitted.
func TestDriftDetector_BelowMinPrompts(t *testing.T) {
	det := detectors.NewDriftDetector(0.3)
	events := []*types.Event{
		promptEvent("p-0", "search for papers", 0),
		promptEvent("p-1", "cook spaghetti", 1),
	}

	findings := runDrift(t, det, events)
	if len(findings) != 0 {
		t.Errorf("expected no findings with < minPrompts events, got %d", len(findings))
	}
}

// Empty events list should return no findings.
func TestDriftDetector_EmptyEvents(t *testing.T) {
	det := detectors.NewDriftDetector(0.3)
	findings := runDrift(t, det, nil)
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty input, got %d", len(findings))
	}
}

// Non-prompt events should be ignored.
func TestDriftDetector_IgnoresNonPromptEvents(t *testing.T) {
	det := detectors.NewDriftDetector(0.3)
	events := []*types.Event{
		promptEvent("p-0", "search for machine learning papers", 0),
		// Interleaved tool_call events — should be ignored
		{
			ID: "tc-0", SessionID: "sess-drift", AgentID: "agent-1", TenantID: "tenant-1",
			Type: types.EventToolCall, Severity: types.SeverityInfo,
			Timestamp: time.Unix(1, 0),
			ToolCall:  &types.ToolCallData{ToolName: "search", Success: true},
		},
		promptEvent("p-1", "cook pasta with tomato sauce", 2),
		promptEvent("p-2", "book a flight to paris", 3),
	}

	// We have 3 prompt events, 2 of which diverge → should fire.
	findings := runDrift(t, det, events)
	if len(findings) == 0 {
		t.Error("expected drift detection, got 0 (tool_call events should be ignored)")
	}
}

// Confidence must be in [0.0, 1.0].
func TestDriftDetector_ConfidenceInValidRange(t *testing.T) {
	det := detectors.NewDriftDetector(0.3)
	var events []*types.Event
	events = append(events, promptEvent("p-0", "search for machine learning papers", 0))
	for i := 1; i < 10; i++ {
		events = append(events, promptEvent(
			fmt.Sprintf("p-%d", i),
			fmt.Sprintf("completely unrelated topic number %d about cooking and travel", i),
			float64(i),
		))
	}

	findings := runDrift(t, det, events)
	for _, f := range findings {
		if f.conf < 0.0 || f.conf > 1.0 {
			t.Errorf("confidence out of range [0,1]: %f", f.conf)
		}
	}
}

// Severity should be ERROR when drift fraction >= 0.8 of subsequent prompts.
func TestDriftDetector_SeverityErrorAtHighDriftFraction(t *testing.T) {
	det := detectors.NewDriftDetector(0.3)
	// 1 reference + 4 subsequent all diverging = 100% drift fraction → ERROR.
	events := []*types.Event{
		promptEvent("p-0", "search for machine learning papers in computer science", 0),
		promptEvent("p-1", "cook italian pasta recipe with basil tomatoes", 1),
		promptEvent("p-2", "book flight tickets to paris london berlin", 2),
		promptEvent("p-3", "weather forecast rain snow sunny cold warm", 3),
		promptEvent("p-4", "stock market investment portfolio dividends", 4),
	}

	findings := runDrift(t, det, events)
	if len(findings) == 0 {
		t.Fatal("expected drift finding")
	}
	if findings[0].severity != string(types.SeverityError) {
		t.Errorf("expected severity=error at high drift fraction, got %s", findings[0].severity)
	}
}

// Drift is only emitted once per session (no re-emission after the first detection).
func TestDriftDetector_OnlyEmitsOnce(t *testing.T) {
	det := detectors.NewDriftDetector(0.3)
	var events []*types.Event
	events = append(events, promptEvent("p-0", "search for machine learning papers", 0))
	for i := 1; i < 6; i++ {
		events = append(events, promptEvent(
			fmt.Sprintf("p-%d", i),
			fmt.Sprintf("cook pasta topic %d", i),
			float64(i),
		))
	}

	findings := runDrift(t, det, events)
	if len(findings) != 1 {
		t.Errorf("expected exactly 1 drift finding (no re-emission), got %d", len(findings))
	}
}

// Cross-session isolation: drift in session A should not affect session B.
func TestDriftDetector_CrossSessionIsolation(t *testing.T) {
	det := detectors.NewDriftDetector(0.3)

	// Session A: very similar prompts — no drift (Jaccard well above 0.3).
	eventsA := []*types.Event{
		promptEvent("a-0", "search for machine learning papers on neural networks", 0),
		promptEvent("a-1", "search for machine learning research on neural networks", 1),
		promptEvent("a-2", "search for machine learning papers on deep neural networks", 2),
	}

	// Session B: drifting prompts — drift.
	eventsB := []*types.Event{
		{ID: "b-0", SessionID: "sess-B", AgentID: "agent-1", TenantID: "tenant-1",
			Type: types.EventPrompt, Severity: types.SeverityInfo, Timestamp: time.Unix(0, 0),
			Prompt: &types.PromptData{Content: "search for machine learning papers"}},
		{ID: "b-1", SessionID: "sess-B", AgentID: "agent-1", TenantID: "tenant-1",
			Type: types.EventPrompt, Severity: types.SeverityInfo, Timestamp: time.Unix(1, 0),
			Prompt: &types.PromptData{Content: "cook spaghetti with cheese"}},
		{ID: "b-2", SessionID: "sess-B", AgentID: "agent-1", TenantID: "tenant-1",
			Type: types.EventPrompt, Severity: types.SeverityInfo, Timestamp: time.Unix(2, 0),
			Prompt: &types.PromptData{Content: "book flight to paris"}},
	}

	findingsA := runDrift(t, det, eventsA)
	if len(findingsA) != 0 {
		t.Errorf("session A: expected no drift, got %d findings", len(findingsA))
	}

	findingsB := runDrift(t, det, eventsB)
	if len(findingsB) == 0 {
		t.Error("session B: expected drift detection, got 0")
	}
	for _, f := range findingsB {
		if f.ftype != string(types.DetectionGoalDrift) {
			t.Errorf("session B: expected goal_drift, got %s", f.ftype)
		}
	}
}
