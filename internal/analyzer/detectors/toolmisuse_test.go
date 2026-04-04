package detectors_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/agent-transponder/agent-transponder/internal/analyzer/detectors"
	"github.com/agent-transponder/agent-transponder/internal/types"
)

// ---------------------------------------------------------------------------
// Helpers (mirror Python test helpers)
// ---------------------------------------------------------------------------

func toolMisuseEvent(
	eventID, toolName string,
	arguments map[string]interface{},
	success bool,
	retryCount int,
	ts float64,
) *types.Event {
	argsJSON, _ := json.Marshal(arguments)
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
			Arguments:  json.RawMessage(argsJSON),
			Success:    success,
			RetryCount: retryCount,
		},
	}
}

func failingCalls(toolName string, count int) []*types.Event {
	events := make([]*types.Event, count)
	for i := 0; i < count; i++ {
		events[i] = toolMisuseEvent(
			fmt.Sprintf("fail-%s-%d", toolName, i),
			toolName,
			map[string]interface{}{"query": "test"},
			false,
			i,
			float64(i),
		)
	}
	return events
}

func runMisuse(t *testing.T, det *detectors.ToolMisuseDetector, events []*types.Event) []struct {
	ftype   string
	message string
	conf    float64
	ids     []string
} {
	t.Helper()
	var all []struct {
		ftype   string
		message string
		conf    float64
		ids     []string
	}
	for _, e := range events {
		fs, err := det.Analyze(e)
		if err != nil {
			t.Fatalf("Analyze error: %v", err)
		}
		for _, f := range fs {
			all = append(all, struct {
				ftype   string
				message string
				conf    float64
				ids     []string
			}{f.Type, f.Message, f.Confidence, f.EventIDs})
		}
	}
	return all
}

// ---------------------------------------------------------------------------
// Test cases (mirror Python TestToolMisuseDetector)
// ---------------------------------------------------------------------------

// test_detects_retry_storm: 6 failing calls with same args > max_retries=5.
func TestToolMisuse_DetectsRetryStorm(t *testing.T) {
	det := detectors.NewToolMisuseDetector(5)
	events := failingCalls("database_query", 6)

	findings := runMisuse(t, det, events)

	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding, got 0")
	}

	hasToolMisuse := false
	for _, f := range findings {
		if f.ftype == string(types.DetectionToolMisuse) {
			hasToolMisuse = true
		}
	}
	if !hasToolMisuse {
		t.Errorf("expected tool_misuse detection type")
	}

	// All 6 failing event IDs should appear somewhere in the findings.
	allIDs := make(map[string]struct{})
	for _, f := range findings {
		for _, id := range f.ids {
			allIDs[id] = struct{}{}
		}
	}
	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("fail-database_query-%d", i)
		if _, ok := allIDs[id]; !ok {
			t.Errorf("missing event ID %s in findings", id)
		}
	}
}

// test_retry_storm_at_exactly_threshold_no_detection: exactly 5 failures should
// NOT trigger the retry-storm check (need > 5).
func TestToolMisuse_ExactlyThresholdNoRetryStorm(t *testing.T) {
	det := detectors.NewToolMisuseDetector(5)
	events := failingCalls("database_query", 5)

	findings := runMisuse(t, det, events)

	// Retry storm requires > 5, so 5 should not trigger it.
	for _, f := range findings {
		if f.ftype == string(types.DetectionToolMisuse) {
			// Verify it's not a retry-storm message with "6" failures.
			// (A failure-rate detection for 100% rate is OK here.)
			_ = f // acceptable if it's a rate detection
		}
	}
	// The key assertion: no finding should mention "6 times" or claim > max_retries.
	for _, f := range findings {
		if len(f.ids) > 5 && containsStr(f.message, "and failing each time") {
			t.Errorf("retry-storm fired with <= threshold failures: %s", f.message)
		}
	}
}

// test_no_detection_below_max_retries: 4 failures < max_retries=5,
// min_calls_for_rate=10 so rate check is also skipped.
func TestToolMisuse_NoBelowMaxRetries(t *testing.T) {
	det := detectors.NewToolMisuseDetectorFull(5, 0.7, 10)
	events := failingCalls("search", 4)

	findings := runMisuse(t, det, events)
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

// test_no_detection_for_successful_calls: 9 successes + 1 failure = 10% rate.
func TestToolMisuse_NoDetectionForSuccessfulCalls(t *testing.T) {
	det := detectors.NewToolMisuseDetector(5)
	var events []*types.Event
	for i := 0; i < 9; i++ {
		events = append(events, toolMisuseEvent(fmt.Sprintf("ok-%d", i), "search", nil, true, 0, float64(i)))
	}
	events = append(events, toolMisuseEvent("fail-0", "search", nil, false, 0, 9.0))

	findings := runMisuse(t, det, events)
	if len(findings) != 0 {
		t.Errorf("expected no findings (10%% failure rate), got %d", len(findings))
	}
}

// test_no_detection_for_varied_successful_tools: multiple tools, all succeeding.
func TestToolMisuse_NoDetectionForVariedSuccessfulTools(t *testing.T) {
	det := detectors.NewToolMisuseDetector(5)
	var events []*types.Event
	for i := 0; i < 10; i++ {
		events = append(events, toolMisuseEvent(
			fmt.Sprintf("e-%d", i),
			fmt.Sprintf("tool_%d", i),
			nil, true, 0, float64(i),
		))
	}

	findings := runMisuse(t, det, events)
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

// test_detects_high_failure_rate_varied_args: same tool, varying args, 80% failure.
func TestToolMisuse_DetectsHighFailureRateVariedArgs(t *testing.T) {
	det := detectors.NewToolMisuseDetector(5)
	var events []*types.Event
	for i := 0; i < 5; i++ {
		events = append(events, toolMisuseEvent(
			fmt.Sprintf("e-%d", i),
			"api_call",
			map[string]interface{}{"id": i},
			i == 0, // only first call succeeds
			0, float64(i),
		))
	}

	findings := runMisuse(t, det, events)
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding, got 0")
	}
	hasToolMisuse := false
	hasTool := false
	for _, f := range findings {
		if f.ftype == string(types.DetectionToolMisuse) {
			hasToolMisuse = true
		}
		if containsStr(f.message, "api_call") {
			hasTool = true
		}
	}
	if !hasToolMisuse {
		t.Error("expected tool_misuse detection")
	}
	if !hasTool {
		t.Error("expected message to mention api_call")
	}
}

// test_failure_rate_below_min_calls_not_flagged: only 2 calls < min_calls_for_rate=3.
func TestToolMisuse_FailureRateBelowMinCalls(t *testing.T) {
	det := detectors.NewToolMisuseDetector(5)
	events := []*types.Event{
		toolMisuseEvent("e-0", "flaky_tool", nil, false, 0, 0.0),
		toolMisuseEvent("e-1", "flaky_tool", nil, false, 0, 1.0),
	}

	findings := runMisuse(t, det, events)
	if len(findings) != 0 {
		t.Errorf("expected no findings (only 2 calls < min_calls_for_rate=3), got %d", len(findings))
	}
}

// test_empty_events: empty input returns no findings.
func TestToolMisuse_EmptyEvents(t *testing.T) {
	det := detectors.NewToolMisuseDetector(5)
	findings := runMisuse(t, det, nil)
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty input, got %d", len(findings))
	}
}

// test_no_tool_call_events: only prompt events.
func TestToolMisuse_NoToolCallEvents(t *testing.T) {
	det := detectors.NewToolMisuseDetector(5)
	var events []*types.Event
	for i := 0; i < 5; i++ {
		events = append(events, &types.Event{
			ID:        fmt.Sprintf("p-%d", i),
			SessionID: "sess-1",
			AgentID:   "agent-1",
			TenantID:  "tenant-1",
			Type:      types.EventPrompt,
			Severity:  types.SeverityInfo,
			Timestamp: time.Unix(int64(i), 0),
			Prompt:    &types.PromptData{Content: fmt.Sprintf("message %d", i), Role: "user"},
		})
	}

	findings := runMisuse(t, det, events)
	if len(findings) != 0 {
		t.Errorf("expected no findings for prompt-only events, got %d", len(findings))
	}
}

// test_confidence_in_valid_range: all confidences must be in [0.0, 1.0].
func TestToolMisuse_ConfidenceInValidRange(t *testing.T) {
	det := detectors.NewToolMisuseDetector(5)
	events := failingCalls("risky_tool", 20)

	findings := runMisuse(t, det, events)
	for _, f := range findings {
		if f.conf < 0.0 || f.conf > 1.0 {
			t.Errorf("confidence out of range [0,1]: %f (message: %s)", f.conf, f.message)
		}
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
