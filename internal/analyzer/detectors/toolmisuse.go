package detectors

import (
	"encoding/json"
	"fmt"

	"github.com/agent-transponder/agent-transponder/internal/analyzer"
	"github.com/agent-transponder/agent-transponder/internal/types"
)

// callRecord holds the result of a single tool invocation.
type callRecord struct {
	eventID    string
	success    bool
	retryCount int
}

// toolStats accumulates stats for a single tool name within a session.
type toolStats struct {
	// per (tool_name, canonical_args) retry-storm tracking
	byArgs map[string][]callRecord // key: canonicalArgs(arguments)
	// per tool_name overall call list (for failure-rate check)
	all []callRecord
	// which (tool_name, args_key) pairs have already emitted a retry-storm finding
	emittedRetryStorm map[string]struct{}
	// whether a failure-rate finding has been emitted for this tool
	emittedRateDetection bool
}

func newToolStats() *toolStats {
	return &toolStats{
		byArgs:            make(map[string][]callRecord),
		emittedRetryStorm: make(map[string]struct{}),
	}
}

// misuseSess holds per-session state for the ToolMisuseDetector.
type misuseSess struct {
	tools map[string]*toolStats // key: tool_name
}

func newMisuseSess() *misuseSess {
	return &misuseSess{tools: make(map[string]*toolStats)}
}

// ToolMisuseDetector detects tool misuse via two signals (port of tool_misuse.py):
//
//  1. Retry storm: the same (tool_name, canonical_args) pair fails more than
//     maxConsecutiveFailures times.
//
//  2. High failure rate: more than minFailureRate fraction of all calls to a
//     given tool fail (requires at least minCallsForRate samples).
type ToolMisuseDetector struct {
	maxConsecutiveFailures int
	minFailureRate         float64
	minCallsForRate        int
	sessions               map[string]*misuseSess
}

// NewToolMisuseDetector creates a ToolMisuseDetector from plugin config.
// maxConsecutiveFailures maps to max_retries in the Python reference.
// Uses hardcoded defaults for minFailureRate (0.7) and minCallsForRate (3).
func NewToolMisuseDetector(maxConsecutiveFailures int) *ToolMisuseDetector {
	return NewToolMisuseDetectorFull(maxConsecutiveFailures, 0.7, 3)
}

// NewToolMisuseDetectorFull creates a ToolMisuseDetector with all parameters
// explicitly specified.  Useful in tests.
func NewToolMisuseDetectorFull(maxConsecutiveFailures int, minFailureRate float64, minCallsForRate int) *ToolMisuseDetector {
	if maxConsecutiveFailures <= 0 {
		maxConsecutiveFailures = 5
	}
	if minFailureRate <= 0 {
		minFailureRate = 0.7
	}
	if minCallsForRate <= 0 {
		minCallsForRate = 3
	}
	return &ToolMisuseDetector{
		maxConsecutiveFailures: maxConsecutiveFailures,
		minFailureRate:         minFailureRate,
		minCallsForRate:        minCallsForRate,
		sessions:               make(map[string]*misuseSess),
	}
}

// Name implements analyzer.Detector.
func (d *ToolMisuseDetector) Name() string { return "ToolMisuseDetector" }

// Reset implements analyzer.Detector.
func (d *ToolMisuseDetector) Reset() {
	d.sessions = make(map[string]*misuseSess)
}

// Analyze implements analyzer.Detector.
//
//nolint:gocognit // faithful port of tool_misuse.py; extracting sub-functions would obscure the algorithm
func (d *ToolMisuseDetector) Analyze(event *types.Event) ([]analyzer.Finding, error) {
	if event.Type != types.EventToolCall || event.ToolCall == nil {
		return nil, nil
	}

	sess := d.sessions[event.SessionID]
	if sess == nil {
		sess = newMisuseSess()
		d.sessions[event.SessionID] = sess
	}

	tc := event.ToolCall
	toolName := tc.ToolName
	argsKey := canonicalArgs(tc.Arguments)
	rec := callRecord{
		eventID:    event.ID,
		success:    tc.Success,
		retryCount: tc.RetryCount,
	}

	ts := sess.tools[toolName]
	if ts == nil {
		ts = newToolStats()
		sess.tools[toolName] = ts
	}
	ts.byArgs[argsKey] = append(ts.byArgs[argsKey], rec)
	ts.all = append(ts.all, rec)

	var findings []analyzer.Finding

	// -- 1. Retry-storm check ------------------------------------------------
	argsRecords := ts.byArgs[argsKey]
	if _, alreadyEmitted := ts.emittedRetryStorm[argsKey]; !alreadyEmitted {
		var failures []callRecord
		for _, r := range argsRecords {
			if !r.success {
				failures = append(failures, r)
			}
		}
		if len(failures) > d.maxConsecutiveFailures {
			ts.emittedRetryStorm[argsKey] = struct{}{}

			maxRC := 0
			failIDs := make([]string, len(failures))
			for i, f := range failures {
				failIDs[i] = f.eventID
				if f.retryCount > maxRC {
					maxRC = f.retryCount
				}
			}

			confidence := min(0.6+float64(len(failures)-d.maxConsecutiveFailures)*0.05, 1.0)
			findings = append(findings, analyzer.Finding{
				ID:         fmt.Sprintf("misuse-storm-%s-%s-%d", event.SessionID, toolName, len(ts.emittedRetryStorm)),
				SessionID:  event.SessionID,
				AgentID:    event.AgentID,
				TenantID:   event.TenantID,
				Timestamp:  event.Timestamp,
				Detector:   d.Name(),
				Type:       string(types.DetectionToolMisuse),
				Severity:   string(types.SeverityWarning),
				Confidence: round2(confidence),
				Message: fmt.Sprintf(
					"Tool '%s' called with identical arguments %d times and failing each time (threshold: %d)",
					toolName, len(failures), d.maxConsecutiveFailures,
				),
				EventIDs: failIDs,
				Evidence: fmt.Sprintf(
					"args_key=%q, failure_count=%d, max_retry_count_seen=%d",
					argsKey, len(failures), maxRC,
				),
			})
		}
	}

	// -- 2. Failure-rate check -----------------------------------------------
	if !ts.emittedRateDetection {
		total := len(ts.all)
		if total >= d.minCallsForRate {
			var failedIDs []string
			for _, r := range ts.all {
				if !r.success {
					failedIDs = append(failedIDs, r.eventID)
				}
			}
			failureRate := float64(len(failedIDs)) / float64(total)
			if failureRate >= d.minFailureRate {
				// Avoid double-reporting if the retry-storm already fired for this tool.
				alreadyStorm := len(ts.emittedRetryStorm) > 0
				if !alreadyStorm {
					ts.emittedRateDetection = true

					confidence := min(0.5+failureRate*0.4, 1.0)
					findings = append(findings, analyzer.Finding{
						ID:         fmt.Sprintf("misuse-rate-%s-%s", event.SessionID, toolName),
						SessionID:  event.SessionID,
						AgentID:    event.AgentID,
						TenantID:   event.TenantID,
						Timestamp:  event.Timestamp,
						Detector:   d.Name(),
						Type:       string(types.DetectionToolMisuse),
						Severity:   string(types.SeverityWarning),
						Confidence: round2(confidence),
						Message: fmt.Sprintf(
							"Tool '%s' has a %.0f%% failure rate over %d calls (threshold: %.0f%%)",
							toolName, failureRate*100, total, d.minFailureRate*100,
						),
						EventIDs: failedIDs,
						Evidence: fmt.Sprintf(
							"total_calls=%d, failed_calls=%d, failure_rate=%.3f",
							total, len(failedIDs), failureRate,
						),
					})
				}
			}
		}
	}

	return findings, nil
}

// canonicalArgs produces a stable string key for tool arguments by
// unmarshalling and re-marshalling (encoding/json sorts map keys).
func canonicalArgs(raw json.RawMessage) string {
	if raw == nil {
		return ""
	}
	var obj interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return string(raw)
	}
	result, err := json.Marshal(obj)
	if err != nil {
		return string(raw)
	}
	return string(result)
}
