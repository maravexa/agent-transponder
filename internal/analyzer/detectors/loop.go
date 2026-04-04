// Package detectors contains the behavioral anomaly detectors for the
// Agent Transponder analyzer.  Each detector is a faithful Go port of the
// corresponding Python reference implementation in
// analysis/flight_recorder_analysis/detectors/.
package detectors

import (
	"fmt"
	"time"

	"github.com/agent-transponder/agent-transponder/internal/analyzer"
	"github.com/agent-transponder/agent-transponder/internal/types"
)

// loopSession tracks accumulated tool-call state for one session.
type loopSession struct {
	toolNames []string    // ordered sequence of tool names
	eventIDs  []string    // corresponding event IDs
	times     []time.Time // corresponding timestamps

	// emittedStartIDs records the first event ID of each loop span that has
	// already been reported.  Once a loop starting at event X is emitted we
	// suppress further reports for the same start position (even if more
	// repetitions accumulate later), matching the Python reference behavior
	// of reporting each loop instance exactly once.
	emittedStartIDs map[string]struct{}
}

func newLoopSession() *loopSession {
	return &loopSession{
		emittedStartIDs: make(map[string]struct{}),
	}
}

// LoopDetector detects repeated sequences of tool calls (task loops) within
// a session.  It is a stateful, per-event port of loop_detector.py.
//
// Algorithm (same as Python reference):
//  1. Maintain a per-session ordered sequence of (tool_name, event_id, time).
//  2. On each new tool_call event, append to the session's sequence.
//  3. Optionally trim events outside the time window (window_seconds).
//  4. Run a sliding-window search over the current sequence: for every possible
//     subsequence length L in [minSeqLen, n//minReps], check whether any window
//     of length L repeats minReps consecutive times.
//  5. Emit new findings for spans not previously reported.
type LoopDetector struct {
	minSeqLen     int
	minReps       int
	windowSeconds int
	sessions      map[string]*loopSession
}

// NewLoopDetector creates a LoopDetector from plugin config.
// threshold → minReps, window_seconds → windowSeconds.
// minSeqLen defaults to 2, matching the Python reference implementation.
func NewLoopDetector(threshold, windowSeconds int) *LoopDetector {
	return NewLoopDetectorFull(threshold, windowSeconds, 2)
}

// NewLoopDetectorFull creates a LoopDetector with all parameters explicitly
// specified.  Use this in tests that need minSeqLen=1 (matching the Python
// test that sets min_sequence_len=1).
func NewLoopDetectorFull(threshold, windowSeconds, minSeqLen int) *LoopDetector {
	if threshold <= 0 {
		threshold = 3
	}
	if minSeqLen <= 0 {
		minSeqLen = 2
	}
	return &LoopDetector{
		minSeqLen:     minSeqLen,
		minReps:       threshold,
		windowSeconds: windowSeconds,
		sessions:      make(map[string]*loopSession),
	}
}

// Name implements analyzer.Detector.
func (d *LoopDetector) Name() string { return "LoopDetector" }

// Reset implements analyzer.Detector — clears all session state.
func (d *LoopDetector) Reset() {
	d.sessions = make(map[string]*loopSession)
}

// Analyze implements analyzer.Detector.
func (d *LoopDetector) Analyze(event *types.Event) ([]analyzer.Finding, error) {
	if event.Type != types.EventToolCall || event.ToolCall == nil {
		return nil, nil
	}

	sess := d.sessions[event.SessionID]
	if sess == nil {
		sess = newLoopSession()
		d.sessions[event.SessionID] = sess
	}

	// Append the new event.
	sess.toolNames = append(sess.toolNames, event.ToolCall.ToolName)
	sess.eventIDs = append(sess.eventIDs, event.ID)
	sess.times = append(sess.times, event.Timestamp)

	// Trim events outside the time window (relative to the newest event).
	if d.windowSeconds > 0 {
		cutoff := event.Timestamp.Add(-time.Duration(d.windowSeconds) * time.Second)
		first := 0
		for first < len(sess.times) && sess.times[first].Before(cutoff) {
			first++
		}
		if first > 0 {
			sess.toolNames = sess.toolNames[first:]
			sess.eventIDs = sess.eventIDs[first:]
			sess.times = sess.times[first:]
		}
	}

	return d.detectLoops(event, sess), nil
}

// detectLoops runs the sliding-window search and returns new findings.
func (d *LoopDetector) detectLoops(event *types.Event, sess *loopSession) []analyzer.Finding {
	n := len(sess.toolNames)
	if n < d.minSeqLen*d.minReps {
		return nil
	}

	var findings []analyzer.Finding
	reportedPositions := make(map[int]struct{})

	maxLen := n / d.minReps
	for seqLen := d.minSeqLen; seqLen <= maxLen; seqLen++ {
		i := 0
		for i <= n-seqLen*d.minReps {
			if _, already := reportedPositions[i]; already {
				i++
				continue
			}

			window := sess.toolNames[i : i+seqLen]
			reps := 1
			j := i + seqLen
			for j+seqLen <= n && sliceEq(sess.toolNames[j:j+seqLen], window) {
				reps++
				j += seqLen
			}

			if reps >= d.minReps {
				spanEnd := i + seqLen*reps
				involvedIDs := sess.eventIDs[i:spanEnd]

				// Use the first event ID as the dedup key so that
				// growing repetitions of the same loop (same start
				// position) are only reported once — matching the
				// Python reference which processes the full batch.
				startKey := sess.eventIDs[i]
				if _, emitted := sess.emittedStartIDs[startKey]; !emitted {
					sess.emittedStartIDs[startKey] = struct{}{}

					extra := reps - d.minReps
					confidence := min64(0.5+float64(extra)*0.1, 1.0)

					toolList := make([]string, seqLen)
					copy(toolList, window)

					findings = append(findings, analyzer.Finding{
						ID:         fmt.Sprintf("loop-%s-%d", event.SessionID, len(sess.emittedStartIDs)),
						SessionID:  event.SessionID,
						AgentID:    event.AgentID,
						TenantID:   event.TenantID,
						Timestamp:  event.Timestamp,
						Detector:   d.Name(),
						Type:       string(types.DetectionLoop),
						Severity:   string(types.SeverityWarning),
						Confidence: roundF(confidence, 2),
						Message: fmt.Sprintf(
							"Tool-call sequence %v repeated %dx (threshold: %d)",
							toolList, reps, d.minReps,
						),
						EventIDs: append([]string(nil), involvedIDs...),
						Evidence: fmt.Sprintf(
							"Sequence of length %d repeated %d consecutive times starting at position %d in the tool-call stream.",
							seqLen, reps, i,
						),
					})
				}

				for pos := i; pos < spanEnd; pos++ {
					reportedPositions[pos] = struct{}{}
				}
				i = spanEnd
			} else {
				i++
			}
		}
	}

	return findings
}

// sliceEq returns true if a and b contain the same strings.
func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func min64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// roundF rounds f to decimalPlaces decimal places.
func roundF(f float64, decimalPlaces int) float64 {
	pow := 1.0
	for i := 0; i < decimalPlaces; i++ {
		pow *= 10
	}
	return float64(int(f*pow+0.5)) / pow
}
