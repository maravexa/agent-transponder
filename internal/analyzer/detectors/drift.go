package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/agent-transponder/agent-transponder/internal/analyzer"
	"github.com/agent-transponder/agent-transponder/internal/types"
)

// tokenRe matches sequences of Unicode word characters (letters, digits,
// underscore) — identical to the Python reference: re.compile(r"\w+", re.UNICODE).
var tokenRe = regexp.MustCompile(`\w+`)

// tokenise returns the set of lower-cased word tokens in text.
func tokenise(text string) map[string]struct{} {
	tokens := tokenRe.FindAllString(text, -1)
	set := make(map[string]struct{}, len(tokens))
	for _, t := range tokens {
		set[strings.ToLower(t)] = struct{}{}
	}
	return set
}

// jaccard computes the Jaccard similarity between two token sets.
// Returns 1.0 when both sets are empty (both empty → identical).
func jaccard(a, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	// union and intersection sizes
	unionSize := len(a)
	intersectSize := 0
	for k := range b {
		if _, ok := a[k]; ok {
			intersectSize++
		} else {
			unionSize++
		}
	}
	if unionSize == 0 {
		return 0.0
	}
	return float64(intersectSize) / float64(unionSize)
}

// driftSession tracks accumulated prompt state for one session.
type driftSession struct {
	prompts        []string // content of each prompt, in order
	promptIDs      []string // corresponding event IDs
	emittedFinding bool     // true once we have emitted a drift finding
}

// DriftDetector detects goal drift via Jaccard token similarity between the
// initial session prompt and subsequent prompts.  Port of drift_detector.py.
//
// Algorithm (same as Python reference):
//  1. Accumulate prompt events in session order.
//  2. Treat the first prompt as the reference (original goal).
//  3. For each subsequent prompt, compute J(reference, prompt).
//  4. If any subsequent prompt has similarity < similarityThreshold AND we have
//     at least minPrompts total, emit a detection describing the drifted prompts.
type DriftDetector struct {
	similarityThreshold float64
	minPrompts          int
	sessions            map[string]*driftSession
}

// NewDriftDetector creates a DriftDetector from plugin config.
// similarityThreshold maps to drift_threshold in the Python reference.
func NewDriftDetector(similarityThreshold float64) *DriftDetector {
	if similarityThreshold <= 0 {
		similarityThreshold = 0.3
	}
	return &DriftDetector{
		similarityThreshold: similarityThreshold,
		minPrompts:          3,
		sessions:            make(map[string]*driftSession),
	}
}

// Name implements analyzer.Detector.
func (d *DriftDetector) Name() string { return "DriftDetector" }

// Reset implements analyzer.Detector.
func (d *DriftDetector) Reset() {
	d.sessions = make(map[string]*driftSession)
}

// Analyze implements analyzer.Detector.
func (d *DriftDetector) Analyze(event *types.Event) ([]analyzer.Finding, error) {
	if event.Type != types.EventPrompt || event.Prompt == nil {
		return nil, nil
	}

	sess := d.sessions[event.SessionID]
	if sess == nil {
		sess = &driftSession{}
		d.sessions[event.SessionID] = sess
	}

	sess.prompts = append(sess.prompts, event.Prompt.Content)
	sess.promptIDs = append(sess.promptIDs, event.ID)

	// Need at least minPrompts before evaluating drift, and don't re-emit.
	if len(sess.prompts) < d.minPrompts || sess.emittedFinding {
		return nil, nil
	}

	referenceTokens := tokenise(sess.prompts[0])

	type driftedEntry struct {
		id  string
		sim float64
	}

	var drifted []driftedEntry
	for i, content := range sess.prompts[1:] {
		tokens := tokenise(content)
		sim := jaccard(referenceTokens, tokens)
		if sim < d.similarityThreshold {
			drifted = append(drifted, driftedEntry{id: sess.promptIDs[i+1], sim: sim})
		}
	}

	if len(drifted) == 0 {
		return nil, nil
	}

	sess.emittedFinding = true

	driftedIDs := make([]string, len(drifted))
	sumSim := 0.0
	minSim := drifted[0].sim
	for i, de := range drifted {
		driftedIDs[i] = de.id
		sumSim += de.sim
		if de.sim < minSim {
			minSim = de.sim
		}
	}
	avgSim := sumSim / float64(len(drifted))

	// Confidence is inversely proportional to average similarity.
	confidence := min(1.0-avgSim+0.1, 1.0)

	totalSubsequent := len(sess.prompts) - 1
	driftFraction := float64(len(drifted)) / float64(totalSubsequent)

	severity := types.SeverityWarning
	if driftFraction >= 0.8 {
		severity = types.SeverityError
	}

	return []analyzer.Finding{
		{
			ID:         fmt.Sprintf("drift-%s", event.SessionID),
			SessionID:  event.SessionID,
			AgentID:    event.AgentID,
			TenantID:   event.TenantID,
			Timestamp:  event.Timestamp,
			Detector:   d.Name(),
			Type:       string(types.DetectionGoalDrift),
			Severity:   string(severity),
			Confidence: round2(confidence),
			Message: fmt.Sprintf(
				"%d/%d subsequent prompts have Jaccard similarity < %.1f vs. initial prompt (avg=%.2f, min=%.2f)",
				len(drifted), totalSubsequent, d.similarityThreshold, avgSim, minSim,
			),
			EventIDs: driftedIDs,
			Evidence: fmt.Sprintf(
				"drift_threshold=%.1f, avg_similarity=%.3f, min_similarity=%.3f, drifted_prompts=%d, total_subsequent_prompts=%d",
				d.similarityThreshold, avgSim, minSim, len(drifted), totalSubsequent,
			),
		},
	}, nil
}
