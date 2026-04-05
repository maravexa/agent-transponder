package analyzer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/agent-transponder/agent-transponder/internal/types"
)

// Analyzer is the core event-loop component.  It polls the events directory,
// dispatches each new event through the registered detectors, and writes
// findings to the findings directory.
type Analyzer struct {
	cfg           *Config
	plugins       *PluginsConfig
	detectors     []Detector
	cursor        *Cursor
	cursorPath    string
	mu            sync.Mutex // guards lastProcessed
	lastProcessed time.Time
	logger        *slog.Logger
}

// New creates an Analyzer from the loaded configs and a set of detectors.
func New(cfg *Config, plugins *PluginsConfig, detectors []Detector, logger *slog.Logger) (*Analyzer, error) {
	if err := os.MkdirAll(cfg.Findings.Path, 0o750); err != nil {
		return nil, fmt.Errorf("create findings dir: %w", err)
	}
	if err := os.MkdirAll(cfg.Events.Path, 0o750); err != nil {
		return nil, fmt.Errorf("create events dir: %w", err)
	}

	cursorPath := CursorPath(cfg.Findings.Path)
	cursor, err := LoadCursor(cursorPath)
	if err != nil {
		return nil, fmt.Errorf("load cursor: %w", err)
	}

	return &Analyzer{
		cfg:        cfg,
		plugins:    plugins,
		detectors:  detectors,
		cursor:     cursor,
		cursorPath: cursorPath,
		logger:     logger,
	}, nil
}

// Run starts the polling loop.  It blocks until ctx is cancelled.
func (a *Analyzer) Run(ctx context.Context) error {
	ticker := time.NewTicker(a.cfg.Events.PollInterval)
	defer ticker.Stop()

	a.logger.Info("analyzer started",
		"events_path", a.cfg.Events.Path,
		"findings_path", a.cfg.Findings.Path,
		"poll_interval", a.cfg.Events.PollInterval,
		"detectors", len(a.detectors),
	)

	// Poll once immediately, then on each tick.
	if err := a.poll(ctx); err != nil {
		a.logger.Error("poll error", "err", err)
	}

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("analyzer shutting down")
			return nil
		case <-ticker.C:
			if err := a.poll(ctx); err != nil {
				a.logger.Error("poll error", "err", err)
			}
		}
	}
}

// LastProcessed returns the timestamp of the most recently processed event.
func (a *Analyzer) LastProcessed() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastProcessed
}

// Poll reads all new events from the events directory, runs detectors,
// writes findings, and saves the cursor.  It is exported so tests can
// trigger a single poll cycle without starting the Run loop.
func (a *Analyzer) Poll(ctx context.Context) error {
	return a.poll(ctx)
}

// poll is the internal implementation called by Run and Poll.
func (a *Analyzer) poll(ctx context.Context) error {
	files, err := a.eventFiles()
	if err != nil {
		return fmt.Errorf("list event files: %w", err)
	}

	var totalEvents int
	var totalFindings int

	for _, path := range files {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		name := filepath.Base(path)
		fc := a.cursor.Get(name)

		events, newOffset, err := a.readNewEvents(path, fc.Offset)
		if err != nil {
			a.logger.Warn("read events error", "file", name, "err", err)
			continue
		}
		if len(events) == 0 {
			continue
		}

		findings := a.runDetectors(events)

		if len(findings) > 0 {
			if err := a.writeFindings(findings); err != nil {
				a.logger.Error("write findings error", "err", err)
				continue
			}
			totalFindings += len(findings)
		}

		// Update cursor and record last-processed time.
		a.cursor.Set(name, FileCursor{
			Offset:   newOffset,
			LastRead: time.Now().UTC(),
		})

		totalEvents += len(events)
		if len(events) > 0 {
			last := events[len(events)-1].Timestamp
			a.mu.Lock()
			if last.After(a.lastProcessed) {
				a.lastProcessed = last
			}
			a.mu.Unlock()
		}
	}

	if totalEvents > 0 {
		a.logger.Info("poll complete",
			"events", totalEvents,
			"findings", totalFindings,
		)
	}

	if err := a.cursor.Save(a.cursorPath); err != nil {
		a.logger.Error("save cursor error", "err", err)
	}

	return nil
}

// eventFiles returns all .jsonl files under the events directory (including
// tenant subdirectories), sorted by path (chronological for date-bucketed files).
func (a *Analyzer) eventFiles() ([]string, error) {
	var paths []string
	err := filepath.WalkDir(a.cfg.Events.Path, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".jsonl") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}

// readNewEvents reads events from path starting at offset.
// Returns the events read and the new file offset (byte position after the
// last complete line consumed).
func (a *Analyzer) readNewEvents(path string, offset int64) ([]*types.Event, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, offset, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if offset > 0 {
		if _, err := f.Seek(offset, 0); err != nil {
			return nil, offset, fmt.Errorf("seek %s to %d: %w", path, offset, err)
		}
	}

	// Use a bufio.Reader so we can track byte position accurately.
	// We count bytes consumed rather than relying on f.Seek after a Scanner,
	// because Scanner pre-buffers data and the file position would overshoot.
	reader := bufio.NewReaderSize(f, 1024*1024)
	newOffset := offset

	var events []*types.Event
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			newOffset += int64(len(line))
			trimmed := line
			// Trim trailing newline(s).
			for len(trimmed) > 0 && (trimmed[len(trimmed)-1] == '\n' || trimmed[len(trimmed)-1] == '\r') {
				trimmed = trimmed[:len(trimmed)-1]
			}
			if len(trimmed) > 0 {
				var event types.Event
				if jsonErr := json.Unmarshal(trimmed, &event); jsonErr != nil {
					a.logger.Warn("skip malformed event line", "path", path, "err", jsonErr)
				} else {
					events = append(events, &event)
				}
			}
		}
		if err != nil {
			// io.EOF is normal end-of-file.
			break
		}
	}

	return events, newOffset, nil
}

// runDetectors dispatches each event through all registered detectors and
// collects the resulting findings.
func (a *Analyzer) runDetectors(events []*types.Event) []Finding {
	var all []Finding
	for _, event := range events {
		for _, det := range a.detectors {
			findings, err := det.Analyze(event)
			if err != nil {
				a.logger.Warn("detector analyze error",
					"detector", det.Name(), "event_id", event.ID, "err", err)
				continue
			}
			all = append(all, findings...)
		}
	}
	return all
}

// writeFindings appends findings as JSONL to the findings file for today.
func (a *Analyzer) writeFindings(findings []Finding) error {
	today := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(a.cfg.Findings.Path, "findings-"+today+".jsonl")

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open findings file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	enc := json.NewEncoder(f)
	for i := range findings {
		if err := enc.Encode(&findings[i]); err != nil {
			return fmt.Errorf("encode finding: %w", err)
		}
	}
	return nil
}

// DetectorStatus describes whether a detector is enabled and loaded.
type DetectorStatus struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// Status returns a snapshot of which detectors are active.
func (a *Analyzer) Status() []DetectorStatus {
	out := make([]DetectorStatus, len(a.detectors))
	for i, d := range a.detectors {
		out[i] = DetectorStatus{Name: d.Name(), Enabled: true}
	}
	return out
}
