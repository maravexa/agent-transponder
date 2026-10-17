package analyzer

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileCursor tracks the read position within a single event file.
type FileCursor struct {
	Offset   int64     `json:"offset"`
	LastRead time.Time `json:"last_read"`
}

// Cursor persists the analyzer's last-processed position across restarts.
// It is stored at <findings_dir>/.cursor.json.
type Cursor struct {
	Files map[string]FileCursor `json:"files"`
}

// NewCursor returns an empty cursor.
func NewCursor() *Cursor {
	return &Cursor{Files: make(map[string]FileCursor)}
}

// LoadCursor reads the cursor file from disk.
// If the file does not exist, a fresh cursor is returned without error.
func LoadCursor(path string) (*Cursor, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if os.IsNotExist(err) {
		return NewCursor(), nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return loadCursor(root, filepath.Base(path))
}

func loadCursor(root *os.Root, name string) (*Cursor, error) {
	data, err := root.ReadFile(name)
	if os.IsNotExist(err) {
		return NewCursor(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read cursor %s: %w", name, err)
	}

	var c Cursor
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse cursor %s: %w", name, err)
	}
	if c.Files == nil {
		c.Files = make(map[string]FileCursor)
	}
	return &c, nil
}

// Save writes the cursor atomically to path by writing a temp file and renaming.
func (c *Cursor) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir cursor dir: %w", err)
	}

	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return c.save(root, filepath.Base(path))
}

func (c *Cursor) save(root *os.Root, name string) error {
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal cursor: %w", err)
	}

	// Exclusive creation prevents following a planted temporary-file symlink.
	tmp := ".cursor-" + rand.Text() + ".tmp"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(tmp) }()
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := root.Rename(tmp, name); err != nil {
		return fmt.Errorf("write cursor tmp: %w", err)
	}
	return nil
}

// Get returns the cursor entry for a file (zero value if unseen).
func (c *Cursor) Get(filename string) FileCursor {
	return c.Files[filename]
}

// Set updates the cursor entry for a file.
func (c *Cursor) Set(filename string, fc FileCursor) {
	c.Files[filename] = fc
}

// CursorPath returns the canonical cursor file path within a findings directory.
func CursorPath(findingsDir string) string {
	return filepath.Join(findingsDir, ".cursor.json")
}
