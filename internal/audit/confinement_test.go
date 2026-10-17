package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(outside, []byte("sentinel"), 0640); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if sink, err := NewHashChainSink(path); err == nil {
		sink.Close()
		t.Fatal("escaped root")
	}
	got, err := os.ReadFile(outside)
	if err != nil || string(got) != "sentinel" {
		t.Fatal("outside modified", err)
	}
}

func TestAuditConfinedRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := NewHashChainSink(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if err = sink.Log(context.Background(), Entry{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	if seq, verifyErr := sink.Verify(context.Background(), 0); verifyErr != nil || seq != -1 {
		t.Fatal(seq, verifyErr)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatal(info, err)
	}
}
