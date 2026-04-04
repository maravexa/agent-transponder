package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	// Write a minimal config and verify defaults are applied for unset fields.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "exporter.yml")
	if err := os.WriteFile(cfgPath, []byte("listen:\n  port: 9999\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.Listen.Port != 9999 {
		t.Errorf("listen.port: want 9999, got %d", cfg.Listen.Port)
	}
	if cfg.Listen.Address != "0.0.0.0" {
		t.Errorf("listen.address default: want 0.0.0.0, got %q", cfg.Listen.Address)
	}
	if cfg.Findings.PollInterval != "30s" {
		t.Errorf("findings.poll_interval default: want 30s, got %q", cfg.Findings.PollInterval)
	}
	if cfg.Metrics.Namespace != "flight_recorder" {
		t.Errorf("metrics.namespace default: want flight_recorder, got %q", cfg.Metrics.Namespace)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("logging.level default: want info, got %q", cfg.Logging.Level)
	}
}

func TestLoadConfig_FullSchema(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "exporter.yml")
	content := `
listen:
  address: "127.0.0.1"
  port: 8430
tls:
  cert: "/etc/fr/tls/exporter/cert.pem"
  key:  "/etc/fr/tls/exporter/key.pem"
  ca:   "/etc/fr/tls/ca/ca.crt"
findings:
  path: "/var/lib/fr/findings"
  poll_interval: "10s"
metrics:
  namespace: "flight_recorder"
logging:
  level: "debug"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.Listen.Address != "127.0.0.1" {
		t.Errorf("listen.address: want 127.0.0.1, got %q", cfg.Listen.Address)
	}
	if cfg.Listen.Port != 8430 {
		t.Errorf("listen.port: want 8430, got %d", cfg.Listen.Port)
	}
	if cfg.TLS.Cert != "/etc/fr/tls/exporter/cert.pem" {
		t.Errorf("tls.cert: got %q", cfg.TLS.Cert)
	}
	if cfg.Findings.Path != "/var/lib/fr/findings" {
		t.Errorf("findings.path: got %q", cfg.Findings.Path)
	}
	if cfg.Findings.PollInterval != "10s" {
		t.Errorf("findings.poll_interval: want 10s, got %q", cfg.Findings.PollInterval)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("logging.level: want debug, got %q", cfg.Logging.Level)
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := loadConfig("/nonexistent/path/exporter.yml")
	if err == nil {
		t.Error("expected error for missing config file, got nil")
	}
}

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	healthHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: want 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: want application/json, got %q", ct)
	}
	body := rr.Body.String()
	if body == "" {
		t.Error("expected non-empty JSON body")
	}
}

func TestBuildTLSConfig_NoCert(t *testing.T) {
	cfg := &Config{}
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg != nil {
		t.Error("expected nil tls.Config when no cert configured")
	}
}
