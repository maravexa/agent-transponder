// Package main is the entry point for the Agent Transponder metrics exporter.
// It walks the findings directory on disk and exposes storage metrics via Prometheus over HTTPS.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"

	"github.com/agent-transponder/agent-transponder/internal/metrics"
)

// Build metadata — set via -ldflags.
var (
	version   = "0.1.0-dev"
	commit    = "unknown"
	buildTime = "unknown"
)

// Config is the YAML configuration schema for the exporter service.
type Config struct {
	Listen struct {
		Address string `yaml:"address"`
		Port    int    `yaml:"port"`
	} `yaml:"listen"`
	TLS struct {
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
		CA   string `yaml:"ca"`
	} `yaml:"tls"`
	Findings struct {
		Path         string `yaml:"path"`
		PollInterval string `yaml:"poll_interval"`
	} `yaml:"findings"`
	Metrics struct {
		Namespace string `yaml:"namespace"`
	} `yaml:"metrics"`
	Logging struct {
		Level string `yaml:"level"`
	} `yaml:"logging"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String(
		"config",
		envOr("AT_CONFIG_PATH", "/etc/flight-recorder/exporter.yml"),
		"path to exporter config file",
	)
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}

	logger := buildLogger(cfg.Logging.Level)
	logger.Info("starting at-exporter",
		"version", version,
		"commit", commit,
		"build_time", buildTime,
		"namespace", cfg.Metrics.Namespace,
	)

	pollInterval, err := time.ParseDuration(cfg.Findings.PollInterval)
	if err != nil {
		logger.Warn("invalid poll_interval, using 30s", "value", cfg.Findings.PollInterval)
		pollInterval = 30 * time.Second
	}

	reg := prometheus.NewRegistry()
	col := metrics.NewCollector(reg)
	col.SetBuildInfo(version, commit, buildTime)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go collectLoop(ctx, col, cfg.Findings.Path, pollInterval, logger)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/health", healthHandler)

	addr := fmt.Sprintf("%s:%d", cfg.Listen.Address, cfg.Listen.Port)

	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return fmt.Errorf("build tls config: %w", err)
	}

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		TLSConfig:    tlsCfg,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("metrics server listening", "addr", addr, "tls", cfg.TLS.Cert != "")
		var srvErr error
		if cfg.TLS.Cert != "" {
			srvErr = srv.ListenAndServeTLS(cfg.TLS.Cert, cfg.TLS.Key)
		} else {
			srvErr = srv.ListenAndServe()
		}
		if srvErr != nil && srvErr != http.ErrServerClosed {
			errCh <- srvErr
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		logger.Info("received signal", "signal", sig)
	case err := <-errCh:
		return err
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	return srv.Shutdown(shutdownCtx)
}

// loadConfig reads and parses the YAML config file at path.
func loadConfig(path string) (*Config, error) {
	// Apply defaults before unmarshalling so missing fields get sensible values.
	cfg := &Config{}
	cfg.Listen.Address = "0.0.0.0"
	cfg.Listen.Port = 8430
	cfg.Findings.Path = "/var/lib/flight-recorder/findings"
	cfg.Findings.PollInterval = "30s"
	cfg.Metrics.Namespace = "flight_recorder"
	cfg.Logging.Level = "info"

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}

// healthHandler returns a JSON health status response.
func healthHandler(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]string{
		"status":  "ok",
		"version": version,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// buildTLSConfig constructs a tls.Config from the cert/key/CA paths in cfg.
// Returns nil if no cert is configured (plain HTTP mode).
func buildTLSConfig(cfg *Config) (*tls.Config, error) {
	if cfg.TLS.Cert == "" {
		return nil, nil
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	if cfg.TLS.CA != "" {
		caData, err := os.ReadFile(cfg.TLS.CA)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", cfg.TLS.CA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("parse CA cert %s", cfg.TLS.CA)
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return tlsCfg, nil
}

// buildLogger creates a structured JSON logger at the requested level.
func buildLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

// collectLoop runs an immediate collection then repeats every interval.
func collectLoop(ctx context.Context, col *metrics.Collector, storePath string, interval time.Duration, logger *slog.Logger) {
	collectStoreMetrics(col, storePath, logger)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collectStoreMetrics(col, storePath, logger)
		}
	}
}

// collectStoreMetrics walks the findings directory and updates gauge metrics.
// Store layout: {basePath}/{tenantID}/{date}.jsonl
func collectStoreMetrics(col *metrics.Collector, storePath string, logger *slog.Logger) {
	tenantBytes := make(map[string]int64)
	tenantEvents := make(map[string]int64)
	var buckets int64

	err := filepath.Walk(storePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".jsonl" {
			return err
		}

		rel, relErr := filepath.Rel(storePath, path)
		if relErr != nil {
			return nil
		}
		tenant := filepath.Dir(rel)
		if tenant == "." {
			tenant = "_default"
		}

		tenantBytes[tenant] += info.Size()
		buckets++

		n, countErr := countLines(path)
		if countErr != nil {
			logger.Warn("failed to count lines", "path", path, "err", countErr)
			return nil
		}
		tenantEvents[tenant] += n
		return nil
	})

	if err != nil && !os.IsNotExist(err) {
		logger.Warn("findings walk error", "path", storePath, "err", err)
	}

	for tenant, b := range tenantBytes {
		col.StorageBytes.WithLabelValues(tenant).Set(float64(b))
	}
	for tenant, n := range tenantEvents {
		col.EventsStored.WithLabelValues(tenant).Set(float64(n))
	}
	col.BucketsActive.Set(float64(buckets))
}

// countLines counts non-empty lines in a file (one event per line in JSONL format).
func countLines(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	var count int64
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if len(scanner.Bytes()) > 0 {
			count++
		}
	}
	return count, scanner.Err()
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
