// Package main is the entry point for the Agent Transponder metrics exporter.
// It walks the event store on disk and exposes storage metrics via Prometheus.
package main

import (
	"bufio"
	"context"
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

	"github.com/agent-transponder/agent-transponder/internal/metrics"
)

// Build metadata — set via -ldflags.
var (
	version   = "0.1.0-dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	listenAddr := envOr("AT_METRICS_ADDR", ":9090")
	storePath := envOr("AT_EVENT_STORE_PATH", "/data/events")

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	logger.Info("starting at-exporter",
		"version", version, "commit", commit, "build_time", buildTime, "addr", listenAddr)

	reg := prometheus.NewRegistry()
	col := metrics.NewCollector(reg)
	col.SetBuildInfo(version, commit, buildTime)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go collectLoop(ctx, col, storePath, logger)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("metrics server listening", "addr", listenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
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

// collectLoop runs an immediate collection then repeats every 30 seconds.
func collectLoop(ctx context.Context, col *metrics.Collector, storePath string, logger *slog.Logger) {
	collectStoreMetrics(col, storePath, logger)
	ticker := time.NewTicker(30 * time.Second)
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

// collectStoreMetrics walks the event store directory and updates gauge metrics.
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
		logger.Warn("event store walk error", "path", storePath, "err", err)
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
	defer f.Close()

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
