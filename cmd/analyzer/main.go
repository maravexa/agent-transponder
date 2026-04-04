// Package main is the entry point for the Agent Transponder analyzer.
// It polls the events directory, runs detection plugins, and writes findings.
package main

import (
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
	"syscall"
	"time"

	"github.com/agent-transponder/agent-transponder/internal/analyzer"
	"github.com/agent-transponder/agent-transponder/internal/analyzer/detectors"
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
	configPath := flag.String("config", envOr("AT_CONFIG_PATH", "/etc/flight-recorder/analyzer.yml"), "path to analyzer config file")
	flag.Parse()

	// -- Load configuration --------------------------------------------------
	cfg, err := analyzer.LoadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	var pluginsCfg *analyzer.PluginsConfig
	if cfg.Plugins.Config != "" {
		pluginsCfg, err = analyzer.LoadPluginsConfig(cfg.Plugins.Config)
		if err != nil {
			return fmt.Errorf("load plugins config: %w", err)
		}
	} else {
		pluginsCfg = analyzer.DefaultPluginsConfig()
	}

	// -- Build structured logger ---------------------------------------------
	logLevel := slog.LevelInfo
	switch cfg.Logging.Level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn", "warning":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	logger.Info("starting at-analyzer",
		"version", version,
		"commit", commit,
		"build_time", buildTime,
	)

	// -- Build detectors from plugin config ----------------------------------
	var dets []analyzer.Detector
	p := pluginsCfg.Plugins

	if p.LoopDetection.Enabled {
		dets = append(dets, detectors.NewLoopDetector(
			p.LoopDetection.Threshold,
			p.LoopDetection.WindowSeconds,
		))
		logger.Info("detector enabled", "name", "LoopDetector",
			"threshold", p.LoopDetection.Threshold,
			"window_seconds", p.LoopDetection.WindowSeconds,
		)
	}

	if p.ToolMisuse.Enabled {
		dets = append(dets, detectors.NewToolMisuseDetector(p.ToolMisuse.MaxConsecutiveFailures))
		logger.Info("detector enabled", "name", "ToolMisuseDetector",
			"max_consecutive_failures", p.ToolMisuse.MaxConsecutiveFailures,
		)
	}

	if p.GoalDrift.Enabled {
		dets = append(dets, detectors.NewDriftDetector(p.GoalDrift.SimilarityThreshold))
		logger.Info("detector enabled", "name", "DriftDetector",
			"similarity_threshold", p.GoalDrift.SimilarityThreshold,
		)
	}

	if len(dets) == 0 {
		logger.Warn("no detectors enabled — analyzer will run but produce no findings")
	}

	// -- Create analyzer -----------------------------------------------------
	az, err := analyzer.New(cfg, pluginsCfg, dets, logger)
	if err != nil {
		return fmt.Errorf("create analyzer: %w", err)
	}

	// -- Context with graceful shutdown --------------------------------------
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// -- Start health HTTP server --------------------------------------------
	healthSrv, err := buildHealthServer(cfg, az)
	if err != nil {
		return fmt.Errorf("build health server: %w", err)
	}

	errCh := make(chan error, 2)
	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.Listen.Address, cfg.Listen.Port)
		logger.Info("health server listening", "addr", addr, "tls", cfg.TLS.Cert != "")
		var srvErr error
		if cfg.TLS.Cert != "" {
			srvErr = healthSrv.ListenAndServeTLS(cfg.TLS.Cert, cfg.TLS.Key)
		} else {
			srvErr = healthSrv.ListenAndServe()
		}
		if srvErr != nil && srvErr != http.ErrServerClosed {
			errCh <- srvErr
		}
	}()

	// -- Start analyzer loop -------------------------------------------------
	go func() {
		if err := az.Run(ctx); err != nil {
			errCh <- err
		}
	}()

	// -- Wait for signal or error --------------------------------------------
	select {
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", "signal", sig)
	case err := <-errCh:
		logger.Error("component error", "err", err)
		cancel()
	}

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	_ = healthSrv.Shutdown(shutCtx)

	logger.Info("at-analyzer stopped")
	return nil
}

// buildHealthServer constructs the HTTP server for the /health endpoint.
func buildHealthServer(cfg *analyzer.Config, az *analyzer.Analyzer) (*http.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		last := az.LastProcessed()
		lastStr := ""
		if !last.IsZero() {
			lastStr = last.UTC().Format(time.RFC3339)
		}

		detStatus := az.Status()
		detMap := make(map[string]bool, len(detStatus))
		for _, d := range detStatus {
			detMap[d.Name] = d.Enabled
		}

		resp := map[string]interface{}{
			"status":         "ok",
			"detectors":      detMap,
			"last_processed": lastStr,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})

	addr := fmt.Sprintf("%s:%d", cfg.Listen.Address, cfg.Listen.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Configure mTLS if all TLS material is present.
	if cfg.TLS.Cert != "" && cfg.TLS.Key != "" && cfg.TLS.CA != "" {
		caData, err := os.ReadFile(cfg.TLS.CA)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", cfg.TLS.CA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("parse CA cert %s", cfg.TLS.CA)
		}
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  pool,
		}
	} else if cfg.TLS.Cert != "" {
		// TLS without client auth.
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}

	return srv, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
