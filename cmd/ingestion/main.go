// Package main is the entry point for the Agent Transponder ingestion API.
// It wires together all subsystems and starts the gRPC + HTTP servers.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/agent-transponder/agent-transponder/internal/audit"
	"github.com/agent-transponder/agent-transponder/internal/eventstore"
	"github.com/agent-transponder/agent-transponder/internal/identity"
	"github.com/agent-transponder/agent-transponder/internal/keymanager"
	"github.com/agent-transponder/agent-transponder/internal/metrics"
	"github.com/agent-transponder/agent-transponder/internal/policy"
	"github.com/agent-transponder/agent-transponder/internal/redaction"
	pb "github.com/agent-transponder/agent-transponder/proto/agenttransponder/v1"
)

// Build metadata — set via -ldflags.
var (
	version   = "0.1.0-dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	configPath := flag.String("config", "config/ingestion.yaml", "Path to ingestion YAML config")
	flag.Parse()

	if err := run(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	// ── Load config ──────────────────────────────────────────────────────────
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// ── Set up structured logger ─────────────────────────────────────────────
	logger := buildLogger(cfg.Logging)
	logger.Info("starting agent-transponder ingestion",
		"version", version, "commit", commit, "build_time", buildTime)

	// ── Initialize identity provider (mTLS) ──────────────────────────────────
	hmacKeys := buildHMACKeyMap(cfg.Agents, logger)
	idProvider, err := identity.NewTLSProvider(identity.TLSProviderConfig{
		CAPath:   cfg.TLS.CAPath,
		CertPath: cfg.TLS.CertPath,
		KeyPath:  cfg.TLS.KeyPath,
		HMACKeys: hmacKeys,
	})
	if err != nil {
		return fmt.Errorf("init identity provider: %w", err)
	}
	defer idProvider.Close()

	// ── Initialize event store ────────────────────────────────────────────────
	store, err := eventstore.NewJSONLStore(cfg.EventStore.Path)
	if err != nil {
		return fmt.Errorf("init event store: %w", err)
	}
	defer store.Close()

	// ── Initialize audit sink ─────────────────────────────────────────────────
	auditSink, err := audit.NewHashChainSink(cfg.Audit.Path)
	if err != nil {
		return fmt.Errorf("init audit sink: %w", err)
	}
	defer auditSink.Close()

	// ── Initialize key manager ────────────────────────────────────────────────
	kekBytes, err := buildKEK()
	if err != nil {
		return fmt.Errorf("derive kek: %w", err)
	}
	km, err := keymanager.NewLocalManager(keymanager.LocalManagerConfig{
		KEK:       kekBytes,
		StorePath: cfg.EventStore.Path + "/keystore.json",
	})
	if err != nil {
		return fmt.Errorf("init key manager: %w", err)
	}
	defer km.Close()

	// ── Initialize policy engine ──────────────────────────────────────────────
	policyEng, err := policy.NewConfigEngine(cfg.Policy.ConfigPath)
	if err != nil {
		return fmt.Errorf("init policy engine: %w", err)
	}
	defer policyEng.Close()

	// ── Initialize redactor ───────────────────────────────────────────────────
	redactor, err := redaction.NewRegexRedactor(buildRedactionPatterns(cfg, logger))
	if err != nil {
		return fmt.Errorf("init redactor: %w", err)
	}

	// ── Initialize Prometheus metrics ─────────────────────────────────────────
	reg := prometheus.NewRegistry()
	collector := metrics.NewCollector(reg)
	collector.BuildInfo.WithLabelValues(version, commit, buildTime).Set(1)

	// ── Initialize analysis forwarder ─────────────────────────────────────────
	forwarder, err := NewAnalysisForwarder(cfg.Analysis, logger)
	if err != nil {
		return fmt.Errorf("init analysis forwarder: %w", err)
	}
	forwarder.Start()
	defer forwarder.Stop()

	// ── Build ingestion server ─────────────────────────────────────────────────
	ingServer := &IngestionServer{
		idProvider: idProvider,
		store:      store,
		auditSink:  auditSink,
		policyEng:  policyEng,
		redactor:   redactor,
		forwarder:  forwarder,
		collector:  collector,
		logger:     logger,
		version:    version,
	}

	// ── Start gRPC server ─────────────────────────────────────────────────────
	tlsCfg, err := idProvider.TLSConfig()
	if err != nil {
		return fmt.Errorf("get tls config: %w", err)
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.ChainUnaryInterceptor(connectionCountInterceptor(collector)),
	)
	pb.RegisterEventIngestionServer(grpcServer, ingServer)

	grpcLis, err := net.Listen("tcp", cfg.Server.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Server.ListenAddr, err)
	}

	grpcErrCh := make(chan error, 1)
	go func() {
		logger.Info("gRPC server listening", "addr", cfg.Server.ListenAddr)
		if err := grpcServer.Serve(grpcLis); err != nil {
			grpcErrCh <- fmt.Errorf("grpc server: %w", err)
		}
	}()

	// ── Start health HTTP server ───────────────────────────────────────────────
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	healthMux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})

	healthSrv := &http.Server{
		Addr:         cfg.Server.HealthAddr,
		Handler:      healthMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	healthErrCh := make(chan error, 1)
	go func() {
		logger.Info("health server listening", "addr", cfg.Server.HealthAddr)
		if err := healthSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			healthErrCh <- fmt.Errorf("health server: %w", err)
		}
	}()

	// ── Start metrics HTTP server ──────────────────────────────────────────────
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	metricsSrv := &http.Server{
		Addr:         cfg.Server.MetricsAddr,
		Handler:      metricsMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	metricsErrCh := make(chan error, 1)
	go func() {
		logger.Info("metrics server listening", "addr", cfg.Server.MetricsAddr)
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			metricsErrCh <- fmt.Errorf("metrics server: %w", err)
		}
	}()

	// ── Wait for signal or server error ──────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		logger.Info("received shutdown signal", "signal", sig)
	case err := <-grpcErrCh:
		return err
	case err := <-healthErrCh:
		return err
	case err := <-metricsErrCh:
		return err
	}

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	logger.Info("shutting down gracefully")

	// Stop accepting new RPCs; wait for in-flight calls to complete.
	grpcServer.GracefulStop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_ = healthSrv.Shutdown(shutdownCtx)
	_ = metricsSrv.Shutdown(shutdownCtx)

	// Stop analysis forwarder (flush pending events).
	forwarder.Stop()

	// Close subsystems in reverse init order.
	_ = store.Close()
	_ = auditSink.Close()
	_ = km.Close()
	_ = policyEng.Close()
	_ = idProvider.Close()

	logger.Info("shutdown complete")
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func buildLogger(cfg LoggingConfig) *slog.Logger {
	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}

// buildHMACKeyMap decodes base64 HMAC keys from the config agents map.
func buildHMACKeyMap(agents map[string]AgentConfig, logger *slog.Logger) map[string][]byte {
	keys := make(map[string][]byte, len(agents))
	for agentID, agentCfg := range agents {
		if agentCfg.HMACKey == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(agentCfg.HMACKey)
		if err != nil {
			// Fall back to raw bytes if not valid base64.
			logger.Warn("HMAC key for agent is not valid base64, using raw bytes",
				"agent_id", agentID)
			decoded = []byte(agentCfg.HMACKey)
		}
		keys[agentID] = decoded
	}
	return keys
}

// buildKEK derives a 32-byte key encryption key from the environment or
// generates a random one for development. In production, load from a KMS.
func buildKEK() ([]byte, error) {
	if raw := os.Getenv("AT_KEK"); raw != "" {
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("decode AT_KEK: %w", err)
		}
		if len(decoded) != 32 {
			return nil, fmt.Errorf("AT_KEK must be 32 bytes (got %d)", len(decoded))
		}
		return decoded, nil
	}
	// Development fallback — a fixed all-zeros key.
	// This is insecure and must be replaced before production.
	return make([]byte, 32), nil
}

// buildRedactionPatterns merges default patterns with any custom patterns from config.
func buildRedactionPatterns(cfg *Config, logger *slog.Logger) []redaction.Pattern {
	patterns := redaction.DefaultPatterns()
	for _, cp := range cfg.Redaction.CustomPatterns {
		if cp.Name == "" || cp.Pattern == "" {
			continue
		}
		// Validate that the pattern compiles by creating a temporary redactor.
		if _, err := redaction.NewRegexRedactor([]redaction.Pattern{
			{Name: cp.Name, RawExpr: cp.Pattern},
		}); err != nil {
			logger.Warn("skipping invalid custom redaction pattern",
				"name", cp.Name, "pattern", cp.Pattern, "err", err)
			continue
		}
		patterns = append(patterns, redaction.Pattern{Name: cp.Name, RawExpr: cp.Pattern})
	}
	return patterns
}

// connectionCountInterceptor increments and decrements the active connections gauge.
func connectionCountInterceptor(c *metrics.Collector) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		c.ActiveConnections.Inc()
		defer c.ActiveConnections.Dec()
		return handler(ctx, req)
	}
}
