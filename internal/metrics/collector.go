// Package metrics defines the Prometheus metrics for Agent Transponder.
// All metrics are aggregate — no PII or event content in labels.
// Labels are bounded to prevent cardinality explosions.
package metrics

import "github.com/prometheus/client_golang/prometheus"

const namespace = "agent_transponder"

// flightRecorderNamespace is used for metrics produced by the analysis
// pipeline (findings, exporter-side counters).
const flightRecorderNamespace = "flight_recorder"

// Collector holds all registered Prometheus metrics.
type Collector struct {
	// Findings metrics (flight_recorder_ prefix — exporter/analyzer side)
	FindingsTotal *prometheus.CounterVec // labels: type, severity, detector

	// Ingestion metrics
	EventsIngested    *prometheus.CounterVec
	EventsRejected    *prometheus.CounterVec
	IngestLatency     *prometheus.HistogramVec
	ActiveConnections prometheus.Gauge

	// Event store metrics
	EventsStored  *prometheus.GaugeVec
	StorageBytes  *prometheus.GaugeVec
	BucketsActive prometheus.Gauge

	// Analysis metrics
	DetectionsTotal *prometheus.CounterVec
	AnalysisLatency *prometheus.HistogramVec
	AnalysisBatches prometheus.Counter
	AnalysisErrors  prometheus.Counter

	// Audit metrics
	AuditEntriesTotal prometheus.Counter
	AuditChainLength  prometheus.Gauge
	AuditVerifyResult *prometheus.GaugeVec

	// Key management metrics
	ActiveDEKs   prometheus.Gauge
	KeyRotations prometheus.Counter
	CryptoShreds prometheus.Counter

	// Rate limiting
	ThrottledRequests *prometheus.CounterVec

	// Health
	BuildInfo *prometheus.GaugeVec
}

// NewCollector creates and registers all metrics.
func NewCollector(reg prometheus.Registerer) *Collector {
	c := &Collector{
		FindingsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: flightRecorderNamespace,
			Name:      "findings_total",
			Help:      "Total findings detected by the analysis engine.",
		}, []string{"type", "severity", "detector"}),

		EventsIngested: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "events_ingested_total",
			Help:      "Total events successfully ingested.",
		}, []string{"tenant_id", "event_type"}), // Bounded: known tenants × known event types

		EventsRejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "events_rejected_total",
			Help:      "Total events rejected at ingestion.",
		}, []string{"reason"}), // Bounded: fixed set of rejection reasons

		IngestLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "ingest_duration_seconds",
			Help:      "Time to process an ingest request.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"tenant_id"}),

		ActiveConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "active_connections",
			Help:      "Currently connected agent SDK clients.",
		}),

		EventsStored: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "events_stored",
			Help:      "Current number of events in the store.",
		}, []string{"tenant_id"}),

		StorageBytes: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "storage_bytes",
			Help:      "Storage consumed by event data.",
		}, []string{"tenant_id"}),

		BucketsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "buckets_active",
			Help:      "Number of active storage buckets.",
		}),

		DetectionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "detections_total",
			Help:      "Total detections raised by the analysis engine.",
		}, []string{"detection_type", "severity"}), // Bounded: known types × known severities

		AnalysisLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "analysis_duration_seconds",
			Help:      "Time to analyze a batch of events.",
			Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"detector"}),

		AnalysisBatches: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "analysis_batches_total",
			Help:      "Total analysis batches processed.",
		}),

		AnalysisErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "analysis_errors_total",
			Help:      "Total analysis engine errors.",
		}),

		AuditEntriesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "audit_entries_total",
			Help:      "Total audit log entries written.",
		}),

		AuditChainLength: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "audit_chain_length",
			Help:      "Current length of the audit hash chain.",
		}),

		AuditVerifyResult: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "audit_chain_intact",
			Help:      "Whether the audit chain is intact (1) or broken (0).",
		}, []string{}),

		ActiveDEKs: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "active_deks",
			Help:      "Number of active data encryption keys.",
		}),

		KeyRotations: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "key_rotations_total",
			Help:      "Total KEK rotations performed.",
		}),

		CryptoShreds: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "crypto_shreds_total",
			Help:      "Total DEK shred operations (secure deletions).",
		}),

		ThrottledRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "throttled_requests_total",
			Help:      "Requests throttled by the policy engine.",
		}, []string{"agent_id"}),

		BuildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "build_info",
			Help:      "Build metadata.",
		}, []string{"version", "commit", "build_time"}),
	}

	// Register all metrics
	reg.MustRegister(
		c.FindingsTotal,
		c.EventsIngested,
		c.EventsRejected,
		c.IngestLatency,
		c.ActiveConnections,
		c.EventsStored,
		c.StorageBytes,
		c.BucketsActive,
		c.DetectionsTotal,
		c.AnalysisLatency,
		c.AnalysisBatches,
		c.AnalysisErrors,
		c.AuditEntriesTotal,
		c.AuditChainLength,
		c.AuditVerifyResult,
		c.ActiveDEKs,
		c.KeyRotations,
		c.CryptoShreds,
		c.ThrottledRequests,
		c.BuildInfo,
	)

	return c
}

// SetBuildInfo records the binary's build metadata.
func (c *Collector) SetBuildInfo(version, commit, buildTime string) {
	c.BuildInfo.WithLabelValues(version, commit, buildTime).Set(1)
}
