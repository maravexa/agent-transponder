package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all ingestion server configuration.
type Config struct {
	Server     ServerConfig           `yaml:"server"`
	TLS        TLSFileConfig          `yaml:"tls"`
	EventStore EventStoreConfig       `yaml:"event_store"`
	Audit      AuditConfig            `yaml:"audit"`
	Policy     PolicyConfig           `yaml:"policy"`
	Logging    LoggingConfig          `yaml:"logging"`
	Agents     map[string]AgentConfig `yaml:"agents"`
	Redaction  RedactionConfig        `yaml:"redaction"`
	Analysis   AnalysisConfig         `yaml:"analysis"`
	Retention  RetentionConfig        `yaml:"retention"`
}

// ServerConfig holds network listener addresses.
type ServerConfig struct {
	ListenAddr  string `yaml:"listen_addr"`
	HealthAddr  string `yaml:"health_addr"`
	MetricsAddr string `yaml:"metrics_addr"`
}

// TLSFileConfig holds paths to TLS certificate files.
type TLSFileConfig struct {
	CAPath   string `yaml:"ca_path"`
	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
}

// EventStoreConfig holds event persistence settings.
type EventStoreConfig struct {
	Path string `yaml:"path"`
}

// AuditConfig holds audit log settings.
type AuditConfig struct {
	Path string `yaml:"path"`
}

// AnalysisConfig holds analysis engine forwarding settings.
type AnalysisConfig struct {
	Addr                    string        `yaml:"addr"`
	CAPath                  string        `yaml:"ca_path"`
	CertPath                string        `yaml:"cert_path"`
	KeyPath                 string        `yaml:"key_path"`
	FlushInterval           time.Duration `yaml:"flush_interval"`
	CircuitBreakerCooldown  time.Duration `yaml:"circuit_breaker_cooldown"`
	BatchSize               int           `yaml:"batch_size"`
	CircuitBreakerThreshold int           `yaml:"circuit_breaker_threshold"`
	TLSEnabled              bool          `yaml:"tls_enabled"`
}

// RetentionConfig holds data retention policy settings.
type RetentionConfig struct {
	DefaultTTL    time.Duration `yaml:"default_ttl"`
	CheckInterval time.Duration `yaml:"check_interval"`
}

// RedactionConfig holds redaction pattern settings.
type RedactionConfig struct {
	CustomPatterns []CustomPattern `yaml:"custom_patterns"`
}

// CustomPattern is a named regex pattern for redaction.
type CustomPattern struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"`
}

// PolicyConfig holds policy engine settings.
type PolicyConfig struct {
	ConfigPath string `yaml:"config_path"`
}

// AgentConfig holds per-agent settings.
type AgentConfig struct {
	HMACKey string `yaml:"hmac_key"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Format string `yaml:"format"` // "json" or "text"
	Level  string `yaml:"level"`  // "debug", "info", "warn", "error"
}

// LoadConfig reads configuration from a YAML file and applies environment
// variable overrides (AT_ prefix).
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	// Expand ${VAR} and $VAR environment variable references in the file.
	expanded := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	applyEnvOverrides(&cfg)
	applyDefaults(&cfg)

	return &cfg, nil
}

// applyEnvOverrides overrides config fields from AT_-prefixed environment variables.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("AT_LISTEN_ADDR"); v != "" {
		cfg.Server.ListenAddr = v
	}
	if v := os.Getenv("AT_HEALTH_ADDR"); v != "" {
		cfg.Server.HealthAddr = v
	}
	if v := os.Getenv("AT_METRICS_ADDR"); v != "" {
		cfg.Server.MetricsAddr = v
	}
	if v := os.Getenv("AT_TLS_CA"); v != "" {
		cfg.TLS.CAPath = v
	}
	if v := os.Getenv("AT_TLS_CERT"); v != "" {
		cfg.TLS.CertPath = v
	}
	if v := os.Getenv("AT_TLS_KEY"); v != "" {
		cfg.TLS.KeyPath = v
	}
	if v := os.Getenv("AT_EVENT_STORE_PATH"); v != "" {
		cfg.EventStore.Path = v
	}
	if v := os.Getenv("AT_AUDIT_PATH"); v != "" {
		cfg.Audit.Path = v
	}
	if v := os.Getenv("AT_ANALYSIS_ADDR"); v != "" {
		cfg.Analysis.Addr = v
	}
	if v := os.Getenv("AT_POLICY_PATH"); v != "" {
		cfg.Policy.ConfigPath = v
	}
	if v := os.Getenv("AT_LOG_FORMAT"); v != "" {
		cfg.Logging.Format = v
	}
	if v := os.Getenv("AT_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
}

// applyDefaults fills in zero-value fields with sensible defaults.
func applyDefaults(cfg *Config) {
	if cfg.Server.ListenAddr == "" {
		cfg.Server.ListenAddr = ":8443"
	}
	if cfg.Server.HealthAddr == "" {
		cfg.Server.HealthAddr = ":8081"
	}
	if cfg.Server.MetricsAddr == "" {
		cfg.Server.MetricsAddr = ":9090"
	}
	if cfg.Analysis.BatchSize == 0 {
		cfg.Analysis.BatchSize = 50
	}
	if cfg.Analysis.FlushInterval == 0 {
		cfg.Analysis.FlushInterval = 5 * time.Second
	}
	if cfg.Analysis.CircuitBreakerThreshold == 0 {
		cfg.Analysis.CircuitBreakerThreshold = 5
	}
	if cfg.Analysis.CircuitBreakerCooldown == 0 {
		cfg.Analysis.CircuitBreakerCooldown = 30 * time.Second
	}
	if cfg.Retention.DefaultTTL == 0 {
		cfg.Retention.DefaultTTL = 72 * time.Hour
	}
	if cfg.Retention.CheckInterval == 0 {
		cfg.Retention.CheckInterval = time.Hour
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
}
