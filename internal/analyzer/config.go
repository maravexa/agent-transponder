// Package analyzer implements the Go analyzer for Agent Transponder.
// It polls JSONL event files, runs detection plugins, and writes findings.
package analyzer

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is loaded from the analyzer YAML file (deployed by Ansible).
type Config struct {
	Listen   ListenConfig   `yaml:"listen"`
	TLS      TLSConfig      `yaml:"tls"`
	Events   EventsConfig   `yaml:"events"`
	Findings FindingsConfig `yaml:"findings"`
	Plugins  PluginsRef     `yaml:"plugins"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// ListenConfig controls the HTTP health endpoint.
type ListenConfig struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

// TLSConfig holds paths to the mTLS material.
type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	CA   string `yaml:"ca"`
}

// EventsConfig controls where the analyzer reads events from.
type EventsConfig struct {
	Path         string        `yaml:"path"`
	PollInterval time.Duration `yaml:"poll_interval"`
}

// FindingsConfig controls where the analyzer writes findings.
type FindingsConfig struct {
	Path string `yaml:"path"`
}

// PluginsRef points to the separate plugins config file.
type PluginsRef struct {
	Config string `yaml:"config"`
}

// LoggingConfig controls log verbosity.
type LoggingConfig struct {
	Level string `yaml:"level"`
}

// PluginsConfig is loaded from the plugins YAML file.
type PluginsConfig struct {
	Plugins PluginSet `yaml:"plugins"`
}

// PluginSet holds per-detector plugin configuration.
type PluginSet struct {
	LoopDetection LoopDetectionPlugin `yaml:"loop_detection"`
	ToolMisuse    ToolMisusePlugin    `yaml:"tool_misuse"`
	GoalDrift     GoalDriftPlugin     `yaml:"goal_drift"`
}

// LoopDetectionPlugin configures the loop detector.
type LoopDetectionPlugin struct {
	Enabled       bool `yaml:"enabled"`
	Threshold     int  `yaml:"threshold"`      // min_repetitions (default 3)
	WindowSeconds int  `yaml:"window_seconds"` // time window in seconds (default 300)
}

// ToolMisusePlugin configures the tool misuse detector.
type ToolMisusePlugin struct {
	Enabled                bool `yaml:"enabled"`
	MaxConsecutiveFailures int  `yaml:"max_consecutive_failures"` // default 3
}

// GoalDriftPlugin configures the drift detector.
type GoalDriftPlugin struct {
	Enabled             bool    `yaml:"enabled"`
	SimilarityThreshold float64 `yaml:"similarity_threshold"` // Jaccard threshold, default 0.7
}

// LoadConfig reads and parses the main analyzer YAML config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	if cfg.Events.PollInterval == 0 {
		cfg.Events.PollInterval = 5 * time.Second
	}
	if cfg.Listen.Port == 0 {
		cfg.Listen.Port = 8420
	}
	if cfg.Listen.Address == "" {
		cfg.Listen.Address = "0.0.0.0"
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}

	return &cfg, nil
}

// LoadPluginsConfig reads and parses the plugins YAML config file.
func LoadPluginsConfig(path string) (*PluginsConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read plugins config %s: %w", path, err)
	}

	var cfg PluginsConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse plugins config %s: %w", path, err)
	}

	// Apply defaults matching the Python reference implementation.
	if cfg.Plugins.LoopDetection.Threshold == 0 {
		cfg.Plugins.LoopDetection.Threshold = 3
	}
	if cfg.Plugins.LoopDetection.WindowSeconds == 0 {
		cfg.Plugins.LoopDetection.WindowSeconds = 300
	}
	if cfg.Plugins.ToolMisuse.MaxConsecutiveFailures == 0 {
		cfg.Plugins.ToolMisuse.MaxConsecutiveFailures = 5
	}
	if cfg.Plugins.GoalDrift.SimilarityThreshold == 0 {
		cfg.Plugins.GoalDrift.SimilarityThreshold = 0.3
	}

	return &cfg, nil
}

// DefaultPluginsConfig returns a PluginsConfig with all detectors enabled
// at the reference-implementation defaults.
func DefaultPluginsConfig() *PluginsConfig {
	return &PluginsConfig{
		Plugins: PluginSet{
			LoopDetection: LoopDetectionPlugin{
				Enabled:       true,
				Threshold:     3,
				WindowSeconds: 300,
			},
			ToolMisuse: ToolMisusePlugin{
				Enabled:                true,
				MaxConsecutiveFailures: 5,
			},
			GoalDrift: GoalDriftPlugin{
				Enabled:             true,
				SimilarityThreshold: 0.3,
			},
		},
	}
}
