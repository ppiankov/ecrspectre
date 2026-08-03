package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds ecrspectre configuration loaded from .ecrspectre.yaml.
// Provider is intentionally absent (WO-7): the cloud provider is chosen by the
// `aws`/`gcp` subcommand, so a config-level provider key would be ambiguous.
type Config struct {
	Regions        []string  `yaml:"regions"`
	Profile        string    `yaml:"profile"`
	Project        string    `yaml:"project"`
	StaleDays      int       `yaml:"stale_days"`
	MaxSizeMB      int       `yaml:"max_size_mb"`
	MinMonthlyCost float64   `yaml:"min_monthly_cost"`
	Format         string    `yaml:"format"`
	Timeout        string    `yaml:"timeout"`
	Exclude        Exclude   `yaml:"exclude"`
	Retention      Retention `yaml:"retention"`
}

// Exclude defines resources to skip during scanning.
type Exclude struct {
	ResourceIDs []string `yaml:"resource_ids"`
	Tags        []string `yaml:"tags"`
}

// Retention configures which images to keep regardless of waste findings.
// Consumed by the retention engine (internal/retention) via the lifecycle-policy
// generator and the finding classifier (WO-13).
type Retention struct {
	KeepLatestN         int      `yaml:"keep_latest_n"`
	KeepLatestNPerMajor bool     `yaml:"keep_latest_n_per_major"`
	KeepLastPerBranch   bool     `yaml:"keep_last_per_branch"`
	BranchPattern       string   `yaml:"branch_pattern"`
	ProtectTags         []string `yaml:"protect_tags"`
	MinAgeDays          int      `yaml:"min_age_days"`
}

// TimeoutDuration parses the timeout string as a duration.
func (c Config) TimeoutDuration() time.Duration {
	if c.Timeout == "" {
		return 0
	}
	d, _ := time.ParseDuration(c.Timeout)
	return d
}

// Load searches for .ecrspectre.yaml or .ecrspectre.yml in the given directory
// and returns the parsed config. Returns an empty Config if no file is found.
func Load(dir string) (Config, error) {
	candidates := []string{
		filepath.Join(dir, ".ecrspectre.yaml"),
		filepath.Join(dir, ".ecrspectre.yml"),
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return Config{}, fmt.Errorf("read config %s: %w", path, err)
		}

		var cfg Config
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse config %s: %w", path, err)
		}
		return cfg, nil
	}

	return Config{}, nil
}
