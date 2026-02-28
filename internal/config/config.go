package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds ecrspectre configuration loaded from .ecrspectre.yaml.
type Config struct {
	Provider       string   `yaml:"provider"`
	Regions        []string `yaml:"regions"`
	Profile        string   `yaml:"profile"`
	Project        string   `yaml:"project"`
	StaleDays      int      `yaml:"stale_days"`
	MaxSizeMB      int      `yaml:"max_size_mb"`
	MinMonthlyCost float64  `yaml:"min_monthly_cost"`
	Format         string   `yaml:"format"`
	Timeout        string   `yaml:"timeout"`
	Exclude        Exclude  `yaml:"exclude"`
}

// Exclude defines resources to skip during scanning.
type Exclude struct {
	ResourceIDs []string `yaml:"resource_ids"`
	Tags        []string `yaml:"tags"`
}

// TimeoutDuration parses the timeout string as a duration.
func (c Config) TimeoutDuration() time.Duration {
	if c.Timeout == "" {
		return 0
	}
	d, _ := time.ParseDuration(c.Timeout)
	return d
}

// MaxSizeBytes returns the max image size threshold in bytes.
func (c Config) MaxSizeBytes() int64 {
	if c.MaxSizeMB <= 0 {
		return 1024 * 1024 * 1024 // 1 GB default
	}
	return int64(c.MaxSizeMB) * 1024 * 1024
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
