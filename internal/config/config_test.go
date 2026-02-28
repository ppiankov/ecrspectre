package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadYAML(t *testing.T) {
	dir := t.TempDir()
	content := `provider: aws
regions:
  - us-east-1
  - eu-west-1
profile: dev
stale_days: 90
max_size_mb: 500
min_monthly_cost: 0.50
format: json
timeout: 5m
exclude:
  resource_ids:
    - repo/old-image
  tags:
    - "env=test"
`
	if err := os.WriteFile(filepath.Join(dir, ".ecrspectre.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Provider != "aws" {
		t.Errorf("Provider = %q, want %q", cfg.Provider, "aws")
	}
	if len(cfg.Regions) != 2 {
		t.Errorf("Regions len = %d, want 2", len(cfg.Regions))
	}
	if cfg.Profile != "dev" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "dev")
	}
	if cfg.StaleDays != 90 {
		t.Errorf("StaleDays = %d, want 90", cfg.StaleDays)
	}
	if cfg.MaxSizeMB != 500 {
		t.Errorf("MaxSizeMB = %d, want 500", cfg.MaxSizeMB)
	}
	if cfg.MinMonthlyCost != 0.50 {
		t.Errorf("MinMonthlyCost = %f, want 0.50", cfg.MinMonthlyCost)
	}
	if cfg.Format != "json" {
		t.Errorf("Format = %q, want %q", cfg.Format, "json")
	}
	if cfg.Timeout != "5m" {
		t.Errorf("Timeout = %q, want %q", cfg.Timeout, "5m")
	}
	if len(cfg.Exclude.ResourceIDs) != 1 {
		t.Errorf("Exclude.ResourceIDs len = %d, want 1", len(cfg.Exclude.ResourceIDs))
	}
	if len(cfg.Exclude.Tags) != 1 {
		t.Errorf("Exclude.Tags len = %d, want 1", len(cfg.Exclude.Tags))
	}
}

func TestLoadYML(t *testing.T) {
	dir := t.TempDir()
	content := `stale_days: 30
`
	if err := os.WriteFile(filepath.Join(dir, ".ecrspectre.yml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.StaleDays != 30 {
		t.Errorf("StaleDays = %d, want 30", cfg.StaleDays)
	}
}

func TestLoadNoFile(t *testing.T) {
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Provider != "" {
		t.Errorf("Provider = %q, want empty", cfg.Provider)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".ecrspectre.yaml"), []byte(":::invalid"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Error("Load() should error on invalid YAML")
	}
}

func TestTimeoutDuration(t *testing.T) {
	tests := []struct {
		timeout string
		want    time.Duration
	}{
		{"5m", 5 * time.Minute},
		{"30s", 30 * time.Second},
		{"", 0},
		{"invalid", 0},
	}
	for _, tt := range tests {
		cfg := Config{Timeout: tt.timeout}
		got := cfg.TimeoutDuration()
		if got != tt.want {
			t.Errorf("TimeoutDuration(%q) = %v, want %v", tt.timeout, got, tt.want)
		}
	}
}

func TestMaxSizeBytes(t *testing.T) {
	tests := []struct {
		mb   int
		want int64
	}{
		{0, 1024 * 1024 * 1024},  // default 1GB
		{-1, 1024 * 1024 * 1024}, // default 1GB
		{500, 500 * 1024 * 1024},
		{1024, 1024 * 1024 * 1024},
	}
	for _, tt := range tests {
		cfg := Config{MaxSizeMB: tt.mb}
		got := cfg.MaxSizeBytes()
		if got != tt.want {
			t.Errorf("MaxSizeBytes(mb=%d) = %d, want %d", tt.mb, got, tt.want)
		}
	}
}
