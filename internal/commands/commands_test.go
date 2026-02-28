package commands

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ppiankov/ecrspectre/internal/config"
)

func TestExecuteVersion(t *testing.T) {
	version = "1.0.0"
	commit = "abc123"
	date = "2026-02-28"

	rootCmd.SetArgs([]string{"version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
}

func TestExecuteNoArgs(t *testing.T) {
	rootCmd.SetArgs([]string{})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
}

func TestEnhanceErrorWithHint(t *testing.T) {
	tests := []struct {
		errMsg string
		hint   string
	}{
		{"NoCredentialProviders: no valid providers", "Configure AWS credentials"},
		{"ExpiredToken: token expired", "session token expired"},
		{"AccessDenied: not authorized", "Insufficient permissions"},
		{"RequestExpired: request timed out", "Check system clock"},
		{"Throttling: rate exceeded", "API rate limit hit"},
		{"could not find default credentials", "gcloud auth"},
	}

	for _, tt := range tests {
		err := enhanceError("test", errors.New(tt.errMsg))
		if !strings.Contains(err.Error(), tt.hint) {
			t.Errorf("enhanceError(%q) missing hint %q, got: %s", tt.errMsg, tt.hint, err)
		}
	}
}

func TestEnhanceErrorWithoutHint(t *testing.T) {
	err := enhanceError("scan", errors.New("some random error"))
	if strings.Contains(err.Error(), "hint:") {
		t.Errorf("unexpected hint in: %s", err)
	}
	if !strings.Contains(err.Error(), "scan:") {
		t.Errorf("missing action prefix in: %s", err)
	}
}

func TestComputeTargetHash(t *testing.T) {
	h1 := computeTargetHash("aws", []string{"us-east-1"}, "")
	h2 := computeTargetHash("aws", []string{"us-east-1"}, "")
	if h1 != h2 {
		t.Error("same inputs should produce same hash")
	}

	h3 := computeTargetHash("gcp", []string{"us-central1"}, "my-project")
	if h1 == h3 {
		t.Error("different inputs should produce different hashes")
	}

	if !strings.HasPrefix(h1, "sha256:") {
		t.Errorf("hash should start with sha256:, got %q", h1)
	}
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(origDir); err != nil {
			t.Log("failed to restore dir:", err)
		}
	})
}

func TestRunInit(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	initFlags.force = false
	if err := runInit(nil, nil); err != nil {
		t.Fatalf("runInit() error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, ".ecrspectre.yaml")); err != nil {
		t.Error("config file not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "ecrspectre-policy.json")); err != nil {
		t.Error("policy file not created")
	}
}

func TestRunInitNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	if err := os.WriteFile(filepath.Join(dir, ".ecrspectre.yaml"), []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}

	initFlags.force = false
	if err := runInit(nil, nil); err != nil {
		t.Fatalf("runInit() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".ecrspectre.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "existing" {
		t.Error("config file should not be overwritten without --force")
	}
}

func TestRunInitForce(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	if err := os.WriteFile(filepath.Join(dir, ".ecrspectre.yaml"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	initFlags.force = true
	if err := runInit(nil, nil); err != nil {
		t.Fatalf("runInit() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".ecrspectre.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "old" {
		t.Error("config file should be overwritten with --force")
	}
}

func TestSelectReporter(t *testing.T) {
	tests := []struct {
		format  string
		wantErr bool
	}{
		{"text", false},
		{"json", false},
		{"sarif", false},
		{"spectrehub", false},
		{"invalid", true},
	}
	for _, tt := range tests {
		r, err := selectReporter(tt.format, "")
		if tt.wantErr {
			if err == nil {
				t.Errorf("selectReporter(%q) should error", tt.format)
			}
		} else {
			if err != nil {
				t.Errorf("selectReporter(%q) error: %v", tt.format, err)
			}
			if r == nil {
				t.Errorf("selectReporter(%q) returned nil reporter", tt.format)
			}
		}
	}
}

func TestSelectReporterOutputFile(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "report.json")

	r, err := selectReporter("json", outFile)
	if err != nil {
		t.Fatalf("selectReporter with output file error: %v", err)
	}
	if r == nil {
		t.Fatal("reporter is nil")
	}
}

func TestParseExcludeTags(t *testing.T) {
	tags := parseExcludeTags(
		[]string{"env=production", "team=platform"},
		[]string{"owner=devops", "ignore"},
	)

	if tags["env"] != "production" {
		t.Errorf("env = %q, want production", tags["env"])
	}
	if tags["team"] != "platform" {
		t.Errorf("team = %q, want platform", tags["team"])
	}
	if tags["owner"] != "devops" {
		t.Errorf("owner = %q, want devops", tags["owner"])
	}
	if tags["ignore"] != "" {
		t.Errorf("ignore = %q, want empty", tags["ignore"])
	}
}

func TestParseExcludeTagsEmpty(t *testing.T) {
	tags := parseExcludeTags(nil, nil)
	if tags != nil {
		t.Error("expected nil for empty tags")
	}
}

func TestApplyAWSConfigDefaults(t *testing.T) {
	// Reset flags to defaults
	awsFlags.format = "text"
	awsFlags.staleDays = 90
	awsFlags.maxSizeMB = 1024
	awsFlags.minMonthlyCost = 0.10

	cfg := config.Config{
		Format:         "json",
		StaleDays:      180,
		MaxSizeMB:      2048,
		MinMonthlyCost: 1.0,
	}

	applyAWSConfigDefaults(cfg)

	if awsFlags.format != "json" {
		t.Errorf("format = %q, want json", awsFlags.format)
	}
	if awsFlags.staleDays != 180 {
		t.Errorf("staleDays = %d, want 180", awsFlags.staleDays)
	}
	if awsFlags.maxSizeMB != 2048 {
		t.Errorf("maxSizeMB = %d, want 2048", awsFlags.maxSizeMB)
	}
	if awsFlags.minMonthlyCost != 1.0 {
		t.Errorf("minMonthlyCost = %f, want 1.0", awsFlags.minMonthlyCost)
	}

	// Reset for other tests
	awsFlags.format = "text"
	awsFlags.staleDays = 90
	awsFlags.maxSizeMB = 1024
	awsFlags.minMonthlyCost = 0.10
}

func TestApplyAWSConfigDefaultsNoOverride(t *testing.T) {
	// Set non-default values (as if user passed flags)
	awsFlags.format = "sarif"
	awsFlags.staleDays = 30
	awsFlags.maxSizeMB = 512
	awsFlags.minMonthlyCost = 5.0

	cfg := config.Config{
		Format:         "json",
		StaleDays:      180,
		MaxSizeMB:      2048,
		MinMonthlyCost: 1.0,
	}

	applyAWSConfigDefaults(cfg)

	// Non-default flag values should not be overridden
	if awsFlags.format != "sarif" {
		t.Errorf("format = %q, want sarif (flag should win)", awsFlags.format)
	}
	if awsFlags.staleDays != 30 {
		t.Errorf("staleDays = %d, want 30 (flag should win)", awsFlags.staleDays)
	}

	// Reset for other tests
	awsFlags.format = "text"
	awsFlags.staleDays = 90
	awsFlags.maxSizeMB = 1024
	awsFlags.minMonthlyCost = 0.10
}

func TestApplyGCPConfigDefaults(t *testing.T) {
	gcpFlags.format = "text"
	gcpFlags.staleDays = 90
	gcpFlags.maxSizeMB = 1024
	gcpFlags.minMonthlyCost = 0.10
	gcpFlags.project = ""

	cfg := config.Config{
		Format:         "json",
		StaleDays:      180,
		MaxSizeMB:      2048,
		MinMonthlyCost: 1.0,
		Project:        "my-gcp-project",
	}

	applyGCPConfigDefaults(cfg)

	if gcpFlags.format != "json" {
		t.Errorf("format = %q, want json", gcpFlags.format)
	}
	if gcpFlags.staleDays != 180 {
		t.Errorf("staleDays = %d, want 180", gcpFlags.staleDays)
	}
	if gcpFlags.maxSizeMB != 2048 {
		t.Errorf("maxSizeMB = %d, want 2048", gcpFlags.maxSizeMB)
	}
	if gcpFlags.minMonthlyCost != 1.0 {
		t.Errorf("minMonthlyCost = %f, want 1.0", gcpFlags.minMonthlyCost)
	}
	if gcpFlags.project != "my-gcp-project" {
		t.Errorf("project = %q, want my-gcp-project", gcpFlags.project)
	}

	// Reset
	gcpFlags.format = "text"
	gcpFlags.staleDays = 90
	gcpFlags.maxSizeMB = 1024
	gcpFlags.minMonthlyCost = 0.10
	gcpFlags.project = ""
}

func TestApplyGCPConfigDefaultsNoOverride(t *testing.T) {
	gcpFlags.format = "sarif"
	gcpFlags.staleDays = 30
	gcpFlags.maxSizeMB = 512
	gcpFlags.minMonthlyCost = 5.0
	gcpFlags.project = "explicit-project"

	cfg := config.Config{
		Format:         "json",
		StaleDays:      180,
		MaxSizeMB:      2048,
		MinMonthlyCost: 1.0,
		Project:        "config-project",
	}

	applyGCPConfigDefaults(cfg)

	if gcpFlags.format != "sarif" {
		t.Errorf("format = %q, want sarif (flag should win)", gcpFlags.format)
	}
	if gcpFlags.staleDays != 30 {
		t.Errorf("staleDays = %d, want 30 (flag should win)", gcpFlags.staleDays)
	}
	if gcpFlags.maxSizeMB != 512 {
		t.Errorf("maxSizeMB = %d, want 512 (flag should win)", gcpFlags.maxSizeMB)
	}
	if gcpFlags.project != "explicit-project" {
		t.Errorf("project = %q, want explicit-project (flag should win)", gcpFlags.project)
	}

	// Reset
	gcpFlags.format = "text"
	gcpFlags.staleDays = 90
	gcpFlags.maxSizeMB = 1024
	gcpFlags.minMonthlyCost = 0.10
	gcpFlags.project = ""
}

func TestEnhanceErrorGCPCredentials(t *testing.T) {
	err := enhanceError("init", errors.New("GOOGLE_APPLICATION_CREDENTIALS not set"))
	if !strings.Contains(err.Error(), "gcloud auth") {
		t.Errorf("missing GCP credential hint, got: %s", err)
	}
}

func TestRunGCPMissingProject(t *testing.T) {
	gcpFlags.project = ""
	rootCmd.SetArgs([]string{"gcp"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing --project")
	}
	if !strings.Contains(err.Error(), "--project") {
		t.Errorf("error should mention --project, got: %s", err)
	}
}

func TestRunAWSSubcommandExists(t *testing.T) {
	// Verify the aws subcommand is registered
	cmd, _, err := rootCmd.Find([]string{"aws"})
	if err != nil {
		t.Fatalf("Find(aws) error: %v", err)
	}
	if cmd.Use != "aws" {
		t.Errorf("command Use = %q, want aws", cmd.Use)
	}
}

func TestRunGCPSubcommandExists(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"gcp"})
	if err != nil {
		t.Fatalf("Find(gcp) error: %v", err)
	}
	if cmd.Use != "gcp" {
		t.Errorf("command Use = %q, want gcp", cmd.Use)
	}
}

func TestRunInitSubcommandExists(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"init"})
	if err != nil {
		t.Fatalf("Find(init) error: %v", err)
	}
	if cmd.Use != "init" {
		t.Errorf("command Use = %q, want init", cmd.Use)
	}
}

func TestVersionCommand(t *testing.T) {
	version = "0.1.0"
	commit = "abc123"
	date = "2026-02-28"

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
}
