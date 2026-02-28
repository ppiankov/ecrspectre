package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ppiankov/ecrspectre/internal/analyzer"
	"github.com/ppiankov/ecrspectre/internal/artifactregistry"
	"github.com/ppiankov/ecrspectre/internal/config"
	"github.com/ppiankov/ecrspectre/internal/registry"
	"github.com/ppiankov/ecrspectre/internal/report"
	"github.com/spf13/cobra"
)

var gcpFlags struct {
	project        string
	locations      []string
	staleDays      int
	maxSizeMB      int
	format         string
	outputFile     string
	minMonthlyCost float64
	noProgress     bool
	timeout        time.Duration
	excludeTags    []string
}

var gcpCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Audit GCP Artifact Registry repositories for waste",
	Long: `Scan all Artifact Registry repositories in a GCP project for stale, untagged,
and oversized container images. Each finding includes an estimated monthly storage waste in USD.

Note: GCP Artifact Registry does not provide pull timestamps, so stale detection
is based on upload time only. Lifecycle policies and vulnerability scans are
ECR-only features and are not checked for GCP.`,
	RunE: runGCP,
}

func init() {
	gcpCmd.Flags().StringVar(&gcpFlags.project, "project", "", "GCP project ID (required)")
	gcpCmd.Flags().StringSliceVar(&gcpFlags.locations, "locations", nil, "Comma-separated location filter (e.g., us-central1,europe-west1)")
	gcpCmd.Flags().IntVar(&gcpFlags.staleDays, "stale-days", 90, "Image age threshold in days since upload")
	gcpCmd.Flags().IntVar(&gcpFlags.maxSizeMB, "max-size", 1024, "Flag images larger than this (MB)")
	gcpCmd.Flags().StringVar(&gcpFlags.format, "format", "text", "Output format: text, json, sarif, spectrehub")
	gcpCmd.Flags().StringVarP(&gcpFlags.outputFile, "output", "o", "", "Output file path (default: stdout)")
	gcpCmd.Flags().Float64Var(&gcpFlags.minMonthlyCost, "min-monthly-cost", 0.10, "Minimum monthly cost to report ($)")
	gcpCmd.Flags().BoolVar(&gcpFlags.noProgress, "no-progress", false, "Disable progress output")
	gcpCmd.Flags().DurationVar(&gcpFlags.timeout, "timeout", 10*time.Minute, "Scan timeout")
	gcpCmd.Flags().StringSliceVar(&gcpFlags.excludeTags, "exclude-tags", nil, "Exclude resources by label (Key=Value, comma-separated)")
}

func runGCP(cmd *cobra.Command, _ []string) error {
	if gcpFlags.project == "" {
		return fmt.Errorf("--project is required for GCP scans")
	}

	ctx := cmd.Context()
	if gcpFlags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, gcpFlags.timeout)
		defer cancel()
	}

	// Load config and apply defaults
	cfg, err := config.Load(".")
	if err != nil {
		slog.Warn("Failed to load config file", "error", err)
	}
	applyGCPConfigDefaults(cfg)

	// Resolve locations
	locations := gcpFlags.locations
	if len(locations) == 0 && len(cfg.Regions) > 0 {
		locations = cfg.Regions
	}
	if len(locations) == 0 {
		return fmt.Errorf("--locations is required (e.g., us-central1,europe-west1)")
	}

	slog.Info("Scanning Artifact Registry", "project", gcpFlags.project, "locations", locations)

	// Initialize client
	client, err := artifactregistry.NewClient(ctx, gcpFlags.project)
	if err != nil {
		return enhanceError("initialize GCP client", err)
	}
	defer func() { _ = client.Close() }()

	// Build scan config
	excludeIDs := make(map[string]bool, len(cfg.Exclude.ResourceIDs))
	for _, id := range cfg.Exclude.ResourceIDs {
		excludeIDs[id] = true
	}
	excludeTags := parseExcludeTags(cfg.Exclude.Tags, gcpFlags.excludeTags)

	scanCfg := registry.ScanConfig{
		StaleDays:      gcpFlags.staleDays,
		MaxSizeBytes:   int64(gcpFlags.maxSizeMB) * 1024 * 1024,
		MinMonthlyCost: gcpFlags.minMonthlyCost,
		Exclude: registry.ExcludeConfig{
			ResourceIDs: excludeIDs,
			Tags:        excludeTags,
		},
	}

	// Run scanner
	scanner := artifactregistry.NewARScanner(client, gcpFlags.project, locations)

	var progressFn func(registry.ScanProgress)
	if !gcpFlags.noProgress {
		progressFn = func(p registry.ScanProgress) {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", p.Region, p.Message)
		}
	}

	result := scanner.Scan(ctx, scanCfg, progressFn)

	// Analyze results
	analysis := analyzer.Analyze(result, analyzer.AnalyzerConfig{
		MinMonthlyCost: gcpFlags.minMonthlyCost,
	})

	// Build report data
	data := report.Data{
		Tool:      "ecrspectre",
		Version:   version,
		Timestamp: time.Now().UTC(),
		Target: report.Target{
			Type:    "artifact-registry",
			URIHash: computeTargetHash("gcp", locations, gcpFlags.project),
		},
		Config: report.ReportConfig{
			Provider:       "gcp",
			Regions:        locations,
			StaleDays:      gcpFlags.staleDays,
			MaxSizeMB:      gcpFlags.maxSizeMB,
			MinMonthlyCost: gcpFlags.minMonthlyCost,
		},
		Findings: analysis.Findings,
		Summary:  analysis.Summary,
		Errors:   analysis.Errors,
	}

	// Select and run reporter
	reporter, err := selectReporter(gcpFlags.format, gcpFlags.outputFile)
	if err != nil {
		return err
	}
	return reporter.Generate(data)
}

func applyGCPConfigDefaults(cfg config.Config) {
	if gcpFlags.format == "text" && cfg.Format != "" {
		gcpFlags.format = cfg.Format
	}
	if gcpFlags.staleDays == 90 && cfg.StaleDays > 0 {
		gcpFlags.staleDays = cfg.StaleDays
	}
	if gcpFlags.maxSizeMB == 1024 && cfg.MaxSizeMB > 0 {
		gcpFlags.maxSizeMB = cfg.MaxSizeMB
	}
	if gcpFlags.minMonthlyCost == 0.10 && cfg.MinMonthlyCost > 0 {
		gcpFlags.minMonthlyCost = cfg.MinMonthlyCost
	}
	if gcpFlags.project == "" && cfg.Project != "" {
		gcpFlags.project = cfg.Project
	}
}
