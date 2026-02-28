package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ppiankov/ecrspectre/internal/analyzer"
	"github.com/ppiankov/ecrspectre/internal/config"
	"github.com/ppiankov/ecrspectre/internal/ecr"
	"github.com/ppiankov/ecrspectre/internal/registry"
	"github.com/ppiankov/ecrspectre/internal/report"
	"github.com/spf13/cobra"
)

var awsFlags struct {
	region         string
	profile        string
	staleDays      int
	maxSizeMB      int
	format         string
	outputFile     string
	minMonthlyCost float64
	includeScan    bool
	noProgress     bool
	timeout        time.Duration
	excludeTags    []string
}

var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "Audit AWS ECR repositories for waste",
	Long: `Scan all ECR repositories in an AWS account for stale, untagged, and oversized
container images. Each finding includes an estimated monthly storage waste in USD.`,
	RunE: runAWS,
}

func init() {
	awsCmd.Flags().StringVar(&awsFlags.region, "region", "", "AWS region (default: from AWS config)")
	awsCmd.Flags().StringVar(&awsFlags.profile, "profile", "", "AWS profile name")
	awsCmd.Flags().IntVar(&awsFlags.staleDays, "stale-days", 90, "Image age threshold in days since last pull")
	awsCmd.Flags().IntVar(&awsFlags.maxSizeMB, "max-size", 1024, "Flag images larger than this (MB)")
	awsCmd.Flags().StringVar(&awsFlags.format, "format", "text", "Output format: text, json, sarif, spectrehub")
	awsCmd.Flags().StringVarP(&awsFlags.outputFile, "output", "o", "", "Output file path (default: stdout)")
	awsCmd.Flags().Float64Var(&awsFlags.minMonthlyCost, "min-monthly-cost", 0.10, "Minimum monthly cost to report ($)")
	awsCmd.Flags().BoolVar(&awsFlags.includeScan, "include-scan", false, "Include vulnerability scan data if available")
	awsCmd.Flags().BoolVar(&awsFlags.noProgress, "no-progress", false, "Disable progress output")
	awsCmd.Flags().DurationVar(&awsFlags.timeout, "timeout", 10*time.Minute, "Scan timeout")
	awsCmd.Flags().StringSliceVar(&awsFlags.excludeTags, "exclude-tags", nil, "Exclude resources by tag (Key=Value, comma-separated)")
}

func runAWS(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	if awsFlags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, awsFlags.timeout)
		defer cancel()
	}

	// Load config and apply defaults
	cfg, err := config.Load(".")
	if err != nil {
		slog.Warn("Failed to load config file", "error", err)
	}
	applyAWSConfigDefaults(cfg)

	// Resolve profile
	profile := awsFlags.profile
	if profile == "" {
		profile = cfg.Profile
	}

	// Resolve region
	region := awsFlags.region
	if region == "" && len(cfg.Regions) > 0 {
		region = cfg.Regions[0]
	}

	// Initialize AWS client
	client, err := ecr.NewClient(ctx, profile, region)
	if err != nil {
		return enhanceError("initialize AWS client", err)
	}

	resolvedRegion := client.Region()
	if resolvedRegion == "" {
		return fmt.Errorf("no AWS region configured; use --region or set AWS_REGION")
	}
	slog.Info("Scanning ECR", "region", resolvedRegion)

	// Build scan config
	excludeIDs := make(map[string]bool, len(cfg.Exclude.ResourceIDs))
	for _, id := range cfg.Exclude.ResourceIDs {
		excludeIDs[id] = true
	}
	excludeTags := parseExcludeTags(cfg.Exclude.Tags, awsFlags.excludeTags)

	scanCfg := registry.ScanConfig{
		StaleDays:      awsFlags.staleDays,
		MaxSizeBytes:   int64(awsFlags.maxSizeMB) * 1024 * 1024,
		MinMonthlyCost: awsFlags.minMonthlyCost,
		Exclude: registry.ExcludeConfig{
			ResourceIDs: excludeIDs,
			Tags:        excludeTags,
		},
	}

	// Run scanner
	scanner := ecr.NewECRScanner(client.NewECRClient(), resolvedRegion, awsFlags.includeScan)

	var progressFn func(registry.ScanProgress)
	if !awsFlags.noProgress {
		progressFn = func(p registry.ScanProgress) {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", p.Region, p.Message)
		}
	}

	result := scanner.Scan(ctx, scanCfg, progressFn)

	// Analyze results
	analysis := analyzer.Analyze(result, analyzer.AnalyzerConfig{
		MinMonthlyCost: awsFlags.minMonthlyCost,
	})

	// Build report data
	data := report.Data{
		Tool:      "ecrspectre",
		Version:   version,
		Timestamp: time.Now().UTC(),
		Target: report.Target{
			Type:    "ecr",
			URIHash: computeTargetHash("aws", []string{resolvedRegion}, profile),
		},
		Config: report.ReportConfig{
			Provider:       "aws",
			Regions:        []string{resolvedRegion},
			StaleDays:      awsFlags.staleDays,
			MaxSizeMB:      awsFlags.maxSizeMB,
			MinMonthlyCost: awsFlags.minMonthlyCost,
		},
		Findings: analysis.Findings,
		Summary:  analysis.Summary,
		Errors:   analysis.Errors,
	}

	// Select and run reporter
	reporter, err := selectReporter(awsFlags.format, awsFlags.outputFile)
	if err != nil {
		return err
	}
	return reporter.Generate(data)
}

func applyAWSConfigDefaults(cfg config.Config) {
	if awsFlags.format == "text" && cfg.Format != "" {
		awsFlags.format = cfg.Format
	}
	if awsFlags.staleDays == 90 && cfg.StaleDays > 0 {
		awsFlags.staleDays = cfg.StaleDays
	}
	if awsFlags.maxSizeMB == 1024 && cfg.MaxSizeMB > 0 {
		awsFlags.maxSizeMB = cfg.MaxSizeMB
	}
	if awsFlags.minMonthlyCost == 0.10 && cfg.MinMonthlyCost > 0 {
		awsFlags.minMonthlyCost = cfg.MinMonthlyCost
	}
}

func selectReporter(format, outputFile string) (report.Reporter, error) {
	w := os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return nil, fmt.Errorf("create output file: %w", err)
		}
		w = f
	}

	switch format {
	case "json":
		return &report.JSONReporter{Writer: w}, nil
	case "text":
		return &report.TextReporter{Writer: w}, nil
	case "sarif":
		return &report.SARIFReporter{Writer: w}, nil
	case "spectrehub":
		return &report.SpectreHubReporter{Writer: w}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %s (use text, json, sarif, or spectrehub)", format)
	}
}

func parseExcludeTags(configTags, flagTags []string) map[string]string {
	tags := make(map[string]string)
	for _, s := range configTags {
		if k, v, ok := strings.Cut(s, "="); ok {
			tags[k] = v
		} else {
			tags[s] = ""
		}
	}
	for _, s := range flagTags {
		if k, v, ok := strings.Cut(s, "="); ok {
			tags[k] = v
		} else {
			tags[s] = ""
		}
	}
	if len(tags) == 0 {
		return nil
	}
	return tags
}
