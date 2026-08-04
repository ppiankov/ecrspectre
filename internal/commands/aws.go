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
	allRegions     bool
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
	// WO-14: policy and delete-script output formats.
	awsCmd.Flags().StringVar(&awsFlags.format, "format", "text", "Output format: text, json, sarif, spectrehub, policy, delete-script")
	awsCmd.Flags().StringVarP(&awsFlags.outputFile, "output", "o", "", "Output file path (default: stdout)")
	awsCmd.Flags().Float64Var(&awsFlags.minMonthlyCost, "min-monthly-cost", 0.10, "Minimum monthly cost to report ($)")
	awsCmd.Flags().BoolVar(&awsFlags.includeScan, "include-scan", false, "Include vulnerability scan data if available")
	awsCmd.Flags().BoolVar(&awsFlags.noProgress, "no-progress", false, "Disable progress output")
	awsCmd.Flags().DurationVar(&awsFlags.timeout, "timeout", 10*time.Minute, "Scan timeout")
	awsCmd.Flags().StringSliceVar(&awsFlags.excludeTags, "exclude-tags", nil, "Exclude resources by tag (Key=Value, comma-separated)")
	// WO-16: scan all enabled regions.
	awsCmd.Flags().BoolVar(&awsFlags.allRegions, "all-regions", false, "Scan all enabled AWS regions (requires ec2:DescribeRegions)")
}

func runAWS(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()

	// WO-7: load config + apply defaults before context setup; explicit flags
	// beat config via Flags().Changed() (was flag==default sentinel) and timeout
	// resolves from config so the context below uses it.
	cfg, err := config.Load(".")
	if err != nil {
		slog.Warn("Failed to load config file", "error", err)
	}
	applyAWSConfigDefaults(cmd, cfg)

	if awsFlags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, awsFlags.timeout)
		defer cancel()
	}

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

	// WO-16: determine regions to scan (--all-regions enumerates via ec2:DescribeRegions).
	var regions []string
	if awsFlags.allRegions {
		rs, err := ecr.ListRegions(ctx, client.NewEC2Client())
		if err != nil {
			return enhanceError("list regions", err)
		}
		if len(rs) == 0 {
			return fmt.Errorf("--all-regions: no enabled regions returned by ec2:DescribeRegions")
		}
		regions = rs
		slog.Info("Scanning all enabled regions", "count", len(regions))
	} else {
		resolvedRegion := client.Region()
		if resolvedRegion == "" {
			return fmt.Errorf("no AWS region configured; use --region, set AWS_REGION, or pass --all-regions")
		}
		regions = []string{resolvedRegion}
	}

	// WO-18: warn when multi-region scan may exceed the timeout.
	if awsFlags.allRegions && len(regions) > 1 {
		slog.Warn("Multi-region scan may exceed the configured timeout; increase --timeout if results are incomplete",
			"regions", len(regions), "timeout", awsFlags.timeout)
	}

	// WO-8: build scan config; exclude-ID map hoisted to shared builder.
	excludeIDs := buildExcludeIDs(cfg.Exclude.ResourceIDs)
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

	// WO-8: progress callback hoisted to shared helper.
	progressFn := stderrProgressFn(awsFlags.noProgress)

	// WO-16: scan each region sequentially, merging results into one aggregate
	// (bounded concurrency is a separate performance WO; sequential avoids
	// exacerbating ECR throttling on large accounts).
	result := &registry.ScanResult{}
	for _, region := range regions {
		slog.Info("Scanning ECR", "region", region)
		scanner := ecr.NewECRScanner(client.NewECRClientForRegion(region), region, awsFlags.includeScan)
		mergeScanResults(result, scanner.Scan(ctx, scanCfg, progressFn))
	}

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
			URIHash: computeTargetHash("aws", regions, profile),
		},
		Config: report.ReportConfig{
			Provider:       "aws",
			Regions:        regions,
			StaleDays:      awsFlags.staleDays,
			MaxSizeMB:      awsFlags.maxSizeMB,
			MinMonthlyCost: awsFlags.minMonthlyCost,
			Retention:      cfg.Retention,
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

// WO-16: mergeScanResults merges src into dst (aggregates multi-region scans).
func mergeScanResults(dst, src *registry.ScanResult) {
	dst.Findings = append(dst.Findings, src.Findings...)
	dst.Errors = append(dst.Errors, src.Errors...)
	dst.ResourcesScanned += src.ResourcesScanned
	dst.RepositoriesScanned += src.RepositoriesScanned
}

// WO-8: applies config defaults for unset AWS flags; delegates to the shared
// applyConfigDefaults so the precedence logic lives once.
func applyAWSConfigDefaults(cmd *cobra.Command, cfg config.Config) {
	applyConfigDefaults(cmd, cfg, scanFlagRefs{
		format:         &awsFlags.format,
		staleDays:      &awsFlags.staleDays,
		maxSizeMB:      &awsFlags.maxSizeMB,
		minMonthlyCost: &awsFlags.minMonthlyCost,
		timeout:        &awsFlags.timeout,
	})
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
	// WO-14: policy emits a lifecycle policy; delete-script prints dry-run batch-delete commands.
	case "policy":
		return &report.PolicyReporter{Writer: w}, nil
	case "delete-script":
		return &report.DeleteScriptReporter{Writer: w}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %s (use text, json, sarif, spectrehub, policy, or delete-script)", format)
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
