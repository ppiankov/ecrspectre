package ecr

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	awsecr "github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/ppiankov/ecrspectre/internal/pricing"
	"github.com/ppiankov/ecrspectre/internal/registry"
)

// ECRScanner audits AWS ECR repositories for waste.
type ECRScanner struct {
	client      ECRAPI
	region      string
	includeScan bool
	now         time.Time // injectable for testing
}

// NewECRScanner creates a scanner for the given ECR client and region.
func NewECRScanner(client ECRAPI, region string, includeScan bool) *ECRScanner {
	return &ECRScanner{
		client:      client,
		region:      region,
		includeScan: includeScan,
		now:         time.Now(),
	}
}

// Scan implements registry.RegistryScanner.
func (s *ECRScanner) Scan(ctx context.Context, cfg registry.ScanConfig, progress func(registry.ScanProgress)) *registry.ScanResult {
	result := &registry.ScanResult{}

	repos, err := ListRepositories(ctx, s.client)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", s.region, err))
		return result
	}

	result.RepositoriesScanned = len(repos)
	s.reportProgress(progress, fmt.Sprintf("Found %d repositories", len(repos)))

	for _, repo := range repos {
		repoName := deref(repo.RepositoryName)
		if cfg.Exclude.ResourceIDs[repoName] {
			continue
		}

		s.scanRepository(ctx, cfg, repo, result, progress)
	}

	return result
}

func (s *ECRScanner) scanRepository(ctx context.Context, cfg registry.ScanConfig, repo ecrtypes.Repository, result *registry.ScanResult, progress func(registry.ScanProgress)) {
	repoName := deref(repo.RepositoryName)
	s.reportProgress(progress, fmt.Sprintf("Scanning %s", repoName))

	images, err := ListImages(ctx, s.client, repoName)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("%s/%s: %v", s.region, repoName, err))
		return
	}

	if len(images) == 0 {
		result.Findings = append(result.Findings, registry.Finding{
			ID:                    registry.FindingUnusedRepo,
			Severity:              registry.SeverityLow,
			ResourceType:          registry.ResourceRepository,
			ResourceID:            repoName,
			Region:                s.region,
			Message:               "Repository has no images",
			EstimatedMonthlyWaste: 0,
		})
		return
	}

	// Check lifecycle policy
	hasPolicy, err := HasLifecyclePolicy(ctx, s.client, repoName)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("%s/%s lifecycle: %v", s.region, repoName, err))
	} else if !hasPolicy {
		result.Findings = append(result.Findings, registry.Finding{
			ID:           registry.FindingNoLifecyclePolicy,
			Severity:     registry.SeverityMedium,
			ResourceType: registry.ResourceRepository,
			ResourceID:   repoName,
			Region:       s.region,
			Message:      "No lifecycle policy configured — images accumulate indefinitely",
		})
	}

	staleCount := 0
	for _, img := range images {
		result.ResourcesScanned++
		findings := s.analyzeImage(ctx, cfg, repoName, img)
		result.Findings = append(result.Findings, findings...)

		for _, f := range findings {
			if f.ID == registry.FindingStaleImage {
				staleCount++
			}
		}
	}

	// All images stale = unused repo
	if staleCount == len(images) && len(images) > 0 {
		totalWaste := 0.0
		for _, img := range images {
			totalWaste += pricing.MonthlyStorageCost("ecr", s.region, derefInt64(img.ImageSizeInBytes))
		}
		result.Findings = append(result.Findings, registry.Finding{
			ID:                    registry.FindingUnusedRepo,
			Severity:              registry.SeverityLow,
			ResourceType:          registry.ResourceRepository,
			ResourceID:            repoName,
			Region:                s.region,
			Message:               fmt.Sprintf("All %d images are stale", len(images)),
			EstimatedMonthlyWaste: totalWaste,
			Metadata: map[string]any{
				"image_count": len(images),
			},
		})
	}
}

func (s *ECRScanner) analyzeImage(_ context.Context, cfg registry.ScanConfig, repoName string, img ecrtypes.ImageDetail) []registry.Finding {
	var findings []registry.Finding

	digest := deref(img.ImageDigest)
	imageID := fmt.Sprintf("%s@%s", repoName, digest)
	sizeBytes := derefInt64(img.ImageSizeInBytes)
	cost := pricing.MonthlyStorageCost("ecr", s.region, sizeBytes)
	sizeMB := float64(sizeBytes) / (1024 * 1024)

	// Resource name from tags
	resourceName := ""
	if len(img.ImageTags) > 0 {
		resourceName = fmt.Sprintf("%s:%s", repoName, strings.Join(img.ImageTags, ","))
	}

	// Untagged image
	if len(img.ImageTags) == 0 {
		findings = append(findings, registry.Finding{
			ID:                    registry.FindingUntaggedImage,
			Severity:              registry.SeverityHigh,
			ResourceType:          registry.ResourceImage,
			ResourceID:            imageID,
			Region:                s.region,
			Message:               fmt.Sprintf("Untagged image (%.0f MB)", sizeMB),
			EstimatedMonthlyWaste: cost,
			Metadata: map[string]any{
				"size_bytes": sizeBytes,
				"digest":     digest,
			},
		})
	}

	// Stale image — not pulled in > staleDays
	if cfg.StaleDays > 0 {
		staleThreshold := s.now.AddDate(0, 0, -cfg.StaleDays)
		lastActivity := lastActivityTime(img)
		if lastActivity != nil && lastActivity.Before(staleThreshold) {
			daysSince := int(s.now.Sub(*lastActivity).Hours() / 24)
			findings = append(findings, registry.Finding{
				ID:                    registry.FindingStaleImage,
				Severity:              registry.SeverityHigh,
				ResourceType:          registry.ResourceImage,
				ResourceID:            imageID,
				ResourceName:          resourceName,
				Region:                s.region,
				Message:               fmt.Sprintf("Not pulled in %d days (%.0f MB)", daysSince, sizeMB),
				EstimatedMonthlyWaste: cost,
				Metadata: map[string]any{
					"last_pull":  lastActivity.Format(time.RFC3339),
					"days_stale": daysSince,
					"size_bytes": sizeBytes,
					"stale_days": cfg.StaleDays,
				},
			})
		}
	}

	// Large image
	if cfg.MaxSizeBytes > 0 && sizeBytes > cfg.MaxSizeBytes {
		findings = append(findings, registry.Finding{
			ID:                    registry.FindingLargeImage,
			Severity:              registry.SeverityMedium,
			ResourceType:          registry.ResourceImage,
			ResourceID:            imageID,
			ResourceName:          resourceName,
			Region:                s.region,
			Message:               fmt.Sprintf("Image is %.0f MB (threshold: %d MB)", sizeMB, cfg.MaxSizeBytes/(1024*1024)),
			EstimatedMonthlyWaste: cost,
			Metadata: map[string]any{
				"size_bytes":      sizeBytes,
				"threshold_bytes": cfg.MaxSizeBytes,
			},
		})
	}

	// Multi-arch bloat: image manifest list with multiple platforms
	if img.ImageManifestMediaType != nil && strings.Contains(deref(img.ImageManifestMediaType), "manifest.list") {
		// Image index (multi-arch) — check if individual platforms are stale
		if cfg.StaleDays > 0 {
			lastActivity := lastActivityTime(img)
			staleThreshold := s.now.AddDate(0, 0, -cfg.StaleDays)
			if lastActivity != nil && lastActivity.Before(staleThreshold) {
				findings = append(findings, registry.Finding{
					ID:                    registry.FindingMultiArchBloat,
					Severity:              registry.SeverityLow,
					ResourceType:          registry.ResourceImage,
					ResourceID:            imageID,
					ResourceName:          resourceName,
					Region:                s.region,
					Message:               fmt.Sprintf("Stale multi-architecture image (%.0f MB)", sizeMB),
					EstimatedMonthlyWaste: cost,
					Metadata: map[string]any{
						"size_bytes": sizeBytes,
						"media_type": deref(img.ImageManifestMediaType),
					},
				})
			}
		}
	}

	return findings
}

// lastActivityTime returns the most recent activity time for an image.
// Prefers lastRecordedPullTime, falls back to imagePushedAt.
func lastActivityTime(img ecrtypes.ImageDetail) *time.Time {
	if img.LastRecordedPullTime != nil {
		return img.LastRecordedPullTime
	}
	return img.ImagePushedAt
}

func (s *ECRScanner) reportProgress(progress func(registry.ScanProgress), msg string) {
	if progress != nil {
		progress(registry.ScanProgress{
			Region:    s.region,
			Scanner:   "ecr",
			Message:   msg,
			Timestamp: time.Now(),
		})
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// ScanVulnerabilities checks an image for CVE findings from ECR's built-in scan.
func (s *ECRScanner) ScanVulnerabilities(ctx context.Context, repoName, digest string) ([]registry.Finding, error) {
	out, err := s.client.DescribeImageScanFindings(ctx, &awsecr.DescribeImageScanFindingsInput{
		RepositoryName: &repoName,
		ImageId:        &ecrtypes.ImageIdentifier{ImageDigest: &digest},
	})
	if err != nil {
		slog.Debug("No scan findings available", "repo", repoName, "error", err)
		return nil, nil
	}

	if out.ImageScanFindings == nil || len(out.ImageScanFindings.Findings) == 0 {
		return nil, nil
	}

	// Count by severity
	counts := make(map[string]int)
	for _, f := range out.ImageScanFindings.Findings {
		counts[string(f.Severity)]++
	}

	critCount := counts["CRITICAL"]
	highCount := counts["HIGH"]
	total := len(out.ImageScanFindings.Findings)

	if critCount == 0 && highCount == 0 {
		return nil, nil
	}

	imageID := fmt.Sprintf("%s@%s", repoName, digest)
	return []registry.Finding{
		{
			ID:           registry.FindingVulnerableImage,
			Severity:     registry.SeverityCritical,
			ResourceType: registry.ResourceImage,
			ResourceID:   imageID,
			Region:       s.region,
			Message:      fmt.Sprintf("%d vulnerabilities (%d critical, %d high)", total, critCount, highCount),
			Metadata: map[string]any{
				"total_findings":  total,
				"critical_count":  critCount,
				"high_count":      highCount,
				"severity_counts": counts,
			},
		},
	}, nil
}
