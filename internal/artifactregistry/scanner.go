package artifactregistry

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ppiankov/ecrspectre/internal/pricing"
	"github.com/ppiankov/ecrspectre/internal/registry"
)

// ARScanner audits GCP Artifact Registry repositories for waste.
type ARScanner struct {
	client    ARAPI
	project   string
	locations []string
	now       time.Time // injectable for testing
}

// NewARScanner creates a scanner for the given Artifact Registry client.
func NewARScanner(client ARAPI, project string, locations []string) *ARScanner {
	return &ARScanner{
		client:    client,
		project:   project,
		locations: locations,
		now:       time.Now(),
	}
}

// Scan implements registry.RegistryScanner.
func (s *ARScanner) Scan(ctx context.Context, cfg registry.ScanConfig, progress func(registry.ScanProgress)) *registry.ScanResult {
	result := &registry.ScanResult{}

	for _, location := range s.locations {
		s.reportProgress(progress, location, fmt.Sprintf("Scanning location %s", location))

		repos, err := s.client.ListRepositories(ctx, s.project, location)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", location, err))
			continue
		}

		result.RepositoriesScanned += len(repos)
		s.reportProgress(progress, location, fmt.Sprintf("Found %d Docker repositories", len(repos)))

		for _, repo := range repos {
			if cfg.Exclude.ResourceIDs[repo.RepoID] {
				continue
			}
			s.scanRepository(ctx, cfg, repo, result, progress)
		}
	}

	return result
}

func (s *ARScanner) scanRepository(ctx context.Context, cfg registry.ScanConfig, repo Repository, result *registry.ScanResult, progress func(registry.ScanProgress)) {
	s.reportProgress(progress, repo.Location, fmt.Sprintf("Scanning %s", repo.RepoID))

	images, err := s.client.ListDockerImages(ctx, repo.Name)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("%s/%s: %v", repo.Location, repo.RepoID, err))
		return
	}

	if len(images) == 0 {
		result.Findings = append(result.Findings, registry.Finding{
			ID:                    registry.FindingUnusedRepo,
			Severity:              registry.SeverityLow,
			ResourceType:          registry.ResourceRepository,
			ResourceID:            repo.RepoID,
			Region:                repo.Location,
			Message:               "Repository has no Docker images",
			EstimatedMonthlyWaste: 0,
		})
		return
	}

	staleCount := 0
	for _, img := range images {
		result.ResourcesScanned++
		findings := s.analyzeImage(cfg, repo, img)
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
			totalWaste += pricing.MonthlyStorageCost("artifactregistry", repo.Location, img.SizeBytes)
		}
		result.Findings = append(result.Findings, registry.Finding{
			ID:                    registry.FindingUnusedRepo,
			Severity:              registry.SeverityLow,
			ResourceType:          registry.ResourceRepository,
			ResourceID:            repo.RepoID,
			Region:                repo.Location,
			Message:               fmt.Sprintf("All %d images are stale", len(images)),
			EstimatedMonthlyWaste: totalWaste,
			Metadata: map[string]any{
				"image_count": len(images),
			},
		})
	}
}

func (s *ARScanner) analyzeImage(cfg registry.ScanConfig, repo Repository, img DockerImage) []registry.Finding {
	var findings []registry.Finding

	imageID := img.URI
	if imageID == "" {
		imageID = img.Name
	}
	sizeBytes := img.SizeBytes
	cost := pricing.MonthlyStorageCost("artifactregistry", repo.Location, sizeBytes)
	sizeMB := float64(sizeBytes) / (1024 * 1024)

	// Resource name from tags
	resourceName := ""
	if len(img.Tags) > 0 {
		resourceName = fmt.Sprintf("%s:%s", repo.RepoID, strings.Join(img.Tags, ","))
	}

	// Untagged image
	if len(img.Tags) == 0 {
		findings = append(findings, registry.Finding{
			ID:                    registry.FindingUntaggedImage,
			Severity:              registry.SeverityHigh,
			ResourceType:          registry.ResourceImage,
			ResourceID:            imageID,
			Region:                repo.Location,
			Message:               fmt.Sprintf("Untagged image (%.0f MB)", sizeMB),
			EstimatedMonthlyWaste: cost,
			Metadata: map[string]any{
				"size_bytes": sizeBytes,
				"uri":        img.URI,
			},
		})
	}

	// Stale image — uploaded > staleDays ago (GCP has no pull timestamp)
	if cfg.StaleDays > 0 && !img.UploadTime.IsZero() {
		staleThreshold := s.now.AddDate(0, 0, -cfg.StaleDays)
		if img.UploadTime.Before(staleThreshold) {
			daysSince := int(s.now.Sub(img.UploadTime).Hours() / 24)
			findings = append(findings, registry.Finding{
				ID:                    registry.FindingStaleImage,
				Severity:              registry.SeverityHigh,
				ResourceType:          registry.ResourceImage,
				ResourceID:            imageID,
				ResourceName:          resourceName,
				Region:                repo.Location,
				Message:               fmt.Sprintf("Uploaded %d days ago, no pull data available (%.0f MB)", daysSince, sizeMB),
				EstimatedMonthlyWaste: cost,
				Metadata: map[string]any{
					"upload_time": img.UploadTime.Format(time.RFC3339),
					"days_stale":  daysSince,
					"size_bytes":  sizeBytes,
					"stale_days":  cfg.StaleDays,
					"note":        "GCP AR has no pull timestamp; staleness based on upload time",
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
			Region:                repo.Location,
			Message:               fmt.Sprintf("Image is %.0f MB (threshold: %d MB)", sizeMB, cfg.MaxSizeBytes/(1024*1024)),
			EstimatedMonthlyWaste: cost,
			Metadata: map[string]any{
				"size_bytes":      sizeBytes,
				"threshold_bytes": cfg.MaxSizeBytes,
			},
		})
	}

	// Multi-arch bloat
	if strings.Contains(img.MediaType, "manifest.list") || strings.Contains(img.MediaType, "image.index") {
		if cfg.StaleDays > 0 && !img.UploadTime.IsZero() {
			staleThreshold := s.now.AddDate(0, 0, -cfg.StaleDays)
			if img.UploadTime.Before(staleThreshold) {
				findings = append(findings, registry.Finding{
					ID:                    registry.FindingMultiArchBloat,
					Severity:              registry.SeverityLow,
					ResourceType:          registry.ResourceImage,
					ResourceID:            imageID,
					ResourceName:          resourceName,
					Region:                repo.Location,
					Message:               fmt.Sprintf("Stale multi-architecture image (%.0f MB)", sizeMB),
					EstimatedMonthlyWaste: cost,
					Metadata: map[string]any{
						"size_bytes": sizeBytes,
						"media_type": img.MediaType,
					},
				})
			}
		}
	}

	return findings
}

func (s *ARScanner) reportProgress(progress func(registry.ScanProgress), location, msg string) {
	if progress != nil {
		progress(registry.ScanProgress{
			Region:    location,
			Scanner:   "artifactregistry",
			Message:   msg,
			Timestamp: time.Now(),
		})
	}
}
