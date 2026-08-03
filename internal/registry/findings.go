package registry

import "fmt"

// LargeImageFinding builds the LARGE_IMAGE finding shared by every scanner.
// WO-8: hoisted from ecr and artifactregistry to prevent copy-paste divergence;
// both providers produced this finding byte-for-byte identically.
func LargeImageFinding(imageID, resourceName, region string, sizeBytes int64, sizeMB, cost float64, maxBytes int64) Finding {
	return Finding{
		ID:                    FindingLargeImage,
		Severity:              SeverityMedium,
		ResourceType:          ResourceImage,
		ResourceID:            imageID,
		ResourceName:          resourceName,
		Region:                region,
		Message:               fmt.Sprintf("Image is %.0f MB (threshold: %d MB)", sizeMB, maxBytes/(1024*1024)),
		EstimatedMonthlyWaste: cost,
		Metadata: map[string]any{
			"size_bytes":      sizeBytes,
			"threshold_bytes": maxBytes,
		},
	}
}

// WO-8: builds the UNUSED_REPO finding emitted when every image in a repository
// is stale; hoisted from ecr and artifactregistry (waste sum is per-provider).
func AllStaleRepoFinding(resourceID, region string, imageCount int, totalWaste float64) Finding {
	return Finding{
		ID:                    FindingUnusedRepo,
		Severity:              SeverityLow,
		ResourceType:          ResourceRepository,
		ResourceID:            resourceID,
		Region:                region,
		Message:               fmt.Sprintf("All %d images are stale", imageCount),
		EstimatedMonthlyWaste: totalWaste,
		Metadata: map[string]any{
			"image_count": imageCount,
		},
	}
}
