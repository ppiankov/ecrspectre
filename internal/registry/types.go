package registry

import "time"

// Severity levels for findings.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// ResourceType identifies the registry resource being audited.
type ResourceType string

const (
	ResourceImage      ResourceType = "image"
	ResourceRepository ResourceType = "repository"
)

// FindingID identifies the type of waste detected.
type FindingID string

const (
	FindingUntaggedImage     FindingID = "UNTAGGED_IMAGE"
	FindingStaleImage        FindingID = "STALE_IMAGE"
	FindingLargeImage        FindingID = "LARGE_IMAGE"
	FindingNoLifecyclePolicy FindingID = "NO_LIFECYCLE_POLICY"
	FindingVulnerableImage   FindingID = "VULNERABLE_IMAGE"
	FindingUnusedRepo        FindingID = "UNUSED_REPO"
	FindingMultiArchBloat    FindingID = "MULTI_ARCH_BLOAT"
)

// Finding represents a single waste detection result.
type Finding struct {
	ID                    FindingID      `json:"id"`
	Severity              Severity       `json:"severity"`
	ResourceType          ResourceType   `json:"resource_type"`
	ResourceID            string         `json:"resource_id"`
	ResourceName          string         `json:"resource_name,omitempty"`
	Region                string         `json:"region"`
	Message               string         `json:"message"`
	EstimatedMonthlyWaste float64        `json:"estimated_monthly_waste"`
	Metadata              map[string]any `json:"metadata,omitempty"`
}

// ScanResult holds all findings from scanning a set of resources.
type ScanResult struct {
	Findings            []Finding `json:"findings"`
	Errors              []string  `json:"errors,omitempty"`
	ResourcesScanned    int       `json:"resources_scanned"`
	RepositoriesScanned int       `json:"repositories_scanned"`
}

// ScanConfig holds parameters that control scanning behavior.
type ScanConfig struct {
	StaleDays      int
	MaxSizeBytes   int64
	MinMonthlyCost float64
	Exclude        ExcludeConfig
}

// ExcludeConfig holds resource exclusion rules.
type ExcludeConfig struct {
	ResourceIDs map[string]bool
	Tags        map[string]string
}

// ScanProgress reports scanning progress to callers.
type ScanProgress struct {
	Region    string
	Scanner   string
	Message   string
	Timestamp time.Time
}
