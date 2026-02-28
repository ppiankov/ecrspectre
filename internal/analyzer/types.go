package analyzer

import (
	"github.com/ppiankov/ecrspectre/internal/registry"
)

// Summary holds aggregated statistics about scan findings.
type Summary struct {
	TotalResourcesScanned int            `json:"total_resources_scanned"`
	TotalFindings         int            `json:"total_findings"`
	TotalMonthlyWaste     float64        `json:"total_monthly_waste"`
	BySeverity            map[string]int `json:"by_severity"`
	ByResourceType        map[string]int `json:"by_resource_type"`
	RepositoriesScanned   int            `json:"repositories_scanned"`
}

// AnalysisResult holds filtered findings and computed summary.
type AnalysisResult struct {
	Findings []registry.Finding `json:"findings"`
	Summary  Summary            `json:"summary"`
	Errors   []string           `json:"errors,omitempty"`
}

// AnalyzerConfig controls analysis behavior.
type AnalyzerConfig struct {
	MinMonthlyCost float64
}
