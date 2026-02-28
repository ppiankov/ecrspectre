package analyzer

import (
	"github.com/ppiankov/ecrspectre/internal/registry"
)

// Analyze filters findings by minimum cost and computes aggregated summary statistics.
func Analyze(result *registry.ScanResult, cfg AnalyzerConfig) *AnalysisResult {
	var filtered []registry.Finding
	for _, f := range result.Findings {
		if f.EstimatedMonthlyWaste >= cfg.MinMonthlyCost {
			filtered = append(filtered, f)
		}
	}

	summary := Summary{
		TotalResourcesScanned: result.ResourcesScanned,
		TotalFindings:         len(filtered),
		RepositoriesScanned:   result.RepositoriesScanned,
		BySeverity:            make(map[string]int),
		ByResourceType:        make(map[string]int),
	}

	for _, f := range filtered {
		summary.TotalMonthlyWaste += f.EstimatedMonthlyWaste
		summary.BySeverity[string(f.Severity)]++
		summary.ByResourceType[string(f.ResourceType)]++
	}

	return &AnalysisResult{
		Findings: filtered,
		Summary:  summary,
		Errors:   result.Errors,
	}
}
