package analyzer

import (
	"testing"

	"github.com/ppiankov/ecrspectre/internal/registry"
)

func TestAnalyzeFiltersbyMinCost(t *testing.T) {
	result := &registry.ScanResult{
		Findings: []registry.Finding{
			{ID: registry.FindingStaleImage, Severity: registry.SeverityHigh, ResourceType: registry.ResourceImage, EstimatedMonthlyWaste: 5.0},
			{ID: registry.FindingUntaggedImage, Severity: registry.SeverityHigh, ResourceType: registry.ResourceImage, EstimatedMonthlyWaste: 0.50},
			{ID: registry.FindingLargeImage, Severity: registry.SeverityMedium, ResourceType: registry.ResourceImage, EstimatedMonthlyWaste: 10.0},
		},
		ResourcesScanned:    100,
		RepositoriesScanned: 5,
	}

	analysis := Analyze(result, AnalyzerConfig{MinMonthlyCost: 1.0})

	if analysis.Summary.TotalFindings != 2 {
		t.Errorf("TotalFindings = %d, want 2", analysis.Summary.TotalFindings)
	}
	if len(analysis.Findings) != 2 {
		t.Errorf("Findings len = %d, want 2", len(analysis.Findings))
	}
	if analysis.Summary.TotalMonthlyWaste != 15.0 {
		t.Errorf("TotalMonthlyWaste = %f, want 15.0", analysis.Summary.TotalMonthlyWaste)
	}
	if analysis.Summary.TotalResourcesScanned != 100 {
		t.Errorf("TotalResourcesScanned = %d, want 100", analysis.Summary.TotalResourcesScanned)
	}
	if analysis.Summary.RepositoriesScanned != 5 {
		t.Errorf("RepositoriesScanned = %d, want 5", analysis.Summary.RepositoriesScanned)
	}
}

func TestAnalyzeSeverityHistogram(t *testing.T) {
	result := &registry.ScanResult{
		Findings: []registry.Finding{
			{Severity: registry.SeverityHigh, ResourceType: registry.ResourceImage, EstimatedMonthlyWaste: 1.0},
			{Severity: registry.SeverityHigh, ResourceType: registry.ResourceImage, EstimatedMonthlyWaste: 2.0},
			{Severity: registry.SeverityMedium, ResourceType: registry.ResourceRepository, EstimatedMonthlyWaste: 3.0},
		},
	}

	analysis := Analyze(result, AnalyzerConfig{MinMonthlyCost: 0})

	if analysis.Summary.BySeverity["high"] != 2 {
		t.Errorf("BySeverity[high] = %d, want 2", analysis.Summary.BySeverity["high"])
	}
	if analysis.Summary.BySeverity["medium"] != 1 {
		t.Errorf("BySeverity[medium] = %d, want 1", analysis.Summary.BySeverity["medium"])
	}
	if analysis.Summary.ByResourceType["image"] != 2 {
		t.Errorf("ByResourceType[image] = %d, want 2", analysis.Summary.ByResourceType["image"])
	}
	if analysis.Summary.ByResourceType["repository"] != 1 {
		t.Errorf("ByResourceType[repository] = %d, want 1", analysis.Summary.ByResourceType["repository"])
	}
}

func TestAnalyzeNoFindings(t *testing.T) {
	result := &registry.ScanResult{
		ResourcesScanned:    50,
		RepositoriesScanned: 3,
	}

	analysis := Analyze(result, AnalyzerConfig{MinMonthlyCost: 0})

	if analysis.Summary.TotalFindings != 0 {
		t.Errorf("TotalFindings = %d, want 0", analysis.Summary.TotalFindings)
	}
	if analysis.Summary.TotalMonthlyWaste != 0 {
		t.Errorf("TotalMonthlyWaste = %f, want 0", analysis.Summary.TotalMonthlyWaste)
	}
}

func TestAnalyzePreservesErrors(t *testing.T) {
	result := &registry.ScanResult{
		Errors: []string{"failed to scan repo-a", "timeout on repo-b"},
	}

	analysis := Analyze(result, AnalyzerConfig{MinMonthlyCost: 0})

	if len(analysis.Errors) != 2 {
		t.Errorf("Errors len = %d, want 2", len(analysis.Errors))
	}
}

func TestAnalyzeZeroMinCost(t *testing.T) {
	result := &registry.ScanResult{
		Findings: []registry.Finding{
			{EstimatedMonthlyWaste: 0.0},
			{EstimatedMonthlyWaste: 0.01},
		},
	}

	analysis := Analyze(result, AnalyzerConfig{MinMonthlyCost: 0})

	if analysis.Summary.TotalFindings != 2 {
		t.Errorf("TotalFindings = %d, want 2", analysis.Summary.TotalFindings)
	}
}
