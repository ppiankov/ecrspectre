package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/ecrspectre/internal/analyzer"
	"github.com/ppiankov/ecrspectre/internal/registry"
)

func sampleData() Data {
	return Data{
		Tool:      "ecrspectre",
		Version:   "0.1.0",
		Timestamp: time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC),
		Target: Target{
			Type:    "ecr",
			URIHash: "sha256:abc123",
		},
		Config: ReportConfig{
			Provider:       "aws",
			Regions:        []string{"us-east-1"},
			StaleDays:      90,
			MaxSizeMB:      1024,
			MinMonthlyCost: 1.0,
		},
		Findings: []registry.Finding{
			{
				ID:                    registry.FindingStaleImage,
				Severity:              registry.SeverityHigh,
				ResourceType:          registry.ResourceImage,
				ResourceID:            "sha256:deadbeef",
				ResourceName:          "myapp:v1.0",
				Region:                "us-east-1",
				Message:               "Image not pulled in 120 days",
				EstimatedMonthlyWaste: 5.50,
			},
			{
				ID:                    registry.FindingUntaggedImage,
				Severity:              registry.SeverityHigh,
				ResourceType:          registry.ResourceImage,
				ResourceID:            "sha256:cafebabe",
				Region:                "us-east-1",
				Message:               "Image has no tags",
				EstimatedMonthlyWaste: 2.30,
			},
		},
		Summary: analyzer.Summary{
			TotalResourcesScanned: 50,
			TotalFindings:         2,
			TotalMonthlyWaste:     7.80,
			RepositoriesScanned:   3,
			BySeverity:            map[string]int{"high": 2},
			ByResourceType:        map[string]int{"image": 2},
		},
	}
}

func TestJSONReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &JSONReporter{Writer: &buf}

	if err := r.Generate(sampleData()); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `"$schema": "spectre/v1"`) {
		t.Error("missing spectre/v1 schema")
	}
	if !strings.Contains(output, `"tool": "ecrspectre"`) {
		t.Error("missing tool name")
	}
	if !strings.Contains(output, `"STALE_IMAGE"`) {
		t.Error("missing STALE_IMAGE finding")
	}

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestTextReporterWithFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &TextReporter{Writer: &buf}

	if err := r.Generate(sampleData()); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "ecrspectre") {
		t.Error("missing header")
	}
	if !strings.Contains(output, "myapp:v1.0") {
		t.Error("missing resource name")
	}
	if !strings.Contains(output, "Summary") {
		t.Error("missing summary section")
	}
	if !strings.Contains(output, "Repositories scanned") {
		t.Error("missing repositories scanned line")
	}
}

func TestTextReporterNoFindings(t *testing.T) {
	data := sampleData()
	data.Findings = nil
	data.Summary.TotalFindings = 0

	var buf bytes.Buffer
	r := &TextReporter{Writer: &buf}

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No waste found") {
		t.Error("missing 'no waste' message")
	}
}

func TestTextReporterWithErrors(t *testing.T) {
	data := sampleData()
	data.Errors = []string{"failed to scan repo-a"}

	var buf bytes.Buffer
	r := &TextReporter{Writer: &buf}

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	if !strings.Contains(buf.String(), "Warnings (1)") {
		t.Error("missing warnings section")
	}
}

func TestSARIFReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &SARIFReporter{Writer: &buf}

	if err := r.Generate(sampleData()); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `"version": "2.1.0"`) {
		t.Error("missing SARIF version")
	}
	if !strings.Contains(output, `"STALE_IMAGE"`) {
		t.Error("missing STALE_IMAGE rule")
	}
	if !strings.Contains(output, "registry://") {
		t.Error("missing registry URI")
	}

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestSpectreHubReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &SpectreHubReporter{Writer: &buf}

	if err := r.Generate(sampleData()); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `"schema": "spectre/v1"`) {
		t.Error("missing spectre/v1 schema")
	}
	if !strings.Contains(output, `"ecrspectre"`) {
		t.Error("missing tool name")
	}
}

func TestSARIFLevelMapping(t *testing.T) {
	tests := []struct {
		sev  registry.Severity
		want string
	}{
		{registry.SeverityCritical, "error"},
		{registry.SeverityHigh, "error"},
		{registry.SeverityMedium, "warning"},
		{registry.SeverityLow, "note"},
	}
	for _, tt := range tests {
		got := sarifLevel(tt.sev)
		if got != tt.want {
			t.Errorf("sarifLevel(%q) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestBuildSARIFRules(t *testing.T) {
	rules := buildSARIFRules()
	if len(rules) != 7 {
		t.Errorf("buildSARIFRules() len = %d, want 7", len(rules))
	}
}

func TestJSONReporterNoFindings(t *testing.T) {
	data := sampleData()
	data.Findings = nil

	var buf bytes.Buffer
	r := &JSONReporter{Writer: &buf}

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}
