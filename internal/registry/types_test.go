package registry

import "testing"

func TestSeverityConstants(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
	}
	for _, tt := range tests {
		if string(tt.sev) != tt.want {
			t.Errorf("Severity %q != %q", tt.sev, tt.want)
		}
	}
}

func TestResourceTypeConstants(t *testing.T) {
	if string(ResourceImage) != "image" {
		t.Errorf("ResourceImage = %q, want %q", ResourceImage, "image")
	}
	if string(ResourceRepository) != "repository" {
		t.Errorf("ResourceRepository = %q, want %q", ResourceRepository, "repository")
	}
}

func TestFindingIDConstants(t *testing.T) {
	ids := []struct {
		id   FindingID
		want string
	}{
		{FindingUntaggedImage, "UNTAGGED_IMAGE"},
		{FindingStaleImage, "STALE_IMAGE"},
		{FindingLargeImage, "LARGE_IMAGE"},
		{FindingNoLifecyclePolicy, "NO_LIFECYCLE_POLICY"},
		{FindingVulnerableImage, "VULNERABLE_IMAGE"},
		{FindingUnusedRepo, "UNUSED_REPO"},
		{FindingMultiArchBloat, "MULTI_ARCH_BLOAT"},
	}
	for _, tt := range ids {
		if string(tt.id) != tt.want {
			t.Errorf("FindingID %q != %q", tt.id, tt.want)
		}
	}
}

func TestExcludeConfigDefaults(t *testing.T) {
	cfg := ExcludeConfig{}
	if cfg.ResourceIDs != nil {
		t.Error("ResourceIDs should be nil by default")
	}
	if cfg.Tags != nil {
		t.Error("Tags should be nil by default")
	}
}

func TestScanResultDefaults(t *testing.T) {
	r := ScanResult{}
	if r.ResourcesScanned != 0 {
		t.Errorf("ResourcesScanned = %d, want 0", r.ResourcesScanned)
	}
	if len(r.Findings) != 0 {
		t.Errorf("Findings len = %d, want 0", len(r.Findings))
	}
}
