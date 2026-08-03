package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/ecrspectre/internal/config"
	"github.com/ppiankov/ecrspectre/internal/registry"
)

// WO-14: emits delete commands for stale/untagged images, excluding protected tags.
func TestDeleteScriptReporter(t *testing.T) {
	data := Data{
		Config:    ReportConfig{StaleDays: 90},
		Timestamp: time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
		Findings: []registry.Finding{
			// untagged + stale -> delete candidate
			{ID: registry.FindingUntaggedImage, ResourceType: registry.ResourceImage, ResourceID: "app@sha256:aaa", Region: "us-east-1", Metadata: map[string]any{"digest": "sha256:aaa", "days_stale": 100}},
			// stale but carries protected tag 'release' -> excluded
			{ID: registry.FindingStaleImage, ResourceType: registry.ResourceImage, ResourceID: "web@sha256:bbb", ResourceName: "web:release", Region: "us-east-1", Metadata: map[string]any{"digest": "sha256:bbb", "days_stale": 200}},
			// repo-level finding -> excluded (not an image)
			{ID: registry.FindingUnusedRepo, ResourceType: registry.ResourceRepository, ResourceID: "old", Region: "us-east-1"},
		},
	}
	var buf bytes.Buffer
	if err := (&DeleteScriptReporter{Writer: &buf}).Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "batch-delete-image --repository app --image-ids imageDigest=sha256:aaa --region us-east-1") {
		t.Errorf("expected delete command for app, got:\n%s", out)
	}
	if strings.Contains(out, "sha256:bbb") {
		t.Errorf("protected release image must be excluded:\n%s", out)
	}
	if !strings.Contains(out, "1 candidate") {
		t.Errorf("expected '1 candidate' summary, got:\n%s", out)
	}
}

// WO-14: below-min-age images are excluded from the delete script.
func TestDeleteScriptReporterMinAgeExcludes(t *testing.T) {
	// A stale image younger than the retention min-age must be kept.
	data := Data{
		Config:    ReportConfig{Retention: config.Retention{MinAgeDays: 30}},
		Timestamp: time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC),
		Findings: []registry.Finding{
			{ID: registry.FindingStaleImage, ResourceType: registry.ResourceImage, ResourceID: "app@sha256:young", Region: "us-east-1", Metadata: map[string]any{"digest": "sha256:young", "days_stale": 5}},
		},
	}
	var buf bytes.Buffer
	if err := (&DeleteScriptReporter{Writer: &buf}).Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if strings.Contains(buf.String(), "batch-delete-image") {
		t.Errorf("below-min-age image must not get a delete command:\n%s", buf.String())
	}
}
