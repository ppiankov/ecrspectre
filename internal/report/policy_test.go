package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ppiankov/ecrspectre/internal/registry"
)

func TestPolicyReporter(t *testing.T) {
	data := Data{
		Config: ReportConfig{StaleDays: 90},
		Findings: []registry.Finding{
			{ID: registry.FindingStaleImage, ResourceType: registry.ResourceImage, ResourceID: "app@sha256:aaa", Region: "us-east-1"},
			{ID: registry.FindingStaleImage, ResourceType: registry.ResourceImage, ResourceID: "app@sha256:bbb", Region: "us-east-1"}, // same repo -> deduped
			{ID: registry.FindingStaleImage, ResourceType: registry.ResourceImage, ResourceID: "web@sha256:ccc", Region: "us-east-1"},
			{ID: registry.FindingUnusedRepo, ResourceType: registry.ResourceRepository, ResourceID: "other", Region: "us-east-1"}, // not an image
		},
	}
	var buf bytes.Buffer
	if err := (&PolicyReporter{Writer: &buf}).Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"sinceImagePushed", "--repository app", "--repository web", "put-lifecycle-policy"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
	if got := strings.Count(out, "--repository app"); got != 1 {
		t.Errorf("app should appear once (deduped), got %d", got)
	}
	if strings.Contains(out, "--repository other") {
		t.Errorf("repo-level finding 'other' must not be in the apply list")
	}
}

func TestPolicyReporterNoFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := (&PolicyReporter{Writer: &buf}).Generate(Data{}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(buf.String(), "no image findings") {
		t.Errorf("expected no-findings note, got:\n%s", buf.String())
	}
}

func TestPolicyReporterSurfacesWarnings(t *testing.T) {
	// A throttled/partial scan must be visible so an incomplete policy isn't mistaken for complete.
	data := Data{
		Config: ReportConfig{StaleDays: 90},
		Errors: []string{"eu-central-1/repo-x: ThrottlingException", "eu-central-1/repo-y: timeout"},
	}
	var buf bytes.Buffer
	if err := (&PolicyReporter{Writer: &buf}).Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Warnings (2)") {
		t.Errorf("expected warnings header, got:\n%s", out)
	}
	if !strings.Contains(out, "ThrottlingException") {
		t.Errorf("expected error text surfaced, got:\n%s", out)
	}
}
