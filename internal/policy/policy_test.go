package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ppiankov/ecrspectre/internal/retention"
)

func TestGenerateLifecyclePolicy(t *testing.T) {
	cfg := PolicyConfig{
		KeepLatestN:  30,
		UntaggedDays: 7,
		StaleDays:    90,
		ProtectTags:  []string{"latest", "release"},
	}
	p := GenerateLifecyclePolicy(cfg)
	if len(p.Rules) != 4 {
		t.Fatalf("got %d rules, want 4", len(p.Rules))
	}
	// Priorities are sequential from 1.
	for i, r := range p.Rules {
		if r.RulePriority != i+1 {
			t.Errorf("rule %d priority=%d want %d", i, r.RulePriority, i+1)
		}
		if r.Action == nil || r.Action.Type != "expire" {
			t.Errorf("rule %d: missing expire action", i)
		}
	}
	// Order: protect -> keepLatestN -> untagged -> stale.
	if p.Rules[0].Selection.TagStatus != TagStatusTagged {
		t.Errorf("rule 0 tagStatus=%s want tagged", p.Rules[0].Selection.TagStatus)
	}
	if p.Rules[1].Selection.CountType != "imageCountMoreThan" || p.Rules[1].Selection.CountNumber != 30 {
		t.Errorf("keep-latest-N rule wrong: %+v", p.Rules[1].Selection)
	}
	if p.Rules[2].Selection.TagStatus != TagStatusUntagged || p.Rules[2].Selection.CountUnit != "days" {
		t.Errorf("untagged rule wrong: %+v", p.Rules[2].Selection)
	}
	if p.Rules[3].Selection.CountType != "sinceImagePushed" || p.Rules[3].Selection.CountNumber != 90 {
		t.Errorf("stale rule wrong: %+v", p.Rules[3].Selection)
	}
}

func TestGenerateLifecyclePolicyMinimal(t *testing.T) {
	p := GenerateLifecyclePolicy(PolicyConfig{StaleDays: 60})
	if len(p.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(p.Rules))
	}
	if p.Rules[0].Selection.CountNumber != 60 {
		t.Errorf("stale count=%d want 60", p.Rules[0].Selection.CountNumber)
	}
	if p.Rules[0].Selection.CountUnit != "days" {
		t.Errorf("stale countUnit=%q want days", p.Rules[0].Selection.CountUnit)
	}
}

func TestGenerateLifecyclePolicyEmpty(t *testing.T) {
	if p := GenerateLifecyclePolicy(PolicyConfig{}); len(p.Rules) != 0 {
		t.Fatalf("got %d rules, want 0 for empty config", len(p.Rules))
	}
}

func TestGeneratePolicyJSON(t *testing.T) {
	js, err := GeneratePolicyJSON(PolicyConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("GeneratePolicyJSON: %v", err)
	}
	var got LifecyclePolicy
	if err := json.Unmarshal(js, &got); err != nil {
		t.Fatalf("generated JSON invalid: %v\n%s", err, js)
	}
	if len(got.Rules) != 1 {
		t.Fatalf("round-trip rules=%d want 1", len(got.Rules))
	}
}

func TestGenerateTerraform(t *testing.T) {
	out, err := GenerateTerraform("talala/ads-core-backend", PolicyConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("GenerateTerraform: %v", err)
	}
	for _, want := range []string{
		`resource "aws_ecr_lifecycle_policy" "talala_ads_core_backend"`,
		`repository = "talala/ads-core-backend"`,
		"policy = <<EOF",
		"sinceImagePushed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terraform output missing %q\n%s", want, out)
		}
	}
}

func TestTerraformResourceName(t *testing.T) {
	tests := map[string]string{
		"talala/ads-core-backend": "talala_ads_core_backend",
		"env/android-builder":     "env_android_builder",
		"plain":                   "plain",
		"a.b-c/d":                 "a_b_c_d",
	}
	for in, want := range tests {
		if got := terraformResourceName(in); got != want {
			t.Errorf("terraformResourceName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestScoreFinding(t *testing.T) {
	tests := []struct {
		name      string
		daysStale int
		untagged  bool
		verdict   retention.Verdict
		want      Confidence
	}{
		{"keep verdict wins", 400, true, retention.Verdict{Decision: retention.Keep, Reason: "protected tag"}, ConfKeep},
		{"untagged and stale", 120, true, retention.Verdict{Decision: retention.Candidate}, ConfHigh},
		{"stale only", 120, false, retention.Verdict{Decision: retention.Candidate}, ConfMedium},
		{"neither", 0, false, retention.Verdict{Decision: retention.Candidate}, ConfLow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := ScoreFinding(tt.daysStale, tt.untagged, tt.verdict)
			if got != tt.want {
				t.Errorf("ScoreFinding(...)=%q want %q (reason=%q)", got, tt.want, reason)
			}
			if reason == "" {
				t.Error("reason must be non-empty")
			}
		})
	}
}
