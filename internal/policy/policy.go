// WO-14: turn scan findings + retention rules into a recommended ECR lifecycle
// policy and a confidence-scored delete plan. Output-only — it never deletes; it
// produces a human-reviewable plan (AWS JSON, Terraform, delete script).
package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ppiankov/ecrspectre/internal/retention"
)

// protectKeepDefault is the countNumber used by the "keep protected tags" rule.
// ECR lifecycle policies have no "never expire" action, so a large countNumber
// keeps all practically-relevant protected images; the operator tunes the output.
const protectKeepDefault = 100

// PolicyConfig captures the thresholds encoded into a recommended lifecycle policy.
type PolicyConfig struct {
	KeepLatestN  int      // keep the N most recent images (0 = omit the rule)
	UntaggedDays int      // expire untagged images older than this (0 = omit)
	StaleDays    int      // expire tagged images older than this (0 = omit)
	ProtectTags  []string // tags to keep (e.g. latest, release)
}

// TagStatus is the ECR lifecycle selection tagStatus value.
type TagStatus string

const (
	TagStatusAny      TagStatus = "any"
	TagStatusTagged   TagStatus = "tagged"
	TagStatusUntagged TagStatus = "untagged"
)

type selection struct {
	TagStatus      TagStatus `json:"tagStatus"`
	TagPatternList []string  `json:"tagPatternList,omitempty"`
	CountType      string    `json:"countType,omitempty"`
	CountUnit      string    `json:"countUnit,omitempty"`
	CountNumber    int       `json:"countNumber,omitempty"`
}

type expireAction struct {
	Type string `json:"type"`
}

// LifecycleRule is one ECR lifecycle-policy rule.
type LifecycleRule struct {
	RulePriority int           `json:"rulePriority"`
	Description  string        `json:"description,omitempty"`
	Selection    selection     `json:"selection"`
	Action       *expireAction `json:"action"`
}

// LifecyclePolicy is the AWS ECR policy document.
type LifecyclePolicy struct {
	Rules []LifecycleRule `json:"rules"`
}

// GenerateLifecyclePolicy builds a recommended ECR lifecycle policy. Rules are
// ordered protect-tags -> keep-latest-N -> expire-untagged -> expire-stale, the
// standard cleanup pattern. Returns an empty policy if no thresholds are set.
func GenerateLifecyclePolicy(cfg PolicyConfig) LifecyclePolicy {
	var rules []LifecycleRule
	pri := 1
	add := func(desc string, sel selection) {
		rules = append(rules, LifecycleRule{
			RulePriority: pri,
			Description:  desc,
			Selection:    sel,
			Action:       &expireAction{Type: "expire"},
		})
		pri++
	}
	if len(cfg.ProtectTags) > 0 {
		add(fmt.Sprintf("Keep protected tags (%s)", strings.Join(cfg.ProtectTags, ", ")),
			selection{TagStatus: TagStatusTagged, TagPatternList: cfg.ProtectTags, CountType: "imageCountMoreThan", CountNumber: protectKeepDefault})
	}
	if cfg.KeepLatestN > 0 {
		add(fmt.Sprintf("Keep the %d most recent images", cfg.KeepLatestN),
			selection{TagStatus: TagStatusAny, CountType: "imageCountMoreThan", CountNumber: cfg.KeepLatestN})
	}
	if cfg.UntaggedDays > 0 {
		add(fmt.Sprintf("Expire untagged images older than %d days", cfg.UntaggedDays),
			selection{TagStatus: TagStatusUntagged, CountType: "sinceImagePushed", CountUnit: "days", CountNumber: cfg.UntaggedDays})
	}
	if cfg.StaleDays > 0 {
		add(fmt.Sprintf("Expire images older than %d days", cfg.StaleDays),
			selection{TagStatus: TagStatusAny, CountType: "sinceImagePushed", CountUnit: "days", CountNumber: cfg.StaleDays})
	}
	return LifecyclePolicy{Rules: rules}
}

// GeneratePolicyJSON returns the lifecycle policy as pretty-printed AWS JSON.
func GeneratePolicyJSON(cfg PolicyConfig) ([]byte, error) {
	return json.MarshalIndent(GenerateLifecyclePolicy(cfg), "", "  ")
}

// GenerateTerraform returns an aws_ecr_lifecycle_policy resource for the repo
// with the generated policy embedded as a heredoc.
func GenerateTerraform(repoName string, cfg PolicyConfig) (string, error) {
	js, err := GeneratePolicyJSON(cfg)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("resource \"aws_ecr_lifecycle_policy\" %q {\n  repository = %q\n  policy = <<EOF\n%s\nEOF\n}\n",
		terraformResourceName(repoName), repoName, js), nil
}

// terraformResourceName turns a repository name into a valid Terraform resource
// label (replace non [A-Za-z0-9_] with '_').
func terraformResourceName(repo string) string {
	var b strings.Builder
	for _, r := range repo {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// Confidence rates how safe an image is to delete.
type Confidence string

const (
	ConfKeep   Confidence = "keep"   // retained by a retention rule (do not delete)
	ConfHigh   Confidence = "high"   // untagged and stale
	ConfMedium Confidence = "medium" // stale
	ConfLow    Confidence = "low"    // other (e.g. only oversized)
)

// ScoreFinding maps a finding's signals + its retention verdict to a delete
// confidence with a reason. A Keep verdict always wins (the image is protected).
func ScoreFinding(daysStale int, untagged bool, verdict retention.Verdict) (Confidence, string) {
	if verdict.Decision == retention.Keep {
		return ConfKeep, "retained: " + verdict.Reason
	}
	switch {
	case untagged && daysStale > 0:
		return ConfHigh, "untagged and stale"
	case daysStale > 0:
		return ConfMedium, "stale"
	default:
		return ConfLow, "not stale or untagged"
	}
}
