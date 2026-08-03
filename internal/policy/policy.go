// WO-14: turn scan findings + retention rules into a recommended ECR lifecycle
// policy and a confidence-scored delete plan. Output-only — never deletes; it
// produces a human-reviewable plan (AWS JSON, Terraform, delete script).
package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ppiankov/ecrspectre/internal/retention"
)

// WO-14: protectKeepDefault is the countNumber for the "keep protected tags" rule.
const protectKeepDefault = 100

// WO-14: PolicyConfig captures the thresholds encoded into a lifecycle policy.
type PolicyConfig struct {
	KeepLatestN  int
	UntaggedDays int
	StaleDays    int
	ProtectTags  []string
}

// WO-14: TagStatus is the ECR lifecycle selection tagStatus value.
type TagStatus string

const (
	// WO-14: TagStatusAny matches tagged and untagged images.
	TagStatusAny TagStatus = "any"
	// WO-14: TagStatusTagged matches images carrying at least one tag.
	TagStatusTagged TagStatus = "tagged"
	// WO-14: TagStatusUntagged matches images with no tags.
	TagStatusUntagged TagStatus = "untagged"
)

// WO-14: selection is one lifecycle-rule selection clause (AWS schema subset).
type selection struct {
	TagStatus      TagStatus `json:"tagStatus"`
	TagPatternList []string  `json:"tagPatternList,omitempty"`
	CountType      string    `json:"countType,omitempty"`
	CountUnit      string    `json:"countUnit,omitempty"`
	CountNumber    int       `json:"countNumber,omitempty"`
}

// WO-14: expireAction is the lifecycle-rule expire action.
type expireAction struct {
	Type string `json:"type"`
}

// WO-14: LifecycleRule is one ECR lifecycle-policy rule.
type LifecycleRule struct {
	RulePriority int           `json:"rulePriority"`
	Description  string        `json:"description,omitempty"`
	Selection    selection     `json:"selection"`
	Action       *expireAction `json:"action"`
}

// WO-14: LifecyclePolicy is the AWS ECR policy document.
type LifecyclePolicy struct {
	Rules []LifecycleRule `json:"rules"`
}

// WO-14: GenerateLifecyclePolicy builds a recommended ECR lifecycle policy. Rules
// are ordered protect-tags -> keep-latest-N -> expire-untagged -> expire-stale.
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

// WO-14: GeneratePolicyJSON returns the lifecycle policy as pretty-printed AWS JSON.
func GeneratePolicyJSON(cfg PolicyConfig) ([]byte, error) {
	return json.MarshalIndent(GenerateLifecyclePolicy(cfg), "", "  ")
}

// WO-14: GenerateTerraform returns an aws_ecr_lifecycle_policy resource with the
// generated policy embedded as a heredoc.
func GenerateTerraform(repoName string, cfg PolicyConfig) (string, error) {
	js, err := GeneratePolicyJSON(cfg)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("resource \"aws_ecr_lifecycle_policy\" %q {\n  repository = %q\n  policy = <<EOF\n%s\nEOF\n}\n",
		terraformResourceName(repoName), repoName, js), nil
}

// WO-14: terraformResourceName turns a repository name into a valid Terraform label.
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

// WO-14: Confidence rates how safe an image is to delete.
type Confidence string

const (
	// WO-14: ConfKeep means retained by a retention rule (do not delete).
	ConfKeep Confidence = "keep"
	// WO-14: ConfHigh means untagged and stale.
	ConfHigh Confidence = "high"
	// WO-14: ConfMedium means stale.
	ConfMedium Confidence = "medium"
	// WO-14: ConfLow means other (e.g. only oversized).
	ConfLow Confidence = "low"
)

// WO-14: ScoreFinding maps a finding's signals + retention verdict to a delete
// confidence with a reason; a Keep verdict always wins.
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
