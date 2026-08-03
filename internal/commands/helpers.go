package commands

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ppiankov/ecrspectre/internal/config"
	"github.com/ppiankov/ecrspectre/internal/registry"
	"github.com/spf13/cobra"
)

// enhanceError wraps an error with context and suggestions for common cloud issues.
func enhanceError(action string, err error) error {
	msg := err.Error()

	var hint string
	switch {
	case strings.Contains(msg, "NoCredentialProviders"):
		hint = "Configure AWS credentials: set AWS_PROFILE, AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, or run 'aws configure'"
	case strings.Contains(msg, "ExpiredToken"):
		hint = "AWS session token expired. Refresh credentials or run 'aws sso login'"
	case strings.Contains(msg, "AccessDenied") || strings.Contains(msg, "UnauthorizedAccess"):
		hint = "Insufficient permissions. Apply the IAM policy from 'ecrspectre init' to your role/user"
	case strings.Contains(msg, "RequestExpired"):
		hint = "Request expired. Check system clock synchronization"
	case strings.Contains(msg, "Throttling"):
		hint = "API rate limit hit. Retry with fewer regions or increase timeout"
	case strings.Contains(msg, "GOOGLE_APPLICATION_CREDENTIALS"):
		hint = "Configure GCP credentials: set GOOGLE_APPLICATION_CREDENTIALS or run 'gcloud auth application-default login'"
	case strings.Contains(msg, "could not find default credentials"):
		hint = "Configure GCP credentials: run 'gcloud auth application-default login'"
	}

	if hint != "" {
		return fmt.Errorf("%s: %w\n  hint: %s", action, err, hint)
	}
	return fmt.Errorf("%s: %w", action, err)
}

// computeTargetHash generates a SHA256 hash for the target URI.
func computeTargetHash(provider string, regions []string, project string) string {
	input := fmt.Sprintf("provider:%s,regions:%s,project:%s", provider, strings.Join(regions, ","), project)
	h := sha256.Sum256([]byte(input))
	return fmt.Sprintf("sha256:%x", h)
}

// scanFlagRefs holds pointers to the overridable scan flags of a provider command.
// WO-8: lets one applyConfigDefaults serve both aws and gcp without duplicating
// the explicit-flag > config > default precedence logic.
type scanFlagRefs struct {
	format         *string
	staleDays      *int
	maxSizeMB      *int
	minMonthlyCost *float64
	timeout        *time.Duration
	project        *string // nil for providers without a project flag
}

// WO-8: applies config values only for flags the user did NOT set explicitly
// (WO-7 precedence logic, hoisted here so it lives once); project only when non-nil.
func applyConfigDefaults(cmd *cobra.Command, cfg config.Config, r scanFlagRefs) {
	f := cmd.Flags()
	if !f.Changed("format") && cfg.Format != "" {
		*r.format = cfg.Format
	}
	if !f.Changed("stale-days") && cfg.StaleDays > 0 {
		*r.staleDays = cfg.StaleDays
	}
	if !f.Changed("max-size") && cfg.MaxSizeMB > 0 {
		*r.maxSizeMB = cfg.MaxSizeMB
	}
	if !f.Changed("min-monthly-cost") && cfg.MinMonthlyCost > 0 {
		*r.minMonthlyCost = cfg.MinMonthlyCost
	}
	if !f.Changed("timeout") && cfg.TimeoutDuration() > 0 {
		*r.timeout = cfg.TimeoutDuration()
	}
	if r.project != nil && !f.Changed("project") && cfg.Project != "" {
		*r.project = cfg.Project
	}
}

// WO-8: converts a config resource-ID exclude list into the set the scanner
// consumes; hoisted verbatim from runAWS/runGCP.
func buildExcludeIDs(ids []string) map[string]bool {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// WO-8: returns a progress callback that writes to stderr, or nil when disabled;
// hoisted verbatim from runAWS/runGCP.
func stderrProgressFn(disabled bool) func(registry.ScanProgress) {
	if disabled {
		return nil
	}
	return func(p registry.ScanProgress) {
		fmt.Fprintf(os.Stderr, "[%s] %s\n", p.Region, p.Message)
	}
}
