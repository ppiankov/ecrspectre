package commands

import (
	"crypto/sha256"
	"fmt"
	"strings"
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
