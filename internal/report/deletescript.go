package report

import (
	"io"
	"strings"
	"time"

	"github.com/ppiankov/ecrspectre/internal/registry"
	"github.com/ppiankov/ecrspectre/internal/retention"
)

// WO-14: DeleteScriptReporter prints `aws ecr batch-delete-image` commands for
// findings that are delete candidates (stale or untagged) and not protected by a
// retention rule. It NEVER executes them — output only.
type DeleteScriptReporter struct {
	Writer io.Writer
}

// Generate writes the dry-run delete commands.
func (r *DeleteScriptReporter) Generate(data Data) error {
	protect := data.Config.Retention.ProtectTags
	if len(protect) == 0 {
		protect = retention.DefaultProtectTags()
	}
	rules := retention.Rules{ProtectTags: protect, MinAgeDays: data.Config.Retention.MinAgeDays}

	now := data.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	w := &errWriter{w: r.Writer}
	w.println("# DRY RUN — ecrspectre did NOT delete anything. Review, then run manually.")
	w.println("# Targets stale/untagged images not protected by a retention rule.")
	w.println("# NOTE: keep-latest-N is enforced by the lifecycle policy (--format policy),")
	w.println("# not here, because this script only sees flagged images.")
	count := 0
	for _, f := range data.Findings {
		if f.ResourceType != registry.ResourceImage || !isDeleteCandidate(f) {
			continue
		}
		verdicts, err := retention.Classify([]retention.Image{{Tags: tagsOf(f), PushedAt: pushedAt(f, now)}}, rules, now)
		if err != nil || verdicts[0].Decision == retention.Keep {
			continue
		}
		repo := repoOf(f.ResourceID)
		digest := digestOf(f)
		if repo == "" || digest == "" {
			continue
		}
		w.printf("aws ecr batch-delete-image --repository %s --image-ids imageDigest=%s --region %s\n",
			repo, digest, f.Region)
		count++
	}
	w.println("")
	w.printf("# %d candidate(s). Review the commands above before running.\n", count)
	writeWarnings(w, data.Errors)
	return w.err
}

// isDeleteCandidate reports whether a finding represents a stale or untagged image.
func isDeleteCandidate(f registry.Finding) bool {
	return f.ID == registry.FindingStaleImage || f.ID == registry.FindingUntaggedImage
}

// tagsOf extracts image tags from a finding's ResourceName ("repo:tag1,tag2").
func tagsOf(f registry.Finding) []string {
	name := f.ResourceName
	if i := strings.IndexByte(name, ':'); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		return nil
	}
	return strings.Split(name, ",")
}

// digestOf returns the image digest from metadata, falling back to the ResourceID.
func digestOf(f registry.Finding) string {
	if d, ok := f.Metadata["digest"].(string); ok && d != "" {
		return d
	}
	if i := strings.IndexByte(f.ResourceID, '@'); i >= 0 {
		return f.ResourceID[i+1:]
	}
	return ""
}

// pushedAt reconstructs an approximate push time from the finding's days_stale.
func pushedAt(f registry.Finding, now time.Time) time.Time {
	if days := metaInt(f.Metadata, "days_stale"); days > 0 {
		return now.Add(-time.Duration(days) * 24 * time.Hour)
	}
	return time.Time{}
}

// metaInt reads an int from a findings metadata map, tolerating int/int64/float64.
func metaInt(m map[string]any, key string) int {
	switch n := m[key].(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}
