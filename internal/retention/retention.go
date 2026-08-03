// Package retention classifies container images into keep vs delete-candidate
// using configurable rules: protected tags, keep-latest-N (optionally per semver
// major), keep-last-per-branch, and minimum age. It is pure and deterministic —
// no cloud calls — so it can be unit-tested and reused by both the finding
// classifier and the lifecycle-policy generator (WO-13).
package retention

import (
	"fmt"
	"regexp"
	"sort"
	"time"
)

// Decision is the retention verdict for a single image.
type Decision string

const (
	// Keep means the image must be retained regardless of waste findings.
	Keep Decision = "keep"
	// Candidate means the image is eligible for cleanup (subject to the caller's policy).
	Candidate Decision = "candidate"
)

// Rules configures the retention engine. All fields optional; ProtectTags
// defaults to ^latest$ and ^release(-.*)?$ when empty.
type Rules struct {
	KeepLatestN         int      // keep the N most-recent images (per repo; per major if KeepLatestNPerMajor)
	KeepLatestNPerMajor bool     // apply KeepLatestN within each semver major version
	KeepLastPerBranch   bool     // keep the most-recent image per branch tag (matched by BranchPattern)
	BranchPattern       string   // regex matching branch tags; required when KeepLastPerBranch is true
	ProtectTags         []string // regexes; any image with a matching tag is always Keep
	MinAgeDays          int      // images younger than this many days are always Keep
}

// Image is the engine's input for one image.
type Image struct {
	Tags     []string
	PushedAt time.Time // image push/creation time
}

// Verdict is the engine's output for one image, preserving input order.
type Verdict struct {
	Tags     []string
	Decision Decision
	Reason   string
}

// DefaultProtectTags returns the default protected-tag regexes.
func DefaultProtectTags() []string {
	return []string{`^latest$`, `^release(-.*)?$`}
}

// semverMajor matches a leading optional "v" followed by the major digits.
var semverMajor = regexp.MustCompile(`^v?(\d+)`)

// majorOf returns the semver major ("1", "2", ...) of the first version-shaped
// tag, or "" if no tag is version-shaped.
func majorOf(tags []string) string {
	for _, t := range tags {
		if m := semverMajor.FindStringSubmatch(t); len(m) == 2 && m[1] != "" {
			return m[1]
		}
	}
	return ""
}

func matchesAny(tags []string, res []*regexp.Regexp) bool {
	for _, t := range tags {
		for _, re := range res {
			if re.MatchString(t) {
				return true
			}
		}
	}
	return false
}

func compileAll(patterns []string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("retention: invalid regex %q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// Classify returns one Verdict per input image (same index/order). An image is
// Keep if any rule protects it; otherwise Candidate. Rule precedence is
// protect-tags, then min-age, then keep-latest-N, then keep-last-per-branch;
// the first matching rule wins and an image already kept is never downgraded.
// now is injected so tests are deterministic.
func Classify(images []Image, rules Rules, now time.Time) ([]Verdict, error) {
	if len(rules.ProtectTags) == 0 {
		rules.ProtectTags = DefaultProtectTags()
	}
	protect, err := compileAll(rules.ProtectTags)
	if err != nil {
		return nil, err
	}
	var branchRE *regexp.Regexp
	if rules.KeepLastPerBranch && rules.BranchPattern != "" {
		res, err := compileAll([]string{rules.BranchPattern})
		if err != nil {
			return nil, err
		}
		branchRE = res[0]
	}

	v := make([]Verdict, len(images))
	markKeep := func(i int, reason string) {
		if v[i].Decision != Keep { // first matching rule wins
			v[i].Decision = Keep
			v[i].Reason = reason
		}
	}
	for i, img := range images {
		v[i].Tags = img.Tags
		v[i].Decision = Candidate
		v[i].Reason = "not protected and not within any keep rule"
		if matchesAny(img.Tags, protect) {
			markKeep(i, "protected tag")
			continue
		}
		if rules.MinAgeDays > 0 && !img.PushedAt.IsZero() &&
			now.Sub(img.PushedAt) < time.Duration(rules.MinAgeDays)*24*time.Hour {
			markKeep(i, fmt.Sprintf("below min age (%dd)", rules.MinAgeDays))
		}
	}

	if rules.KeepLatestN > 0 {
		keepLatestN(images, rules, markKeep)
	}
	if branchRE != nil {
		keepLastPerBranch(images, branchRE, markKeep)
	}
	return v, nil
}

// keepLatestN marks the N most-recent images Keep, optionally within each major.
// Images already kept by an earlier rule still occupy a slot in the top N.
func keepLatestN(images []Image, rules Rules, markKeep func(int, string)) {
	if rules.KeepLatestNPerMajor {
		groups := map[string][]int{}
		for i, img := range images {
			if maj := majorOf(img.Tags); maj != "" {
				groups[maj] = append(groups[maj], i)
			}
		}
		for maj, idxs := range groups {
			keepTopN(idxs, images, rules.KeepLatestN, markKeep, fmt.Sprintf("within latest %d for major %s", rules.KeepLatestN, maj))
		}
		return
	}
	idxs := make([]int, len(images))
	for i := range images {
		idxs[i] = i
	}
	keepTopN(idxs, images, rules.KeepLatestN, markKeep, fmt.Sprintf("within latest %d", rules.KeepLatestN))
}

// keepTopN sorts idxs by PushedAt descending (stable) and keeps the first n.
func keepTopN(idxs []int, images []Image, n int, markKeep func(int, string), reason string) {
	sort.SliceStable(idxs, func(a, b int) bool {
		return images[idxs[a]].PushedAt.After(images[idxs[b]].PushedAt)
	})
	for k, i := range idxs {
		if k >= n {
			break
		}
		markKeep(i, reason)
	}
}

// keepLastPerBranch keeps the most-recent image carrying each branch tag.
func keepLastPerBranch(images []Image, branchRE *regexp.Regexp, markKeep func(int, string)) {
	best := map[string]int{} // branch tag -> index of the most-recent image with it
	for i, img := range images {
		for _, t := range img.Tags {
			if !branchRE.MatchString(t) {
				continue
			}
			if cur, ok := best[t]; !ok || images[i].PushedAt.After(images[cur].PushedAt) {
				best[t] = i
			}
		}
	}
	for branch, i := range best {
		markKeep(i, "last build of branch "+branch)
	}
}
