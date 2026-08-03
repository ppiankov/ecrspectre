// WO-13: pure retention engine — classifies images into keep vs delete-candidate
// using configurable rules (protected tags, keep-latest-N optionally per semver
// major, keep-last-per-branch, minimum age); no cloud calls; consumed by the
// lifecycle-policy generator and the finding classifier.
package retention

import (
	"fmt"
	"regexp"
	"sort"
	"time"
)

// WO-13: Decision is the retention verdict for a single image.
type Decision string

// WO-13: Keep (retain) and Candidate (cleanup-eligible) Decision values.
const (
	Keep      Decision = "keep"
	Candidate Decision = "candidate"
)

// WO-13: Rules configures the retention engine; ProtectTags defaults when empty.
type Rules struct {
	KeepLatestN         int
	KeepLatestNPerMajor bool
	KeepLastPerBranch   bool
	BranchPattern       string
	ProtectTags         []string
	MinAgeDays          int
}

// WO-13: Image is the engine's input for one image.
type Image struct {
	Tags     []string
	PushedAt time.Time
}

// WO-13: Verdict is the engine's output for one image, preserving input order.
type Verdict struct {
	Tags     []string
	Decision Decision
	Reason   string
}

// WO-13: DefaultProtectTags returns the default protected-tag regexes.
func DefaultProtectTags() []string {
	return []string{`^latest$`, `^release(-.*)?$`}
}

// WO-13: semverMajor matches a leading optional "v" followed by the major digits.
var semverMajor = regexp.MustCompile(`^v?(\d+)`)

// WO-13: majorOf returns the semver major of the first version-shaped tag, or "".
func majorOf(tags []string) string {
	for _, t := range tags {
		if m := semverMajor.FindStringSubmatch(t); len(m) == 2 && m[1] != "" {
			return m[1]
		}
	}
	return ""
}

// WO-13: matchesAny reports whether any tag matches any regex.
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

// WO-13: compileAll compiles a set of regex patterns, erroring on any invalid one.
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

// WO-13: Classify returns one Verdict per input image (preserving order); an image
// is Keep if any rule protects it, else Candidate. Precedence is protect-tags,
// min-age, keep-latest-N, keep-last-per-branch; first match wins, never downgraded.
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
		if v[i].Decision != Keep {
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

// WO-13: keepLatestN marks the N most-recent images Keep, optionally per major.
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

// WO-13: keepTopN sorts idxs by PushedAt desc (stable) and keeps the first n.
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

// WO-13: keepLastPerBranch keeps the most-recent image carrying each branch tag.
func keepLastPerBranch(images []Image, branchRE *regexp.Regexp, markKeep func(int, string)) {
	best := map[string]int{}
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
