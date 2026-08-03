package retention

import (
	"testing"
	"time"
)

// WO-13: mustTime parses a strict RFC3339 timestamp, panicking on error.
func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// WO-13: table-driven coverage of Classify across all rule combinations.
func TestClassify(t *testing.T) {
	now := mustTime("2026-08-03T00:00:00Z")
	daysAgo := func(n int) time.Time { return now.Add(-time.Duration(n) * 24 * time.Hour) }

	tests := []struct {
		name   string
		images []Image
		rules  Rules
		want   []Decision
	}{
		{
			name: "default protect tags keep latest and release",
			images: []Image{
				{Tags: []string{"latest"}, PushedAt: daysAgo(365)},
				{Tags: []string{"release"}, PushedAt: daysAgo(365)},
				{Tags: []string{"1.0.0"}, PushedAt: daysAgo(365)},
				{Tags: nil, PushedAt: daysAgo(365)},
			},
			rules: Rules{},
			want:  []Decision{Keep, Keep, Candidate, Candidate},
		},
		{
			name: "custom protect tags override defaults",
			images: []Image{
				{Tags: []string{"stable"}, PushedAt: daysAgo(400)},
				{Tags: []string{"1.0.0"}, PushedAt: daysAgo(400)},
				{Tags: []string{"latest"}, PushedAt: daysAgo(400)}, // no longer protected
			},
			rules: Rules{ProtectTags: []string{`^stable$`}},
			want:  []Decision{Keep, Candidate, Candidate},
		},
		{
			name: "min age keeps young images",
			images: []Image{
				{Tags: []string{"1.0.0"}, PushedAt: daysAgo(5)},   // younger than 30d
				{Tags: []string{"1.0.1"}, PushedAt: daysAgo(200)}, // older
			},
			rules: Rules{MinAgeDays: 30},
			want:  []Decision{Keep, Candidate},
		},
		{
			name: "keep latest N overall",
			images: []Image{
				{Tags: []string{"1.0.0"}, PushedAt: daysAgo(100)},
				{Tags: []string{"1.0.1"}, PushedAt: daysAgo(50)},
				{Tags: []string{"1.0.2"}, PushedAt: daysAgo(10)},
				{Tags: []string{"1.0.3"}, PushedAt: daysAgo(1)},
			},
			rules: Rules{KeepLatestN: 2},
			want:  []Decision{Candidate, Candidate, Keep, Keep},
		},
		{
			name: "keep latest N per major",
			images: []Image{
				{Tags: []string{"1.0.0"}, PushedAt: daysAgo(100)}, // major 1
				{Tags: []string{"1.1.0"}, PushedAt: daysAgo(40)},  // major 1, newest of major 1
				{Tags: []string{"2.0.0"}, PushedAt: daysAgo(80)},  // major 2
				{Tags: []string{"2.1.0"}, PushedAt: daysAgo(20)},  // major 2
				{Tags: []string{"2.2.0"}, PushedAt: daysAgo(5)},   // major 2, newest of major 2
			},
			rules: Rules{KeepLatestN: 1, KeepLatestNPerMajor: true},
			want:  []Decision{Candidate, Keep, Candidate, Candidate, Keep},
		},
		{
			name: "keep last per branch",
			images: []Image{
				{Tags: []string{"pr-100"}, PushedAt: daysAgo(10)},
				{Tags: []string{"pr-100"}, PushedAt: daysAgo(2)}, // newest pr-100 -> keep
				{Tags: []string{"pr-101"}, PushedAt: daysAgo(1)}, // only pr-101 -> keep
				{Tags: []string{"1.0.0"}, PushedAt: daysAgo(200)},
			},
			rules: Rules{KeepLastPerBranch: true, BranchPattern: `^pr-`},
			want:  []Decision{Candidate, Keep, Keep, Candidate},
		},
		{
			name: "untagged image is candidate unless in latest N",
			images: []Image{
				{Tags: nil, PushedAt: daysAgo(1)}, // newest -> in top N
				{Tags: nil, PushedAt: daysAgo(100)},
				{Tags: nil, PushedAt: daysAgo(200)},
			},
			rules: Rules{KeepLatestN: 1},
			want:  []Decision{Keep, Candidate, Candidate},
		},
		{
			name: "protect precedence over latest N reason",
			images: []Image{
				{Tags: []string{"latest"}, PushedAt: daysAgo(1)},
				{Tags: []string{"1.0.0"}, PushedAt: daysAgo(2)},
			},
			rules: Rules{KeepLatestN: 2},
			want:  []Decision{Keep, Keep},
		},
		{
			name: "combined protect + latest N + branch",
			images: []Image{
				{Tags: []string{"release"}, PushedAt: daysAgo(400)}, // protect
				{Tags: []string{"3.0.0"}, PushedAt: daysAgo(3)},     // top-3 by recency
				{Tags: []string{"3.0.1"}, PushedAt: daysAgo(2)},     // top-3
				{Tags: []string{"3.0.2"}, PushedAt: daysAgo(1)},     // top-3
				{Tags: []string{"pr-9"}, PushedAt: daysAgo(5)},      // last of branch pr-9
				{Tags: []string{"1.0.0"}, PushedAt: daysAgo(300)},   // candidate
			},
			rules: Rules{KeepLatestN: 3, KeepLastPerBranch: true, BranchPattern: `^pr-`},
			want:  []Decision{Keep, Keep, Keep, Keep, Keep, Candidate},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Classify(tt.images, tt.rules, now)
			if err != nil {
				t.Fatalf("Classify error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d verdicts, want %d", len(got), len(tt.want))
			}
			for i, w := range tt.want {
				if got[i].Decision != w {
					t.Errorf("image %d %v: decision=%s want=%s (reason=%q)", i, got[i].Tags, got[i].Decision, w, got[i].Reason)
				}
			}
		})
	}
}

// WO-13: invalid protect/branch regexes return an error.
func TestClassifyInvalidRegex(t *testing.T) {
	if _, err := Classify(nil, Rules{ProtectTags: []string{"("}}, time.Now()); err == nil {
		t.Fatal("expected error for invalid protect regex")
	}
	if _, err := Classify(nil, Rules{KeepLastPerBranch: true, BranchPattern: "("}, time.Now()); err == nil {
		t.Fatal("expected error for invalid branch regex")
	}
}

// WO-13: majorOf parses leading version digits; non-version tags yield "".
func TestMajorOf(t *testing.T) {
	tests := []struct {
		tags []string
		want string
	}{
		{[]string{"1.2.3"}, "1"},
		{[]string{"v2.0.0"}, "2"},
		{[]string{"4-1-3"}, "4"}, // dash-separated versions still expose their major
		{[]string{"latest"}, ""},
		{[]string{"ads-1916"}, ""}, // does not start with digits -> not version-shaped
		{[]string{"pr-100", "1.0.0"}, "1"},
		{nil, ""},
	}
	for _, tt := range tests {
		if got := majorOf(tt.tags); got != tt.want {
			t.Errorf("majorOf(%v)=%q want %q", tt.tags, got, tt.want)
		}
	}
}
