package ecr

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecr "github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/ppiankov/ecrspectre/internal/registry"
)

var (
	now       = time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)
	recent    = now.AddDate(0, 0, -10)  // 10 days ago
	stale120  = now.AddDate(0, 0, -120) // 120 days ago
	stale200  = now.AddDate(0, 0, -200) // 200 days ago
	oneGB     = int64(1073741824)
	twoGB     = int64(2 * 1073741824)
	halfGB    = int64(536870912)
	hundredMB = int64(104857600)
)

func newTestScanner(client ECRAPI) *ECRScanner {
	s := NewECRScanner(client, "us-east-1", false)
	s.now = now
	return s
}

func defaultCfg() registry.ScanConfig {
	return registry.ScanConfig{
		StaleDays:    90,
		MaxSizeBytes: oneGB,
	}
}

func TestScanUntaggedImage(t *testing.T) {
	mock := newMockClient()
	mock.repos = []ecrtypes.Repository{makeRepo("myapp")}
	mock.images["myapp"] = []ecrtypes.ImageDetail{
		makeImage("sha256:aaa", nil, halfGB, recent, recent),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	untagged := findByID(result.Findings, registry.FindingUntaggedImage)
	if len(untagged) != 1 {
		t.Fatalf("expected 1 UNTAGGED_IMAGE, got %d", len(untagged))
	}
	if untagged[0].Severity != registry.SeverityHigh {
		t.Errorf("severity = %q, want high", untagged[0].Severity)
	}
}

func TestScanStaleImage(t *testing.T) {
	mock := newMockClient()
	mock.repos = []ecrtypes.Repository{makeRepo("myapp")}
	mock.images["myapp"] = []ecrtypes.ImageDetail{
		makeImage("sha256:bbb", []string{"v1.0"}, halfGB, stale200, stale120),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	stale := findByID(result.Findings, registry.FindingStaleImage)
	if len(stale) != 1 {
		t.Fatalf("expected 1 STALE_IMAGE, got %d", len(stale))
	}
	if stale[0].Severity != registry.SeverityHigh {
		t.Errorf("severity = %q, want high", stale[0].Severity)
	}
	if stale[0].Metadata["days_stale"].(int) < 120 {
		t.Errorf("days_stale = %v, want >= 120", stale[0].Metadata["days_stale"])
	}
}

func TestScanRecentImageNotStale(t *testing.T) {
	mock := newMockClient()
	mock.repos = []ecrtypes.Repository{makeRepo("myapp")}
	mock.images["myapp"] = []ecrtypes.ImageDetail{
		makeImage("sha256:ccc", []string{"latest"}, halfGB, stale200, recent),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	stale := findByID(result.Findings, registry.FindingStaleImage)
	if len(stale) != 0 {
		t.Errorf("expected 0 STALE_IMAGE for recently-pulled image, got %d", len(stale))
	}
}

func TestScanLargeImage(t *testing.T) {
	mock := newMockClient()
	mock.repos = []ecrtypes.Repository{makeRepo("myapp")}
	mock.images["myapp"] = []ecrtypes.ImageDetail{
		makeImage("sha256:ddd", []string{"latest"}, twoGB, recent, recent),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	large := findByID(result.Findings, registry.FindingLargeImage)
	if len(large) != 1 {
		t.Fatalf("expected 1 LARGE_IMAGE, got %d", len(large))
	}
	if large[0].Severity != registry.SeverityMedium {
		t.Errorf("severity = %q, want medium", large[0].Severity)
	}
}

func TestScanSmallImageNotLarge(t *testing.T) {
	mock := newMockClient()
	mock.repos = []ecrtypes.Repository{makeRepo("myapp")}
	mock.images["myapp"] = []ecrtypes.ImageDetail{
		makeImage("sha256:eee", []string{"latest"}, hundredMB, recent, recent),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	large := findByID(result.Findings, registry.FindingLargeImage)
	if len(large) != 0 {
		t.Errorf("expected 0 LARGE_IMAGE for 100MB image, got %d", len(large))
	}
}

func TestScanNoLifecyclePolicy(t *testing.T) {
	mock := newMockClient()
	mock.repos = []ecrtypes.Repository{makeRepo("myapp")}
	mock.images["myapp"] = []ecrtypes.ImageDetail{
		makeImage("sha256:fff", []string{"latest"}, halfGB, recent, recent),
	}
	// No lifecycle policy (default in mock)

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	nolp := findByID(result.Findings, registry.FindingNoLifecyclePolicy)
	if len(nolp) != 1 {
		t.Fatalf("expected 1 NO_LIFECYCLE_POLICY, got %d", len(nolp))
	}
}

func TestScanWithLifecyclePolicy(t *testing.T) {
	mock := newMockClient()
	mock.repos = []ecrtypes.Repository{makeRepo("myapp")}
	mock.images["myapp"] = []ecrtypes.ImageDetail{
		makeImage("sha256:ggg", []string{"latest"}, halfGB, recent, recent),
	}
	mock.lifecycleRepos["myapp"] = true

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	nolp := findByID(result.Findings, registry.FindingNoLifecyclePolicy)
	if len(nolp) != 0 {
		t.Errorf("expected 0 NO_LIFECYCLE_POLICY when policy exists, got %d", len(nolp))
	}
}

func TestScanEmptyRepo(t *testing.T) {
	mock := newMockClient()
	mock.repos = []ecrtypes.Repository{makeRepo("empty-repo")}
	mock.images["empty-repo"] = []ecrtypes.ImageDetail{}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	unused := findByID(result.Findings, registry.FindingUnusedRepo)
	if len(unused) != 1 {
		t.Fatalf("expected 1 UNUSED_REPO for empty repo, got %d", len(unused))
	}
	if unused[0].Message != "Repository has no images" {
		t.Errorf("message = %q", unused[0].Message)
	}
}

func TestScanAllStaleRepo(t *testing.T) {
	mock := newMockClient()
	mock.repos = []ecrtypes.Repository{makeRepo("old-repo")}
	mock.images["old-repo"] = []ecrtypes.ImageDetail{
		makeImage("sha256:h1", []string{"v1"}, halfGB, stale200, stale120),
		makeImage("sha256:h2", []string{"v2"}, halfGB, stale200, stale120),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	unused := findByID(result.Findings, registry.FindingUnusedRepo)
	if len(unused) != 1 {
		t.Fatalf("expected 1 UNUSED_REPO when all images stale, got %d", len(unused))
	}
	if unused[0].EstimatedMonthlyWaste <= 0 {
		t.Error("UNUSED_REPO should have non-zero waste")
	}
}

func TestScanExcludeRepo(t *testing.T) {
	mock := newMockClient()
	mock.repos = []ecrtypes.Repository{makeRepo("excluded"), makeRepo("included")}
	mock.images["included"] = []ecrtypes.ImageDetail{
		makeImage("sha256:iii", []string{"latest"}, halfGB, recent, recent),
	}

	cfg := defaultCfg()
	cfg.Exclude.ResourceIDs = map[string]bool{"excluded": true}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), cfg, nil)

	// Should not have findings about the excluded repo
	for _, f := range result.Findings {
		if f.ResourceID == "excluded" {
			t.Error("excluded repo should not have findings")
		}
	}
}

func TestScanDescribeRepositoriesError(t *testing.T) {
	mock := newMockClient()
	mock.descRepoErr = errors.New("access denied")

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(result.Errors) == 0 {
		t.Error("expected error in result.Errors")
	}
	if len(result.Findings) != 0 {
		t.Error("expected no findings on error")
	}
}

func TestScanDescribeImagesError(t *testing.T) {
	mock := newMockClient()
	mock.repos = []ecrtypes.Repository{makeRepo("broken-repo")}
	mock.descImagesErr["broken-repo"] = errors.New("throttled")

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(result.Errors) == 0 {
		t.Error("expected error in result.Errors")
	}
}

func TestScanMultiArchBloat(t *testing.T) {
	mock := newMockClient()
	mock.repos = []ecrtypes.Repository{makeRepo("multiarch")}

	img := makeImage("sha256:multi", []string{"latest"}, twoGB, stale200, stale120)
	img.ImageManifestMediaType = aws.String("application/vnd.docker.distribution.manifest.list.v2+json")
	mock.images["multiarch"] = []ecrtypes.ImageDetail{img}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	bloat := findByID(result.Findings, registry.FindingMultiArchBloat)
	if len(bloat) != 1 {
		t.Fatalf("expected 1 MULTI_ARCH_BLOAT, got %d", len(bloat))
	}
}

func TestScanVulnerabilities(t *testing.T) {
	mock := newMockClient()
	mock.scanFindings["myapp@sha256:vuln"] = &awsecr.DescribeImageScanFindingsOutput{
		ImageScanFindings: &ecrtypes.ImageScanFindings{
			Findings: []ecrtypes.ImageScanFinding{
				{Severity: ecrtypes.FindingSeverityCritical},
				{Severity: ecrtypes.FindingSeverityHigh},
				{Severity: ecrtypes.FindingSeverityMedium},
			},
		},
	}

	s := newTestScanner(mock)
	findings, err := s.ScanVulnerabilities(context.Background(), "myapp", "sha256:vuln")
	if err != nil {
		t.Fatalf("ScanVulnerabilities() error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 VULNERABLE_IMAGE, got %d", len(findings))
	}
	if findings[0].Severity != registry.SeverityCritical {
		t.Errorf("severity = %q, want critical", findings[0].Severity)
	}
}

func TestScanVulnerabilitiesLowOnly(t *testing.T) {
	mock := newMockClient()
	mock.scanFindings["myapp@sha256:low"] = &awsecr.DescribeImageScanFindingsOutput{
		ImageScanFindings: &ecrtypes.ImageScanFindings{
			Findings: []ecrtypes.ImageScanFinding{
				{Severity: ecrtypes.FindingSeverityLow},
			},
		},
	}

	s := newTestScanner(mock)
	findings, err := s.ScanVulnerabilities(context.Background(), "myapp", "sha256:low")
	if err != nil {
		t.Fatalf("ScanVulnerabilities() error: %v", err)
	}

	if len(findings) != 0 {
		t.Error("expected no findings for low-only vulnerabilities")
	}
}

func TestScanResourcesScannedCount(t *testing.T) {
	mock := newMockClient()
	mock.repos = []ecrtypes.Repository{makeRepo("repo1"), makeRepo("repo2")}
	mock.images["repo1"] = []ecrtypes.ImageDetail{
		makeImage("sha256:r1a", []string{"v1"}, hundredMB, recent, recent),
		makeImage("sha256:r1b", []string{"v2"}, hundredMB, recent, recent),
	}
	mock.images["repo2"] = []ecrtypes.ImageDetail{
		makeImage("sha256:r2a", []string{"v1"}, hundredMB, recent, recent),
	}
	mock.lifecycleRepos["repo1"] = true
	mock.lifecycleRepos["repo2"] = true

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if result.ResourcesScanned != 3 {
		t.Errorf("ResourcesScanned = %d, want 3", result.ResourcesScanned)
	}
	if result.RepositoriesScanned != 2 {
		t.Errorf("RepositoriesScanned = %d, want 2", result.RepositoriesScanned)
	}
}

func TestScanProgress(t *testing.T) {
	mock := newMockClient()
	mock.repos = []ecrtypes.Repository{makeRepo("myapp")}
	mock.images["myapp"] = []ecrtypes.ImageDetail{
		makeImage("sha256:prog", []string{"latest"}, hundredMB, recent, recent),
	}

	var messages []string
	progress := func(p registry.ScanProgress) {
		messages = append(messages, p.Message)
	}

	s := newTestScanner(mock)
	s.Scan(context.Background(), defaultCfg(), progress)

	if len(messages) < 2 {
		t.Errorf("expected at least 2 progress messages, got %d", len(messages))
	}
}

func TestLastActivityTimePrefersPull(t *testing.T) {
	pushed := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	pulled := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	img := makeImage("sha256:x", nil, 100, pushed, pulled)
	got := lastActivityTime(img)
	if got == nil || !got.Equal(pulled) {
		t.Errorf("lastActivityTime should prefer pull time, got %v", got)
	}
}

func TestLastActivityTimeFallsToPush(t *testing.T) {
	pushed := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	img := makeImage("sha256:y", nil, 100, pushed, time.Time{})
	got := lastActivityTime(img)
	if got == nil || !got.Equal(pushed) {
		t.Errorf("lastActivityTime should fall back to push time, got %v", got)
	}
}

func TestScanCostEstimate(t *testing.T) {
	mock := newMockClient()
	mock.repos = []ecrtypes.Repository{makeRepo("myapp")}
	// 1 GB untagged image
	mock.images["myapp"] = []ecrtypes.ImageDetail{
		makeImage("sha256:cost", nil, oneGB, recent, recent),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	untagged := findByID(result.Findings, registry.FindingUntaggedImage)
	if len(untagged) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(untagged))
	}
	// ECR cost: $0.10/GB/month
	if untagged[0].EstimatedMonthlyWaste < 0.09 || untagged[0].EstimatedMonthlyWaste > 0.11 {
		t.Errorf("cost = $%.4f, want ~$0.10", untagged[0].EstimatedMonthlyWaste)
	}
}

func TestDerefNil(t *testing.T) {
	if got := deref(nil); got != "" {
		t.Errorf("deref(nil) = %q, want empty", got)
	}
	s := "hello"
	if got := deref(&s); got != "hello" {
		t.Errorf("deref(&hello) = %q, want hello", got)
	}
}

func TestDerefInt64Nil(t *testing.T) {
	if got := derefInt64(nil); got != 0 {
		t.Errorf("derefInt64(nil) = %d, want 0", got)
	}
	v := int64(42)
	if got := derefInt64(&v); got != 42 {
		t.Errorf("derefInt64(&42) = %d, want 42", got)
	}
}

func TestLastActivityTimeNilBothTimes(t *testing.T) {
	img := ecrtypes.ImageDetail{}
	got := lastActivityTime(img)
	if got != nil {
		t.Errorf("lastActivityTime with no times should return nil, got %v", got)
	}
}

// findByID filters findings by FindingID.
func findByID(findings []registry.Finding, id registry.FindingID) []registry.Finding {
	var out []registry.Finding
	for _, f := range findings {
		if f.ID == id {
			out = append(out, f)
		}
	}
	return out
}
