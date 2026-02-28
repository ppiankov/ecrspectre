package artifactregistry

import (
	"context"
	"errors"
	"testing"
	"time"

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

func newTestScanner(client ARAPI) *ARScanner {
	s := NewARScanner(client, "my-project", []string{"us-central1"})
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
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/myapp", "us-central1", "myapp"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/myapp"] = []DockerImage{
		makeImage("us-central1-docker.pkg.dev/my-project/myapp/img@sha256:aaa", nil, halfGB, recent, ""),
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
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/myapp", "us-central1", "myapp"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/myapp"] = []DockerImage{
		makeImage("us-central1-docker.pkg.dev/my-project/myapp/img@sha256:bbb", []string{"v1.0"}, halfGB, stale120, ""),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	stale := findByID(result.Findings, registry.FindingStaleImage)
	if len(stale) != 1 {
		t.Fatalf("expected 1 STALE_IMAGE, got %d", len(stale))
	}
	if stale[0].Metadata["note"] == nil {
		t.Error("stale finding should include note about upload-based staleness")
	}
}

func TestScanRecentImageNotStale(t *testing.T) {
	mock := newMockClient()
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/myapp", "us-central1", "myapp"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/myapp"] = []DockerImage{
		makeImage("us-central1-docker.pkg.dev/my-project/myapp/img@sha256:ccc", []string{"latest"}, halfGB, recent, ""),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	stale := findByID(result.Findings, registry.FindingStaleImage)
	if len(stale) != 0 {
		t.Errorf("expected 0 STALE_IMAGE for recent image, got %d", len(stale))
	}
}

func TestScanLargeImage(t *testing.T) {
	mock := newMockClient()
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/myapp", "us-central1", "myapp"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/myapp"] = []DockerImage{
		makeImage("us-central1-docker.pkg.dev/my-project/myapp/img@sha256:ddd", []string{"latest"}, twoGB, recent, ""),
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
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/myapp", "us-central1", "myapp"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/myapp"] = []DockerImage{
		makeImage("us-central1-docker.pkg.dev/my-project/myapp/img@sha256:eee", []string{"latest"}, hundredMB, recent, ""),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	large := findByID(result.Findings, registry.FindingLargeImage)
	if len(large) != 0 {
		t.Errorf("expected 0 LARGE_IMAGE, got %d", len(large))
	}
}

func TestScanEmptyRepo(t *testing.T) {
	mock := newMockClient()
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/empty-repo", "us-central1", "empty-repo"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/empty-repo"] = []DockerImage{}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	unused := findByID(result.Findings, registry.FindingUnusedRepo)
	if len(unused) != 1 {
		t.Fatalf("expected 1 UNUSED_REPO, got %d", len(unused))
	}
}

func TestScanAllStaleRepo(t *testing.T) {
	mock := newMockClient()
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/old-repo", "us-central1", "old-repo"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/old-repo"] = []DockerImage{
		makeImage("uri1", []string{"v1"}, halfGB, stale200, ""),
		makeImage("uri2", []string{"v2"}, halfGB, stale200, ""),
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
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/excluded", "us-central1", "excluded"),
		makeRepo("projects/my-project/locations/us-central1/repositories/included", "us-central1", "included"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/included"] = []DockerImage{
		makeImage("uri", []string{"latest"}, hundredMB, recent, ""),
	}

	cfg := defaultCfg()
	cfg.Exclude.ResourceIDs = map[string]bool{"excluded": true}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), cfg, nil)

	for _, f := range result.Findings {
		if f.ResourceID == "excluded" {
			t.Error("excluded repo should not have findings")
		}
	}
}

func TestScanListReposError(t *testing.T) {
	mock := newMockClient()
	mock.listRepoErr["my-project/us-central1"] = errors.New("permission denied")

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(result.Errors) == 0 {
		t.Error("expected error in result.Errors")
	}
}

func TestScanListImagesError(t *testing.T) {
	mock := newMockClient()
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/broken", "us-central1", "broken"),
	}
	mock.listImagesErr["projects/my-project/locations/us-central1/repositories/broken"] = errors.New("timeout")

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if len(result.Errors) == 0 {
		t.Error("expected error in result.Errors")
	}
}

func TestScanMultiArchBloat(t *testing.T) {
	mock := newMockClient()
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/multiarch", "us-central1", "multiarch"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/multiarch"] = []DockerImage{
		makeImage("uri-multi", []string{"latest"}, twoGB, stale200, "application/vnd.docker.distribution.manifest.list.v2+json"),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	bloat := findByID(result.Findings, registry.FindingMultiArchBloat)
	if len(bloat) != 1 {
		t.Fatalf("expected 1 MULTI_ARCH_BLOAT, got %d", len(bloat))
	}
}

func TestScanResourcesScannedCount(t *testing.T) {
	mock := newMockClient()
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/r1", "us-central1", "r1"),
		makeRepo("projects/my-project/locations/us-central1/repositories/r2", "us-central1", "r2"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/r1"] = []DockerImage{
		makeImage("uri1a", []string{"v1"}, hundredMB, recent, ""),
		makeImage("uri1b", []string{"v2"}, hundredMB, recent, ""),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/r2"] = []DockerImage{
		makeImage("uri2a", []string{"v1"}, hundredMB, recent, ""),
	}

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
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/myapp", "us-central1", "myapp"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/myapp"] = []DockerImage{
		makeImage("uri", []string{"latest"}, hundredMB, recent, ""),
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

func TestScanMultipleLocations(t *testing.T) {
	mock := newMockClient()
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/r1", "us-central1", "r1"),
	}
	mock.repos["my-project/europe-west1"] = []Repository{
		makeRepo("projects/my-project/locations/europe-west1/repositories/r2", "europe-west1", "r2"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/r1"] = []DockerImage{
		makeImage("uri1", []string{"v1"}, hundredMB, recent, ""),
	}
	mock.images["projects/my-project/locations/europe-west1/repositories/r2"] = []DockerImage{
		makeImage("uri2", []string{"v1"}, hundredMB, recent, ""),
	}

	s := NewARScanner(mock, "my-project", []string{"us-central1", "europe-west1"})
	s.now = now
	result := s.Scan(context.Background(), defaultCfg(), nil)

	if result.RepositoriesScanned != 2 {
		t.Errorf("RepositoriesScanned = %d, want 2", result.RepositoriesScanned)
	}
	if result.ResourcesScanned != 2 {
		t.Errorf("ResourcesScanned = %d, want 2", result.ResourcesScanned)
	}
}

func TestNoLifecyclePolicyNotEmittedForGCP(t *testing.T) {
	mock := newMockClient()
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/myapp", "us-central1", "myapp"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/myapp"] = []DockerImage{
		makeImage("uri", []string{"latest"}, hundredMB, recent, ""),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	nolp := findByID(result.Findings, registry.FindingNoLifecyclePolicy)
	if len(nolp) != 0 {
		t.Error("NO_LIFECYCLE_POLICY should not be emitted for GCP scans")
	}
}

func TestVulnerableImageNotEmittedForGCP(t *testing.T) {
	mock := newMockClient()
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/myapp", "us-central1", "myapp"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/myapp"] = []DockerImage{
		makeImage("uri", []string{"latest"}, hundredMB, recent, ""),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	vuln := findByID(result.Findings, registry.FindingVulnerableImage)
	if len(vuln) != 0 {
		t.Error("VULNERABLE_IMAGE should not be emitted for GCP scans")
	}
}

func TestScanCostEstimate(t *testing.T) {
	mock := newMockClient()
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/myapp", "us-central1", "myapp"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/myapp"] = []DockerImage{
		makeImage("uri", nil, oneGB, recent, ""),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	untagged := findByID(result.Findings, registry.FindingUntaggedImage)
	if len(untagged) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(untagged))
	}
	// AR cost: $0.10/GB/month
	if untagged[0].EstimatedMonthlyWaste < 0.09 || untagged[0].EstimatedMonthlyWaste > 0.11 {
		t.Errorf("cost = $%.4f, want ~$0.10", untagged[0].EstimatedMonthlyWaste)
	}
}

func TestScanImageEmptyURI(t *testing.T) {
	mock := newMockClient()
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/myapp", "us-central1", "myapp"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/myapp"] = []DockerImage{
		{
			Name:       "projects/p/locations/l/repositories/r/dockerImages/img",
			URI:        "", // empty URI
			Tags:       nil,
			SizeBytes:  halfGB,
			UploadTime: recent,
		},
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	untagged := findByID(result.Findings, registry.FindingUntaggedImage)
	if len(untagged) != 1 {
		t.Fatalf("expected 1 UNTAGGED_IMAGE, got %d", len(untagged))
	}
	// Should fall back to Name when URI is empty
	if untagged[0].ResourceID != "projects/p/locations/l/repositories/r/dockerImages/img" {
		t.Errorf("ResourceID = %q, want Name fallback", untagged[0].ResourceID)
	}
}

func TestScanMultiArchNotStaleNotReported(t *testing.T) {
	mock := newMockClient()
	mock.repos["my-project/us-central1"] = []Repository{
		makeRepo("projects/my-project/locations/us-central1/repositories/multiarch", "us-central1", "multiarch"),
	}
	mock.images["projects/my-project/locations/us-central1/repositories/multiarch"] = []DockerImage{
		makeImage("uri-multi", []string{"latest"}, twoGB, recent, "application/vnd.oci.image.index.v1+json"),
	}

	s := newTestScanner(mock)
	result := s.Scan(context.Background(), defaultCfg(), nil)

	bloat := findByID(result.Findings, registry.FindingMultiArchBloat)
	if len(bloat) != 0 {
		t.Error("recent multi-arch image should not be flagged as bloat")
	}
}

func findByID(findings []registry.Finding, id registry.FindingID) []registry.Finding {
	var out []registry.Finding
	for _, f := range findings {
		if f.ID == id {
			out = append(out, f)
		}
	}
	return out
}
