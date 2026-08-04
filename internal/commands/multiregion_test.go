package commands

import (
	"testing"

	"github.com/ppiankov/ecrspectre/internal/registry"
)

// WO-16: mergeScanResults aggregates findings, errors, and counts across regions.
func TestMergeScanResults(t *testing.T) {
	dst := &registry.ScanResult{
		Findings:            []registry.Finding{{ID: "A"}},
		Errors:              []string{"err1"},
		ResourcesScanned:    10,
		RepositoriesScanned: 5,
	}
	src := &registry.ScanResult{
		Findings:            []registry.Finding{{ID: "B"}, {ID: "C"}},
		Errors:              []string{"err2"},
		ResourcesScanned:    20,
		RepositoriesScanned: 8,
	}

	mergeScanResults(dst, src)

	if len(dst.Findings) != 3 {
		t.Errorf("findings: got %d, want 3", len(dst.Findings))
	}
	if len(dst.Errors) != 2 {
		t.Errorf("errors: got %d, want 2", len(dst.Errors))
	}
	if dst.ResourcesScanned != 30 {
		t.Errorf("resources: got %d, want 30", dst.ResourcesScanned)
	}
	if dst.RepositoriesScanned != 13 {
		t.Errorf("repos: got %d, want 13", dst.RepositoriesScanned)
	}
}
