package registry

import "context"

// RegistryScanner is the interface for cloud-specific container registry scanners.
// Scan returns a *ScanResult whose Errors field carries per-repository failures;
// implementations do not return a separate error (WO-11: signature aligned to
// the real ecr/artifactregistry implementations so this interface is satisfied).
type RegistryScanner interface {
	Scan(ctx context.Context, cfg ScanConfig, progress func(ScanProgress)) *ScanResult
}
