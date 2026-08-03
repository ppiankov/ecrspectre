package registry

import "context"

// WO-11: interface signature aligned to the real ecr/artifactregistry
// implementations. Scan returns *ScanResult (errors flow via ScanResult.Errors,
// not a separate error return) so both scanners genuinely satisfy this interface.
type RegistryScanner interface {
	Scan(ctx context.Context, cfg ScanConfig, progress func(ScanProgress)) *ScanResult
}
