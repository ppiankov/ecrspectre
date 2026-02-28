package registry

import "context"

// RegistryScanner is the interface for cloud-specific container registry scanners.
type RegistryScanner interface {
	Scan(ctx context.Context, cfg ScanConfig, progress func(ScanProgress)) (*ScanResult, error)
}
