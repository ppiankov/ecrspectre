## Philosophy

*Principiis obsta* -- resist the beginnings.

Container registries grow unbounded. Every CI build pushes an image, every deployment creates a tag, and nobody cleans up. ECRSpectre surfaces stale, untagged, and oversized images early -- in scheduled audits, in CI, in cost reviews -- so they can be addressed before storage costs compound.

The tool presents evidence and lets humans decide. It does not auto-delete images, does not guess intent, and does not use ML where deterministic checks suffice.


## Installation

```bash
# From source
git clone https://github.com/ppiankov/ecrspectre.git
cd ecrspectre && make build
```


## Configuration

ECRSpectre reads `.ecrspectre.yaml` from the current directory:

```yaml
provider: aws
regions:
  - us-east-1
  - eu-west-1
stale_days: 90
max_size_mb: 1024
min_monthly_cost: 0.10
format: text
```

Generate a sample config with `ecrspectre init`.


## Output formats

**Text** (default): Human-readable table with severity, resource, region, waste, and message.

**JSON** (`--format json`): `spectre/v1` envelope with findings and summary.

**SARIF** (`--format sarif`): SARIF v2.1.0 for GitHub Security tab integration.

**SpectreHub** (`--format spectrehub`): `spectre/v1` envelope for SpectreHub ingestion.


## Architecture

```
ecrspectre/
├── cmd/ecrspectre/main.go         # Entry point (LDFLAGS)
├── internal/
│   ├── commands/                  # Cobra CLI: aws, gcp, init, version
│   ├── registry/                  # Cloud-agnostic types + scanner interface
│   ├── ecr/                       # AWS ECR scanner
│   ├── artifactregistry/          # GCP Artifact Registry scanner
│   ├── pricing/                   # Storage pricing data
│   ├── analyzer/                  # Filter by min cost, compute summary
│   ├── config/                    # YAML config loader
│   ├── logging/                   # slog setup
│   └── report/                    # Text, JSON, SARIF, SpectreHub reporters
├── Makefile
└── go.mod
```

Key design decisions:

- `cmd/ecrspectre/main.go` is minimal -- a single `Execute()` call with LDFLAGS version injection.
- All logic lives in `internal/` to prevent external import.
- Cloud-agnostic types in `registry/` with provider-specific scanners in `ecr/` and `artifactregistry/`.
- Two subcommands (`aws`, `gcp`) instead of one `scan` -- each cloud has different API surfaces and authentication.
- GCP stale detection uses upload age (no pull timestamp available in Artifact Registry API).
- ECR-only findings (NO_LIFECYCLE_POLICY, VULNERABLE_IMAGE) are not emitted for GCP scans.


## Project Status

**Status: Alpha** · Pre-release

| Milestone | Status |
|-----------|--------|
| Cloud-agnostic types and scanner interface | Complete |
| Config, analyzer, pricing, logging | Complete |
| 4 output formats (text, JSON, SARIF, SpectreHub) | Complete |
| AWS ECR scanner | Planned |
| GCP Artifact Registry scanner | Planned |
| CI/CD pipeline | Planned |
| Homebrew + Docker distribution | Planned |
| Test coverage >85% | In progress |


## Known limitations

- **GCP stale detection is approximate.** Artifact Registry API has no pull timestamp, so "stale" is measured by upload age only.
- **ECR-only findings.** Lifecycle policy and vulnerability checks are not available for GCP Artifact Registry.
- **Approximate pricing.** Cost estimates use published storage rates ($0.10/GB/month for ECR), not your actual pricing.
- **No cross-account support.** Scans a single AWS account or GCP project at a time.

