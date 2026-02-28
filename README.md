# ECRSpectre

[![CI](https://github.com/ppiankov/ecrspectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/ecrspectre/actions/workflows/ci.yml)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Container registry waste auditor. Finds stale, untagged, and bloated images in AWS ECR and GCP Artifact Registry.

Part of the [Spectre family](https://spectrehub.dev) of infrastructure cleanup tools.

## What it is

ECRSpectre scans container registries for images that accumulate storage costs silently. It checks pull timestamps, tag status, image size, lifecycle policies, and vulnerability scan data to identify waste. Each finding includes an estimated monthly storage cost so you can prioritize cleanup by dollar impact.

## What it is NOT

- Not a real-time monitoring tool. ECRSpectre is a point-in-time scanner, not a daemon.
- Not a remediation tool. It reports waste and lets you decide what to do.
- Not a security scanner. Vulnerability findings are surfaced from ECR's built-in scan data, not independent analysis.
- Not a billing replacement. Cost estimates use published storage rates, not your actual negotiated pricing.
- Not a CI image builder. It audits what exists, not what should be built.

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

## Quick start

```bash
# Scan AWS ECR (all regions)
ecrspectre aws

# Scan specific regions
ecrspectre aws --regions us-east-1,eu-west-1

# Scan GCP Artifact Registry
ecrspectre gcp --project my-project-id

# JSON output for automation
ecrspectre aws --format json --output report.json

# SARIF output for GitHub Security tab
ecrspectre aws --format sarif --output results.sarif

# Generate config and IAM policy
ecrspectre init
```

Requires valid cloud credentials (AWS or GCP).

## What it audits

| Finding | Signal | Severity | AWS ECR | GCP AR |
|---------|--------|----------|---------|--------|
| `UNTAGGED_IMAGE` | No tags on image | high | yes | yes |
| `STALE_IMAGE` | No pull > 90d (ECR) / no upload > 90d (GCP) | high | yes | partial |
| `LARGE_IMAGE` | Image > 1GB | medium | yes | yes |
| `NO_LIFECYCLE_POLICY` | ECR repo without expiration rules | medium | yes | no |
| `VULNERABLE_IMAGE` | CVE findings in scan data | critical | yes | no |
| `UNUSED_REPO` | Repo with zero images or all stale | low | yes | yes |
| `MULTI_ARCH_BLOAT` | Platform variants nobody pulls | low | yes | yes |

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

## License

MIT License -- see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and pull requests welcome.

Part of the [Spectre family](https://spectrehub.dev).
