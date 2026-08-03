# ecrspectre

Container registry waste auditor for AWS ECR and GCP Artifact Registry.

## Install

```
brew install ppiankov/tap/ecrspectre
```

Or via Go:

```
go install github.com/ppiankov/ecrspectre/cmd/ecrspectre@latest
```

## Commands

ecrspectre audits one cloud per invocation through two subcommands.

### ecrspectre aws

Audits AWS ECR repositories for stale, untagged, oversized, and (optionally) vulnerable images.

**Flags:**
- `--region` — AWS region (default: from AWS config / `AWS_REGION`)
- `--profile` — AWS profile name
- `--stale-days` — image age threshold in days since last pull (default 90)
- `--max-size` — flag images larger than this in MB (default 1024)
- `--min-monthly-cost` — minimum estimated monthly waste to report in $ (default 0.10)
- `--format json` — output as JSON (`spectre/v1` envelope)
- `--format sarif` — SARIF v2.1.0 for CI integration
- `--format spectrehub` — SpectreHub aggregator format
- `--format text` — human-readable table (default)
- `--output`, `-o` — write the report to a file instead of stdout
- `--include-scan` — include ECR vulnerability scan data when available
- `--no-progress` — suppress progress output to stderr
- `--timeout` — scan timeout (default 10m)
- `--exclude-tags` — exclude resources by tag (`Key=Value`, comma-separated)

### ecrspectre gcp

Audits GCP Artifact Registry repositories. Artifact Registry exposes no pull timestamp, so stale detection is based on upload age only; lifecycle-policy and vulnerability findings are ECR-only.

**Flags:** `--project` (required), `--locations`, plus the shared `--stale-days`, `--max-size`, `--min-monthly-cost`, `--format`, `--output`, `--no-progress`, `--timeout`, and `--exclude-tags` flags above.

**JSON output:**
```json
{
  "$schema": "spectre/v1",
  "tool": "ecrspectre",
  "version": "1.0.0",
  "timestamp": "2026-08-02T00:00:00Z",
  "target": { "type": "ecr", "uri_hash": "sha256:..." },
  "config": {
    "provider": "aws",
    "regions": ["us-east-1"],
    "stale_days": 90,
    "max_size_mb": 1024,
    "min_monthly_cost": 0.1
  },
  "findings": [
    {
      "id": "STALE_IMAGE",
      "severity": "high",
      "resource_type": "image",
      "resource_id": "app@sha256:abc123",
      "region": "us-east-1",
      "message": "Not pulled in 120 days (450 MB)",
      "estimated_monthly_waste": 0.05,
      "metadata": { "days_stale": 120, "size_bytes": 471859200 }
    }
  ],
  "summary": {
    "total_resources_scanned": 1,
    "total_findings": 1,
    "total_monthly_waste": 0.05,
    "by_severity": { "high": 1 },
    "by_resource_type": { "image": 1 },
    "repositories_scanned": 1
  }
}
```

**Exit codes:**
- 0: scan completed (with or without findings)
- 1: scan failed (credentials, permissions, or configuration error)

### ecrspectre init

Generate a sample `.ecrspectre.yaml` config and a read-only IAM policy file.

## Handoffs

- Output: `spectre/v1` JSON. Next: SpectreHub for aggregation across scanners.
- Output: SARIF. Next: CI security gates.
- Refused questions: how to fix findings, whether to remediate, risk acceptance decisions.

## What this does NOT do

- Does not remediate or modify registries — every scan is read-only.
- Does not store findings or manage a findings database.
- Does not replace dedicated registry monitoring — point-in-time audit only.

## Failure Modes

- Client initialization failure (credentials, permissions): exit code 1. No findings produced.
- Per-repository errors (throttling, timeouts, access denied on one repo): collected in the report `errors` field; the scan completes with exit 0 and partial findings. Distrust summary completeness when `errors` is non-empty.

## Parsing examples

```bash
ecrspectre aws --format json | jq '.summary'
ecrspectre aws --format json | jq '.findings[] | select(.severity == "high")'
ecrspectre aws --region us-east-1 --format sarif -o report.sarif
```

---

This tool follows the [Agent-Native CLI Convention](https://ancc.dev). Validate with: `ancc validate .`
