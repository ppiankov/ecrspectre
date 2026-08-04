# Changelog

All notable changes to ECRSpectre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-08-04

### Added
- `--all-regions`: scan all enabled AWS regions in one invocation (requires `ec2:DescribeRegions`)
- Timeout warning when a multi-region sequential scan may exceed the configured timeout

### Changed
- Added `github.com/aws/aws-sdk-go-v2/service/ec2` dependency for region enumeration

## [0.3.0] - 2026-08-03

### Added
- Retention engine: configurable keep rules (protected tags, keep-latest-N optionally per semver major, keep-last-per-branch, minimum age) via the `retention:` config section
- `--format policy`: emits a recommended ECR lifecycle policy (AWS JSON) with per-repository apply commands — read-only, never applies it
- `--format delete-script`: prints dry-run `aws ecr batch-delete-image` commands for stale/untagged images not protected by a retention rule — never executes
- Scan errors are now surfaced in the policy and delete-script outputs so a throttled/partial scan is never mistaken for complete

## [0.2.0] - 2026-08-03

### Added
- Windows CI build leg and Windows quick-start documentation
- Local verify gate (`.verify`, `make verify`) running vet, lint, and race tests

### Changed
- Explicit CLI flags now take precedence over config via `Flags().Changed()`; the `timeout` config key is now wired through to the scan
- Duplicated scanner finding-builders and command helpers hoisted into shared packages
- SpectreHub references now link to https://spectrehub.dev

### Removed
- Dead Go Report Card badge from the README

### Fixed
- `RegistryScanner` interface signature aligned with its implementations

## [0.1.0] - 2026-02-28

### Added

- Cloud-agnostic registry types and scanner interface
- Configuration via `.ecrspectre.yaml` with `ecrspectre init` generator
- IAM policy generator for minimal read-only ECR permissions
- Analyzer with minimum cost filtering and summary aggregation
- 4 output formats: text (terminal table), JSON (`spectre/v1` envelope), SARIF (v2.1.0), SpectreHub
- Storage pricing for AWS ECR and GCP Artifact Registry
- 7 finding types: UNTAGGED_IMAGE, STALE_IMAGE, LARGE_IMAGE, NO_LIFECYCLE_POLICY, VULNERABLE_IMAGE, UNUSED_REPO, MULTI_ARCH_BLOAT
