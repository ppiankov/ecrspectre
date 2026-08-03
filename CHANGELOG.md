# Changelog

All notable changes to ECRSpectre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Windows CI build leg and Windows quick-start documentation
- Local verify gate (`.verify`, `make verify`) running vet, lint, and race tests

### Changed
- Explicit CLI flags now take precedence over config via `Flags().Changed()`; the `timeout` config key is now wired through to the scan
- Duplicated scanner finding-builders and command helpers hoisted into shared packages

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
