# Changelog

All notable changes to ECRSpectre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Cloud-agnostic registry types and scanner interface
- Configuration via `.ecrspectre.yaml` with `ecrspectre init` generator
- IAM policy generator for minimal read-only ECR permissions
- Analyzer with minimum cost filtering and summary aggregation
- 4 output formats: text (terminal table), JSON (`spectre/v1` envelope), SARIF (v2.1.0), SpectreHub
- Storage pricing for AWS ECR and GCP Artifact Registry
- 7 finding types: UNTAGGED_IMAGE, STALE_IMAGE, LARGE_IMAGE, NO_LIFECYCLE_POLICY, VULNERABLE_IMAGE, UNUSED_REPO, MULTI_ARCH_BLOAT
