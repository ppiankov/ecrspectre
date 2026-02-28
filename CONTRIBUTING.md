# Contributing to ECRSpectre

Thank you for considering contributing. This document outlines the process.

## Getting started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/ecrspectre`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test your changes
6. Commit and push
7. Create a pull request

## Development setup

### Prerequisites

- Go 1.26 or later
- Make
- golangci-lint

### Building

```bash
make build
```

### Running tests

```bash
make test
```

### Linting

```bash
make lint
```

### Code formatting

```bash
make fmt
```

## Project structure

```
ecrspectre/
├── cmd/ecrspectre/          # CLI entry point
├── internal/
│   ├── commands/            # Cobra CLI commands
│   ├── registry/            # Cloud-agnostic types + scanner interface
│   ├── ecr/                 # AWS ECR scanner
│   ├── artifactregistry/    # GCP Artifact Registry scanner
│   ├── pricing/             # Storage pricing data
│   ├── analyzer/            # Finding classification + summary
│   ├── config/              # YAML config loader
│   ├── logging/             # slog setup
│   └── report/              # Output formatters
└── docs/                    # Documentation
```

## Contribution areas

### New finding types

Add support for additional waste patterns:
1. Add the finding ID to `internal/registry/types.go`
2. Implement detection in the relevant scanner
3. Add pricing lookup if needed
4. Write tests
5. Add SARIF rule to `internal/report/sarif.go`

### Report formats

Add new output formats in `internal/report/`:
- HTML reports
- CSV exports
- Slack/webhook notifications

## Coding guidelines

- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Pass `golangci-lint` checks
- Write tests for new code (coverage target: >85%)
- Use interface-based mocking for cloud clients
- Check all errors, wrap with context using `fmt.Errorf`
- Comments explain "why" not "what"

## Commit messages

Format: `type: concise imperative statement`

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`, `ci`, `build`

Examples:
- `feat: add multi-arch bloat detection`
- `fix: handle nil tags in ECR scanner`
- `test: add coverage for GCP stale detection`

## Pull request process

1. Ensure `make test && make lint` pass
2. Update CHANGELOG.md if adding features or fixing bugs
3. Create PR with clear description of what and why
4. Respond to review feedback

## SpectreHub compatibility

When modifying JSON output, ensure compatibility with SpectreHub:
- Maintain `spectre/v1` schema
- Include `tool`, `version`, `timestamp` fields
- Follow Spectre family conventions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
