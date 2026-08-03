# ecrspectre

[![CI](https://github.com/ppiankov/ecrspectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/ecrspectre/actions/workflows/ci.yml)
[![ANCC](https://img.shields.io/badge/ANCC-compliant-brightgreen)](https://ancc.dev)

**ecrspectre** — Container registry waste auditor for ECR and Artifact Registry. Part of [SpectreHub](https://spectrehub.dev).

## What it is

- Scans AWS ECR and GCP Artifact Registry for stale, untagged, and bloated images
- Checks pull timestamps, tag status, image size, and lifecycle policies
- Estimates monthly storage cost per finding
- Surfaces vulnerability scan data from ECR's built-in scanner
- Outputs text, JSON, SARIF, and SpectreHub formats

## What it is NOT

- Not a real-time monitor — point-in-time scanner
- Not a remediation tool — reports only, never deletes images
- Not a security scanner — surfaces existing ECR scan data
- Not a CI image builder — audits what exists

## Quick start

### Homebrew

```sh
brew tap ppiankov/tap
brew install ecrspectre
```

### Windows

Download the latest binary from [Releases](https://github.com/ppiankov/ecrspectre/releases), or install with Go:

```sh
go install github.com/ppiankov/ecrspectre/cmd/ecrspectre@latest
```

### From source

```sh
git clone https://github.com/ppiankov/ecrspectre.git
cd ecrspectre
make build
```

### Usage

```sh
ecrspectre aws --region us-east-1 --format json
```

## CLI commands

| Command | Description |
|---------|-------------|
| `ecrspectre aws` | Audit AWS ECR repositories for waste |
| `ecrspectre gcp` | Audit GCP Artifact Registry repositories for waste |
| `ecrspectre init` | Generate IAM policy and config file |
| `ecrspectre version` | Print version |

## SpectreHub integration

ecrspectre feeds container registry waste findings into [SpectreHub](https://spectrehub.dev) for unified visibility across your infrastructure.

```sh
spectrehub collect --tool ecrspectre
```

## Safety

ecrspectre operates in **read-only mode**. It inspects and reports — never modifies, deletes, or alters your images.

## Documentation

| Document | Contents |
|----------|----------|
| [CLI Reference](docs/cli-reference.md) | Full command reference, flags, and configuration |

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Obsta Labs](https://obstalabs.dev)
