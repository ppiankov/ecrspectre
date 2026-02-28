package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var initFlags struct {
	force bool
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate sample config and IAM policy",
	Long:  `Creates a sample .ecrspectre.yaml config file and IAM/GCP policy files for read-only access.`,
	RunE:  runInit,
}

func init() {
	initCmd.Flags().BoolVar(&initFlags.force, "force", false, "Overwrite existing files")
}

func runInit(_ *cobra.Command, _ []string) error {
	configPath := ".ecrspectre.yaml"
	policyPath := "ecrspectre-policy.json"

	wrote := 0

	if err := writeIfNotExists(configPath, sampleConfig, initFlags.force); err != nil {
		return err
	}
	wrote++

	if err := writeIfNotExists(policyPath, sampleIAMPolicy, initFlags.force); err != nil {
		return err
	}
	wrote++

	if wrote > 0 {
		fmt.Printf("Created %s and %s\n", configPath, policyPath)
		fmt.Println("\nNext steps:")
		fmt.Println("  1. Edit .ecrspectre.yaml to set provider (aws or gcp) and regions")
		fmt.Println("  2. For AWS: apply ecrspectre-policy.json to your IAM role/user")
		fmt.Println("  3. For GCP: ensure Artifact Registry Reader role on your service account")
		fmt.Println("  4. Run: ecrspectre aws  OR  ecrspectre gcp --project=PROJECT_ID")
	}
	return nil
}

func writeIfNotExists(path, content string, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			fmt.Printf("Skipping %s (already exists, use --force to overwrite)\n", path)
			return nil
		}
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}

	return os.WriteFile(path, []byte(content), 0o644)
}

const sampleConfig = `# ecrspectre configuration
# See: https://github.com/ppiankov/ecrspectre

# Cloud provider: aws or gcp
# provider: aws

# AWS profile (or set AWS_PROFILE env var)
# profile: default

# GCP project ID (required for gcp provider)
# project: my-project-id

# Regions to scan (default: all enabled regions)
# regions:
#   - us-east-1
#   - us-west-2

# Age threshold for stale images (days since last pull for ECR, since push for GCP)
stale_days: 90

# Maximum acceptable image size (MB). Images above this are flagged.
max_size_mb: 1024

# Minimum monthly cost to report ($)
min_monthly_cost: 0.10

# Output format: text, json, sarif, or spectrehub
format: text

# Scan timeout
timeout: 10m

# Resources to exclude from scanning
# exclude:
#   resource_ids:
#     - myapp/production
#   tags:
#     - "env=production"
`

const sampleIAMPolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EcrSpectreReadOnly",
      "Effect": "Allow",
      "Action": [
        "ecr:DescribeRepositories",
        "ecr:DescribeImages",
        "ecr:ListImages",
        "ecr:BatchGetImage",
        "ecr:GetLifecyclePolicy",
        "ecr:DescribeImageScanFindings",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
`
