package ecr

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// ECRAPI defines the subset of the ECR API used by the scanner.
type ECRAPI interface {
	DescribeRepositories(ctx context.Context, input *ecr.DescribeRepositoriesInput, opts ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	DescribeImages(ctx context.Context, input *ecr.DescribeImagesInput, opts ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
	GetLifecyclePolicy(ctx context.Context, input *ecr.GetLifecyclePolicyInput, opts ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error)
	DescribeImageScanFindings(ctx context.Context, input *ecr.DescribeImageScanFindingsInput, opts ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error)
}

// Client wraps the AWS SDK configuration for creating ECR service clients.
type Client struct {
	cfg aws.Config
}

// NewClient creates a new AWS client using the specified profile and region.
func NewClient(ctx context.Context, profile, region string) (*Client, error) {
	var opts []func(*awsconfig.LoadOptions) error

	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	return &Client{cfg: cfg}, nil
}

// Config returns the underlying AWS config.
func (c *Client) Config() aws.Config {
	return c.cfg
}

// NewECRClient creates an ECR service client from the stored config.
func (c *Client) NewECRClient() ECRAPI {
	return ecr.NewFromConfig(c.cfg)
}

// Region returns the configured region.
func (c *Client) Region() string {
	return c.cfg.Region
}

// ListRepositories returns all ECR repositories using pagination.
func ListRepositories(ctx context.Context, client ECRAPI) ([]ecrtypes.Repository, error) {
	var repos []ecrtypes.Repository
	input := &ecr.DescribeRepositoriesInput{}

	for {
		out, err := client.DescribeRepositories(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("describe repositories: %w", err)
		}
		repos = append(repos, out.Repositories...)
		if out.NextToken == nil {
			break
		}
		input.NextToken = out.NextToken
	}

	slog.Debug("Listed ECR repositories", "count", len(repos))
	return repos, nil
}

// ListImages returns all image details for a given repository using pagination.
func ListImages(ctx context.Context, client ECRAPI, repoName string) ([]ecrtypes.ImageDetail, error) {
	var images []ecrtypes.ImageDetail
	input := &ecr.DescribeImagesInput{
		RepositoryName: aws.String(repoName),
	}

	for {
		out, err := client.DescribeImages(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("describe images for %s: %w", repoName, err)
		}
		images = append(images, out.ImageDetails...)
		if out.NextToken == nil {
			break
		}
		input.NextToken = out.NextToken
	}

	return images, nil
}

// HasLifecyclePolicy checks if a repository has a lifecycle policy configured.
func HasLifecyclePolicy(ctx context.Context, client ECRAPI, repoName string) (bool, error) {
	_, err := client.GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{
		RepositoryName: aws.String(repoName),
	})
	if err != nil {
		var notFound *ecrtypes.LifecyclePolicyNotFoundException
		if errors.As(err, &notFound) {
			return false, nil
		}
		return false, fmt.Errorf("get lifecycle policy for %s: %w", repoName, err)
	}
	return true, nil
}
