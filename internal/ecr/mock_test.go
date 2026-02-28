package ecr

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// mockECRClient implements ECRAPI for testing.
type mockECRClient struct {
	repos          []ecrtypes.Repository
	images         map[string][]ecrtypes.ImageDetail
	lifecycleRepos map[string]bool // repos with lifecycle policy
	scanFindings   map[string]*ecr.DescribeImageScanFindingsOutput
	descRepoErr    error
	descImagesErr  map[string]error
	lifecycleErr   map[string]error
}

func newMockClient() *mockECRClient {
	return &mockECRClient{
		images:         make(map[string][]ecrtypes.ImageDetail),
		lifecycleRepos: make(map[string]bool),
		scanFindings:   make(map[string]*ecr.DescribeImageScanFindingsOutput),
		descImagesErr:  make(map[string]error),
		lifecycleErr:   make(map[string]error),
	}
}

func (m *mockECRClient) DescribeRepositories(_ context.Context, _ *ecr.DescribeRepositoriesInput, _ ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	if m.descRepoErr != nil {
		return nil, m.descRepoErr
	}
	return &ecr.DescribeRepositoriesOutput{Repositories: m.repos}, nil
}

func (m *mockECRClient) DescribeImages(_ context.Context, input *ecr.DescribeImagesInput, _ ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	repo := aws.ToString(input.RepositoryName)
	if err, ok := m.descImagesErr[repo]; ok {
		return nil, err
	}
	return &ecr.DescribeImagesOutput{ImageDetails: m.images[repo]}, nil
}

func (m *mockECRClient) GetLifecyclePolicy(_ context.Context, input *ecr.GetLifecyclePolicyInput, _ ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error) {
	repo := aws.ToString(input.RepositoryName)
	if err, ok := m.lifecycleErr[repo]; ok {
		return nil, err
	}
	if m.lifecycleRepos[repo] {
		return &ecr.GetLifecyclePolicyOutput{
			LifecyclePolicyText: aws.String(`{"rules":[]}`),
		}, nil
	}
	return nil, &ecrtypes.LifecyclePolicyNotFoundException{
		Message: aws.String("lifecycle policy not found"),
	}
}

func (m *mockECRClient) DescribeImageScanFindings(_ context.Context, input *ecr.DescribeImageScanFindingsInput, _ ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
	key := aws.ToString(input.RepositoryName) + "@" + aws.ToString(input.ImageId.ImageDigest)
	if out, ok := m.scanFindings[key]; ok {
		return out, nil
	}
	return &ecr.DescribeImageScanFindingsOutput{}, nil
}

// Test helper to create an image detail.
func makeImage(digest string, tags []string, sizeBytes int64, pushedAt, lastPull time.Time) ecrtypes.ImageDetail {
	img := ecrtypes.ImageDetail{
		ImageDigest:      aws.String(digest),
		ImageSizeInBytes: aws.Int64(sizeBytes),
		ImagePushedAt:    aws.Time(pushedAt),
		ImageTags:        tags,
	}
	if !lastPull.IsZero() {
		img.LastRecordedPullTime = aws.Time(lastPull)
	}
	return img
}

func makeRepo(name string) ecrtypes.Repository {
	return ecrtypes.Repository{
		RepositoryName: aws.String(name),
	}
}
