package artifactregistry

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	ar "cloud.google.com/go/artifactregistry/apiv1"
	arpb "cloud.google.com/go/artifactregistry/apiv1/artifactregistrypb"
	"google.golang.org/api/iterator"
)

// Repository represents a GCP Artifact Registry repository.
type Repository struct {
	Name     string // full resource name
	Location string
	RepoID   string
	Format   string
}

// DockerImage represents a Docker image in Artifact Registry.
type DockerImage struct {
	Name         string // full resource name
	URI          string
	Tags         []string
	SizeBytes    int64
	UploadTime   time.Time
	MediaType    string
	RepositoryID string
}

// ARAPI defines the subset of the Artifact Registry API used by the scanner.
type ARAPI interface {
	ListRepositories(ctx context.Context, project, location string) ([]Repository, error)
	ListDockerImages(ctx context.Context, parent string) ([]DockerImage, error)
	Close() error
}

// Client implements ARAPI using the real GCP SDK.
type Client struct {
	inner   *ar.Client
	project string
}

// NewClient creates a new Artifact Registry client.
func NewClient(ctx context.Context, project string) (*Client, error) {
	c, err := ar.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("create artifact registry client: %w", err)
	}
	return &Client{inner: c, project: project}, nil
}

// Close releases client resources.
func (c *Client) Close() error {
	return c.inner.Close()
}

// ListRepositories returns all Docker-format repositories in a given location.
func (c *Client) ListRepositories(ctx context.Context, project, location string) ([]Repository, error) {
	parent := fmt.Sprintf("projects/%s/locations/%s", project, location)
	it := c.inner.ListRepositories(ctx, &arpb.ListRepositoriesRequest{
		Parent: parent,
	})

	var repos []Repository
	for {
		repo, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list repositories in %s: %w", parent, err)
		}
		// Only include Docker repositories
		if repo.GetFormat() == arpb.Repository_DOCKER {
			repos = append(repos, Repository{
				Name:     repo.GetName(),
				Location: location,
				RepoID:   extractRepoID(repo.GetName()),
				Format:   "DOCKER",
			})
		}
	}

	slog.Debug("Listed AR repositories", "location", location, "count", len(repos))
	return repos, nil
}

// ListDockerImages returns all Docker images in a repository.
func (c *Client) ListDockerImages(ctx context.Context, parent string) ([]DockerImage, error) {
	it := c.inner.ListDockerImages(ctx, &arpb.ListDockerImagesRequest{
		Parent: parent,
	})

	var images []DockerImage
	for {
		img, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list docker images in %s: %w", parent, err)
		}

		var uploadTime time.Time
		if img.GetUploadTime() != nil {
			uploadTime = img.GetUploadTime().AsTime()
		}

		images = append(images, DockerImage{
			Name:         img.GetName(),
			URI:          img.GetUri(),
			Tags:         img.GetTags(),
			SizeBytes:    img.GetImageSizeBytes(),
			UploadTime:   uploadTime,
			MediaType:    img.GetMediaType(),
			RepositoryID: extractRepoIDFromImage(img.GetName()),
		})
	}

	return images, nil
}

// extractRepoID extracts the repository ID from a full resource name.
// Format: projects/{project}/locations/{location}/repositories/{repo}
func extractRepoID(name string) string {
	// Simple approach: take the last segment
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '/' {
			return name[i+1:]
		}
	}
	return name
}

// extractRepoIDFromImage extracts the repository ID from a docker image resource name.
// Format: projects/{project}/locations/{location}/repositories/{repo}/dockerImages/{image}
func extractRepoIDFromImage(name string) string {
	// Find /dockerImages/ and take the segment before it
	const marker = "/dockerImages/"
	idx := -1
	for i := 0; i <= len(name)-len(marker); i++ {
		if name[i:i+len(marker)] == marker {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ""
	}
	// Find last / before /dockerImages/
	for i := idx - 1; i >= 0; i-- {
		if name[i] == '/' {
			return name[i+1 : idx]
		}
	}
	return ""
}
