package artifactregistry

import (
	"context"
	"time"
)

// mockARClient implements ARAPI for testing.
type mockARClient struct {
	repos         map[string][]Repository  // keyed by "project/location"
	images        map[string][]DockerImage // keyed by repo resource name
	listRepoErr   map[string]error         // keyed by "project/location"
	listImagesErr map[string]error         // keyed by repo resource name
}

func newMockClient() *mockARClient {
	return &mockARClient{
		repos:         make(map[string][]Repository),
		images:        make(map[string][]DockerImage),
		listRepoErr:   make(map[string]error),
		listImagesErr: make(map[string]error),
	}
}

func (m *mockARClient) ListRepositories(_ context.Context, project, location string) ([]Repository, error) {
	key := project + "/" + location
	if err, ok := m.listRepoErr[key]; ok {
		return nil, err
	}
	return m.repos[key], nil
}

func (m *mockARClient) ListDockerImages(_ context.Context, parent string) ([]DockerImage, error) {
	if err, ok := m.listImagesErr[parent]; ok {
		return nil, err
	}
	return m.images[parent], nil
}

func (m *mockARClient) Close() error {
	return nil
}

func makeRepo(name, location, repoID string) Repository {
	return Repository{
		Name:     name,
		Location: location,
		RepoID:   repoID,
		Format:   "DOCKER",
	}
}

func makeImage(uri string, tags []string, sizeBytes int64, uploadTime time.Time, mediaType string) DockerImage {
	return DockerImage{
		Name:       "projects/p/locations/l/repositories/r/dockerImages/img",
		URI:        uri,
		Tags:       tags,
		SizeBytes:  sizeBytes,
		UploadTime: uploadTime,
		MediaType:  mediaType,
	}
}
