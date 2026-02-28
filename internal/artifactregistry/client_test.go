package artifactregistry

import "testing"

func TestExtractRepoID(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"projects/my-project/locations/us-central1/repositories/myapp", "myapp"},
		{"projects/p/locations/l/repositories/repo-name", "repo-name"},
		{"simple", "simple"},
	}
	for _, tt := range tests {
		got := extractRepoID(tt.name)
		if got != tt.want {
			t.Errorf("extractRepoID(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestExtractRepoIDFromImage(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"projects/p/locations/l/repositories/myapp/dockerImages/img@sha256:abc", "myapp"},
		{"projects/p/locations/l/repositories/repo-name/dockerImages/x", "repo-name"},
		{"no-marker", ""},
		{"dockerImages/img", ""},
	}
	for _, tt := range tests {
		got := extractRepoIDFromImage(tt.name)
		if got != tt.want {
			t.Errorf("extractRepoIDFromImage(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}
