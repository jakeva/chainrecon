package github

import (
	"testing"

	"github.com/chainrecon/chainrecon/internal/model"
)

func TestParseRepoURL(t *testing.T) {
	tests := []struct {
		name      string
		metadata  *model.PackageMetadata
		wantOwner string
		wantRepo  string
	}{
		{
			name: "https URL",
			metadata: &model.PackageMetadata{
				Repository: &model.Repository{URL: "https://github.com/axios/axios"},
			},
			wantOwner: "axios",
			wantRepo:  "axios",
		},
		{
			name: "https URL with .git",
			metadata: &model.PackageMetadata{
				Repository: &model.Repository{URL: "https://github.com/expressjs/express.git"},
			},
			wantOwner: "expressjs",
			wantRepo:  "express",
		},
		{
			name: "git+https URL",
			metadata: &model.PackageMetadata{
				Repository: &model.Repository{URL: "git+https://github.com/lodash/lodash.git"},
			},
			wantOwner: "lodash",
			wantRepo:  "lodash",
		},
		{
			name: "git:// URL",
			metadata: &model.PackageMetadata{
				Repository: &model.Repository{URL: "git://github.com/foo/bar.git"},
			},
			wantOwner: "foo",
			wantRepo:  "bar",
		},
		{
			name: "ssh URL",
			metadata: &model.PackageMetadata{
				Repository: &model.Repository{URL: "ssh://git@github.com/foo/bar.git"},
			},
			wantOwner: "foo",
			wantRepo:  "bar",
		},
		{
			name: "github shorthand",
			metadata: &model.PackageMetadata{
				Repository: &model.Repository{URL: "github:sigstore/sigstore-js"},
			},
			wantOwner: "sigstore",
			wantRepo:  "sigstore-js",
		},
		{
			name:      "nil metadata",
			metadata:  nil,
			wantOwner: "",
			wantRepo:  "",
		},
		{
			name:      "no repository",
			metadata:  &model.PackageMetadata{},
			wantOwner: "",
			wantRepo:  "",
		},
		{
			name: "empty URL",
			metadata: &model.PackageMetadata{
				Repository: &model.Repository{URL: ""},
			},
			wantOwner: "",
			wantRepo:  "",
		},
		{
			name: "non-GitHub URL",
			metadata: &model.PackageMetadata{
				Repository: &model.Repository{URL: "https://gitlab.com/foo/bar"},
			},
			wantOwner: "",
			wantRepo:  "",
		},
		{
			name: "trailing slash",
			metadata: &model.PackageMetadata{
				Repository: &model.Repository{URL: "https://github.com/foo/bar/"},
			},
			wantOwner: "foo",
			wantRepo:  "bar",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			owner, repo := ParseRepoURL(tc.metadata)
			if owner != tc.wantOwner || repo != tc.wantRepo {
				t.Errorf("ParseRepoURL() = (%q, %q), want (%q, %q)", owner, repo, tc.wantOwner, tc.wantRepo)
			}
		})
	}
}
