package github

import (
	"strings"

	"github.com/jakeva/chainrecon/internal/model"
)

// ParseRepoURL extracts the GitHub owner and repo name from npm package
// metadata. It handles the common URL formats found in package.json:
//   - https://github.com/owner/repo
//   - https://github.com/owner/repo.git
//   - git+https://github.com/owner/repo.git
//   - git://github.com/owner/repo.git
//   - github:owner/repo
//
// Returns empty strings if the repository is not on GitHub.
func ParseRepoURL(metadata *model.PackageMetadata) (owner, repo string) {
	if metadata == nil || metadata.Repository == nil {
		return "", ""
	}

	raw := metadata.Repository.URL
	if raw == "" {
		return "", ""
	}

	// Handle github: shorthand (e.g. "github:owner/repo").
	if strings.HasPrefix(raw, "github:") {
		return splitOwnerRepo(strings.TrimPrefix(raw, "github:"))
	}

	// Strip protocol prefixes.
	raw = strings.TrimPrefix(raw, "git+")
	raw = strings.TrimPrefix(raw, "git://")
	raw = strings.TrimPrefix(raw, "ssh://git@")
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")

	// Must start with github.com.
	if !strings.HasPrefix(raw, "github.com/") {
		return "", ""
	}

	raw = strings.TrimPrefix(raw, "github.com/")
	return splitOwnerRepo(raw)
}

// splitOwnerRepo splits "owner/repo" or "owner/repo.git" into components.
func splitOwnerRepo(path string) (string, string) {
	path = strings.TrimSuffix(path, ".git")
	path = strings.TrimSuffix(path, "/")

	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", ""
	}
	return parts[0], parts[1]
}
