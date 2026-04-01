package model

// GitHubRelease represents a release from the GitHub API.
type GitHubRelease struct {
	TagName    string `json:"tag_name"`
	Name       string `json:"name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

// GitHubTag represents a git tag from the GitHub API.
type GitHubTag struct {
	Name string `json:"name"`
}
