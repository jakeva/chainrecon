// Package npm provides collectors for npm registry metadata.
package npm

import (
	"strings"

	"github.com/chainrecon/chainrecon/internal/model"
)

// personalDomains is the set of email domains considered personal providers.
var personalDomains = map[string]bool{
	"gmail.com":      true,
	"protonmail.com": true,
	"proton.me":      true,
	"outlook.com":    true,
	"hotmail.com":    true,
	"yahoo.com":      true,
	"live.com":       true,
	"icloud.com":     true,
	"me.com":         true,
}

// MaintainerClient provides analysis of npm package maintainer metadata.
type MaintainerClient interface {
	// ExtractMaintainers returns the maintainers listed in the package metadata.
	ExtractMaintainers(metadata *model.PackageMetadata) []model.Maintainer

	// ExtractPublishers returns the unique set of _npmUser accounts across all versions.
	ExtractPublishers(metadata *model.PackageMetadata) []model.NPMUser

	// IsPersonalEmail reports whether the given email address belongs to a personal provider.
	IsPersonalEmail(email string) bool

	// IsScopedPackage reports whether the package name starts with @.
	IsScopedPackage(name string) bool

	// PublishFrequency returns the fraction of versions published by the given username.
	PublishFrequency(metadata *model.PackageMetadata, username string) float64
}

// maintainerClient implements MaintainerClient.
type maintainerClient struct{}

// NewMaintainerClient creates a new MaintainerClient.
func NewMaintainerClient() MaintainerClient {
	return &maintainerClient{}
}

// ExtractMaintainers returns the maintainers listed in the package metadata.
func (c *maintainerClient) ExtractMaintainers(metadata *model.PackageMetadata) []model.Maintainer {
	if metadata == nil {
		return nil
	}
	result := make([]model.Maintainer, len(metadata.Maintainers))
	copy(result, metadata.Maintainers)
	return result
}

// ExtractPublishers returns the unique set of _npmUser accounts across all versions.
// Each user appears at most once, identified by username.
func (c *maintainerClient) ExtractPublishers(metadata *model.PackageMetadata) []model.NPMUser {
	if metadata == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var publishers []model.NPMUser
	for _, v := range metadata.Versions {
		if v.NPMUser == nil {
			continue
		}
		if _, ok := seen[v.NPMUser.Name]; ok {
			continue
		}
		seen[v.NPMUser.Name] = struct{}{}
		publishers = append(publishers, *v.NPMUser)
	}
	return publishers
}

// IsPersonalEmail reports whether the given email address belongs to a personal
// provider such as Gmail, ProtonMail, Outlook, Yahoo, iCloud, or similar.
func (c *maintainerClient) IsPersonalEmail(email string) bool {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return false
	}
	domain := strings.ToLower(parts[1])
	return personalDomains[domain]
}

// IsScopedPackage reports whether the package name starts with @, indicating
// it belongs to an npm scope (e.g. @myorg/mypackage).
func (c *maintainerClient) IsScopedPackage(name string) bool {
	return strings.HasPrefix(name, "@")
}

// PublishFrequency returns the fraction of versions published by the given
// username. Returns 0 if the metadata is nil, has no versions, or the username
// did not publish any version.
func (c *maintainerClient) PublishFrequency(metadata *model.PackageMetadata, username string) float64 {
	if metadata == nil || len(metadata.Versions) == 0 {
		return 0
	}
	total := 0
	matched := 0
	for _, v := range metadata.Versions {
		total++
		if v.NPMUser != nil && v.NPMUser.Name == username {
			matched++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(matched) / float64(total)
}
