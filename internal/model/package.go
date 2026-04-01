// Package model defines the core data types for chainrecon.
package model

import "time"

// PackageMetadata holds the full npm registry metadata for a package.
type PackageMetadata struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	DistTags    map[string]string `json:"dist-tags"`
	Versions    map[string]VersionDetail `json:"versions"`
	Time        map[string]time.Time     `json:"time"`
	Maintainers []Maintainer             `json:"maintainers"`
	Repository  *Repository              `json:"repository,omitempty"`
}

// VersionDetail holds metadata for a single published version.
type VersionDetail struct {
	Version     string       `json:"version"`
	NPMUser     *NPMUser     `json:"_npmUser,omitempty"`
	Dist        Distribution `json:"dist"`
	Description string       `json:"description"`
}

// NPMUser represents the npm account that published a version.
type NPMUser struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Distribution holds the dist metadata for a version.
type Distribution struct {
	Shasum     string       `json:"shasum"`
	Integrity  string       `json:"integrity"`
	Tarball    string       `json:"tarball"`
	Signatures []Signature  `json:"signatures,omitempty"`
}

// Signature represents a registry signature on a version.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Maintainer represents an npm account with publish access.
type Maintainer struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Repository holds the source repository information.
type Repository struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// DownloadCount holds npm download statistics.
type DownloadCount struct {
	Downloads int    `json:"downloads"`
	Start     string `json:"start"`
	End       string `json:"end"`
	Package   string `json:"package"`
}

// SearchResult holds npm search API results for dependent count.
type SearchResult struct {
	Total   int            `json:"total"`
	Objects []SearchObject `json:"objects"`
}

// SearchObject is a single entry in the npm search result.
type SearchObject struct {
	Package SearchPackage `json:"package"`
}

// SearchPackage holds the package info from a search result.
type SearchPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// AttestationBundle holds the response from the npm attestations API.
type AttestationBundle struct {
	Attestations []Attestation `json:"attestations"`
}

// Attestation holds a single attestation from the npm attestations API.
type Attestation struct {
	PredicateType string `json:"predicateType"`
	Bundle        any    `json:"bundle"`
}

// VersionAttestation summarizes the attestation state for one version.
type VersionAttestation struct {
	Version          string `json:"version"`
	HasSLSA          bool   `json:"has_slsa"`
	HasPublish       bool   `json:"has_publish"`
	HasAnyProvenance bool   `json:"has_any_provenance"`
}
