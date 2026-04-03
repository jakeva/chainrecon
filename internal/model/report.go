package model

import "time"

// Report holds the complete scan result for a package.
type Report struct {
	Package           string               `json:"package"`
	Version           string               `json:"version"`
	Description       string               `json:"description,omitempty"`
	RepositoryURL     string               `json:"repository_url,omitempty"`
	Timestamp         time.Time            `json:"timestamp"`
	Scores            Scores               `json:"scores"`
	Findings          []Finding            `json:"findings"`
	ProvenanceHistory []ProvenanceVersion  `json:"provenance_history"`
	Maintainers       []Maintainer         `json:"maintainers,omitempty"`
	WeeklyDownloads   int                  `json:"weekly_downloads"`
	DependentCount    int                  `json:"dependent_count"`
}

// Scores holds all computed scores for a package.
type Scores struct {
	Provenance        float64 `json:"provenance"`
	PublishingHygiene float64 `json:"publishing_hygiene"`
	MaintainerRisk   float64 `json:"maintainer_risk"`
	IdentityStability float64 `json:"identity_stability"`
	ScorecardRepo    float64 `json:"scorecard_repo"`
	BlastRadius      float64 `json:"blast_radius"`
	AttackSurface    float64 `json:"attack_surface"`
	TargetScore      float64 `json:"target_score"`
}

// ProvenanceVersion records the provenance state for a single version.
type ProvenanceVersion struct {
	Version    string          `json:"version"`
	State      ProvenanceState `json:"state"`
	HasSLSA    bool            `json:"has_slsa"`
	HasPublish bool            `json:"has_publish"`
}
