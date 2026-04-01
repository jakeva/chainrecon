package model

// ProvenanceState classifies a package's provenance history.
type ProvenanceState string

const (
	// ProvenanceNever means the package has never published with provenance.
	ProvenanceNever ProvenanceState = "NEVER"
	// ProvenanceActive means current and recent versions have provenance.
	ProvenanceActive ProvenanceState = "ACTIVE"
	// ProvenanceDropped means the package previously had provenance but latest versions do not.
	ProvenanceDropped ProvenanceState = "DROPPED"
	// ProvenanceIntermittent means provenance appears and disappears across versions.
	ProvenanceIntermittent ProvenanceState = "INTERMITTENT"
)

// Severity levels for findings.
type Severity string

const (
	// SeverityCritical indicates the highest risk finding.
	SeverityCritical Severity = "CRITICAL"
	// SeverityHigh indicates a high risk finding.
	SeverityHigh Severity = "HIGH"
	// SeverityMedium indicates a medium risk finding.
	SeverityMedium Severity = "MEDIUM"
	// SeverityLow indicates a low risk finding.
	SeverityLow Severity = "LOW"
	// SeverityInfo indicates an informational finding.
	SeverityInfo Severity = "INFO"
)

// SignalScore holds the score and details for a single analysis signal.
type SignalScore struct {
	Name   string  `json:"name"`
	Score  float64 `json:"score"`
	Detail string  `json:"detail"`
}

// Finding represents a specific security finding from analysis.
type Finding struct {
	Severity Severity `json:"severity"`
	Signal   string   `json:"signal"`
	Message  string   `json:"message"`
	Detail   string   `json:"detail"`
}
