package model

// ScorecardResult holds the response from the OpenSSF Scorecard API.
type ScorecardResult struct {
	Repo      ScorecardRepo  `json:"repo"`
	Scorecard ScorecardScore `json:"scorecard"`
	Score     float64        `json:"score"`
	Checks    []ScorecardCheck `json:"checks"`
}

// ScorecardRepo identifies the repository that was scored.
type ScorecardRepo struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
}

// ScorecardScore holds Scorecard version metadata.
type ScorecardScore struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// ScorecardCheck is a single Scorecard check result.
type ScorecardCheck struct {
	Name          string              `json:"name"`
	Score         int                 `json:"score"`
	Reason        string              `json:"reason"`
	Documentation ScorecardCheckDoc   `json:"documentation"`
}

// ScorecardCheckDoc holds the documentation URL for a check.
type ScorecardCheckDoc struct {
	URL string `json:"url"`
}
