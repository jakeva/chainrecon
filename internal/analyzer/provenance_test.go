package analyzer

import (
	"math"
	"testing"

	"github.com/chainrecon/chainrecon/internal/model"
)

// almostEqual reports whether two float64 values are within the given tolerance.
func almostEqual(a, b, tolerance float64) bool {
	return math.Abs(a-b) <= tolerance
}

func TestClassifyState(t *testing.T) {
	pa := NewProvenanceAnalyzer()

	tests := []struct {
		name         string
		attestations []model.VersionAttestation
		want         model.ProvenanceState
	}{
		{
			name:         "empty slice returns NEVER",
			attestations: nil,
			want:         model.ProvenanceNever,
		},
		{
			name: "all versions have no provenance returns NEVER",
			attestations: []model.VersionAttestation{
				{Version: "3.0.0", HasAnyProvenance: false},
				{Version: "2.0.0", HasAnyProvenance: false},
				{Version: "1.0.0", HasAnyProvenance: false},
			},
			want: model.ProvenanceNever,
		},
		{
			name: "all versions have provenance returns ACTIVE",
			attestations: []model.VersionAttestation{
				{Version: "3.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "2.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "1.0.0", HasAnyProvenance: true, HasSLSA: true},
			},
			want: model.ProvenanceActive,
		},
		{
			name: "latest has no provenance older ones have it returns DROPPED",
			attestations: []model.VersionAttestation{
				{Version: "3.0.0", HasAnyProvenance: false},
				{Version: "2.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "1.0.0", HasAnyProvenance: true, HasSLSA: true},
			},
			want: model.ProvenanceDropped,
		},
		{
			name: "mix of provenance but latest has provenance returns INTERMITTENT",
			attestations: []model.VersionAttestation{
				{Version: "5.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "4.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "3.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "2.0.0", HasAnyProvenance: false},
				{Version: "1.5.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "1.0.0", HasAnyProvenance: false},
			},
			want: model.ProvenanceIntermittent,
		},
		{
			name: "single version with provenance returns ACTIVE",
			attestations: []model.VersionAttestation{
				{Version: "1.0.0", HasAnyProvenance: true, HasSLSA: true},
			},
			want: model.ProvenanceActive,
		},
		{
			name: "single version without provenance returns NEVER",
			attestations: []model.VersionAttestation{
				{Version: "1.0.0", HasAnyProvenance: false},
			},
			want: model.ProvenanceNever,
		},
		{
			name: "recently adopted provenance with older versions lacking it returns ACTIVE",
			attestations: []model.VersionAttestation{
				{Version: "5.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "4.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "3.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "2.0.0", HasAnyProvenance: false},
				{Version: "1.0.0", HasAnyProvenance: false},
			},
			want: model.ProvenanceActive,
		},
		{
			name: "latest has provenance but gap in recent window returns INTERMITTENT",
			attestations: []model.VersionAttestation{
				{Version: "4.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "3.0.0", HasAnyProvenance: false},
				{Version: "2.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "1.0.0", HasAnyProvenance: true, HasSLSA: true},
			},
			want: model.ProvenanceIntermittent,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pa.ClassifyState(tc.attestations)
			if got != tc.want {
				t.Errorf("ClassifyState() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAnalyze_Scoring(t *testing.T) {
	pa := NewProvenanceAnalyzer()
	const tolerance = 0.1

	tests := []struct {
		name         string
		attestations []model.VersionAttestation
		wantState    model.ProvenanceState
		wantMinScore float64
		wantMaxScore float64
	}{
		{
			name: "NEVER state gives base score 5.0",
			attestations: []model.VersionAttestation{
				{Version: "2.0.0", HasAnyProvenance: false},
				{Version: "1.0.0", HasAnyProvenance: false},
			},
			wantState:    model.ProvenanceNever,
			wantMinScore: 4.9,
			wantMaxScore: 5.1,
		},
		{
			name: "ACTIVE state gives base score 1.0",
			attestations: []model.VersionAttestation{
				{Version: "3.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "2.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "1.0.0", HasAnyProvenance: true, HasSLSA: true},
			},
			wantState:    model.ProvenanceActive,
			wantMinScore: 0.9,
			wantMaxScore: 1.1,
		},
		{
			name: "DROPPED state gives base 9.0 plus modifier for latest dropped",
			attestations: []model.VersionAttestation{
				{Version: "3.0.0", HasAnyProvenance: false},
				{Version: "2.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "1.0.0", HasAnyProvenance: true, HasSLSA: true},
			},
			wantState:    model.ProvenanceDropped,
			// base 9.0 + 1.0 (latest dropped) + 0.5 (gap: version 3.0.0 no prov, neighbor 2.0.0 has prov) = 10.5 capped at 10.0
			wantMinScore: 9.9,
			wantMaxScore: 10.1,
		},
		{
			name: "INTERMITTENT state gives base 6.0 plus gap modifiers",
			attestations: []model.VersionAttestation{
				{Version: "4.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "3.0.0", HasAnyProvenance: false},
				{Version: "2.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "1.0.0", HasAnyProvenance: true, HasSLSA: true},
			},
			wantState: model.ProvenanceIntermittent,
			// base 6.0 + 0.5 (gap at 3.0.0 with provenance neighbors on both sides) = 6.5
			wantMinScore: 6.4,
			wantMaxScore: 6.6,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := pa.ClassifyState(tc.attestations)
			if state != tc.wantState {
				t.Errorf("ClassifyState() = %q, want %q", state, tc.wantState)
			}

			signal, _ := pa.Analyze(tc.attestations)

			if signal.Score < tc.wantMinScore || signal.Score > tc.wantMaxScore {
				t.Errorf("Analyze() score = %.2f, want between %.1f and %.1f",
					signal.Score, tc.wantMinScore, tc.wantMaxScore)
			}

			if signal.Name != "provenance" {
				t.Errorf("Analyze() signal name = %q, want %q", signal.Name, "provenance")
			}
		})
	}
}

func TestAnalyze_Findings(t *testing.T) {
	pa := NewProvenanceAnalyzer()

	tests := []struct {
		name             string
		attestations     []model.VersionAttestation
		wantSeverity     model.Severity
		wantMinFindings  int
	}{
		{
			name: "DROPPED generates CRITICAL finding",
			attestations: []model.VersionAttestation{
				{Version: "3.0.0", HasAnyProvenance: false},
				{Version: "2.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "1.0.0", HasAnyProvenance: true, HasSLSA: true},
			},
			wantSeverity:    model.SeverityCritical,
			wantMinFindings: 1,
		},
		{
			name: "NEVER generates MEDIUM finding",
			attestations: []model.VersionAttestation{
				{Version: "2.0.0", HasAnyProvenance: false},
				{Version: "1.0.0", HasAnyProvenance: false},
			},
			wantSeverity:    model.SeverityMedium,
			wantMinFindings: 1,
		},
		{
			name: "ACTIVE generates INFO finding",
			attestations: []model.VersionAttestation{
				{Version: "3.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "2.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "1.0.0", HasAnyProvenance: true, HasSLSA: true},
			},
			wantSeverity:    model.SeverityInfo,
			wantMinFindings: 1,
		},
		{
			name: "INTERMITTENT generates HIGH finding",
			attestations: []model.VersionAttestation{
				{Version: "4.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "3.0.0", HasAnyProvenance: false},
				{Version: "2.0.0", HasAnyProvenance: true, HasSLSA: true},
				{Version: "1.0.0", HasAnyProvenance: true, HasSLSA: true},
			},
			wantSeverity:    model.SeverityHigh,
			wantMinFindings: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, findings := pa.Analyze(tc.attestations)

			if len(findings) < tc.wantMinFindings {
				t.Fatalf("Analyze() produced %d findings, want at least %d", len(findings), tc.wantMinFindings)
			}

			found := false
			for _, f := range findings {
				if f.Severity == tc.wantSeverity {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Analyze() findings missing severity %q; got %v", tc.wantSeverity, findings)
			}

			// Verify all findings reference the provenance signal.
			for _, f := range findings {
				if f.Signal != "provenance" {
					t.Errorf("finding signal = %q, want %q", f.Signal, "provenance")
				}
			}
		})
	}
}

func TestAnalyze_EmptyAttestations(t *testing.T) {
	pa := NewProvenanceAnalyzer()

	signal, findings := pa.Analyze(nil)

	if signal.Name != "provenance" {
		t.Errorf("signal name = %q, want %q", signal.Name, "provenance")
	}

	if !almostEqual(signal.Score, 5.0, 0.1) {
		t.Errorf("empty attestations score = %.2f, want ~5.0", signal.Score)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding for empty attestations")
	}

	if findings[0].Severity != model.SeverityMedium {
		t.Errorf("finding severity = %q, want %q", findings[0].Severity, model.SeverityMedium)
	}
}

func TestAnalyze_ScoreCappedAt10(t *testing.T) {
	pa := NewProvenanceAnalyzer()

	// DROPPED with many gaps should still cap at 10.0.
	attestations := []model.VersionAttestation{
		{Version: "10.0.0", HasAnyProvenance: false},
	}
	// Create alternating provenance/no-provenance to maximize gap modifiers.
	for i := 9; i >= 0; i-- {
		hasProv := i%2 == 0
		attestations = append(attestations, model.VersionAttestation{
			Version:          "1." + string(rune('0'+i)) + ".0",
			HasAnyProvenance: hasProv,
			HasSLSA:          hasProv,
		})
	}

	signal, _ := pa.Analyze(attestations)

	if signal.Score > 10.0 {
		t.Errorf("score = %.2f, must not exceed 10.0", signal.Score)
	}
}
