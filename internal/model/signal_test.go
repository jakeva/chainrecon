package model

import "testing"

func TestSortFindings_BySeverity(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityLow, Signal: "a", Message: "low finding"},
		{Severity: SeverityCritical, Signal: "b", Message: "critical finding"},
		{Severity: SeverityInfo, Signal: "c", Message: "info finding"},
		{Severity: SeverityHigh, Signal: "d", Message: "high finding"},
		{Severity: SeverityMedium, Signal: "e", Message: "medium finding"},
	}

	SortFindings(findings)

	expected := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
	for i, want := range expected {
		if findings[i].Severity != want {
			t.Errorf("findings[%d].Severity = %s, want %s", i, findings[i].Severity, want)
		}
	}
}

func TestSortFindings_StableOrder(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityHigh, Signal: "provenance", Message: "first high"},
		{Severity: SeverityHigh, Signal: "blast_radius", Message: "second high"},
		{Severity: SeverityHigh, Signal: "identity", Message: "third high"},
	}

	SortFindings(findings)

	// Stable sort should preserve original order for equal severity.
	if findings[0].Message != "first high" {
		t.Errorf("findings[0].Message = %q, want %q", findings[0].Message, "first high")
	}
	if findings[1].Message != "second high" {
		t.Errorf("findings[1].Message = %q, want %q", findings[1].Message, "second high")
	}
	if findings[2].Message != "third high" {
		t.Errorf("findings[2].Message = %q, want %q", findings[2].Message, "third high")
	}
}

func TestSortFindings_Empty(t *testing.T) {
	var findings []Finding
	SortFindings(findings) // should not panic
}

func TestSortFindings_SingleElement(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityMedium, Signal: "test", Message: "only one"},
	}
	SortFindings(findings)
	if findings[0].Severity != SeverityMedium {
		t.Errorf("unexpected severity after sorting single element")
	}
}
