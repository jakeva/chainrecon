package npm

import (
	"testing"

	"github.com/jakeva/chainrecon/internal/model"
)

func TestMaintainerClient_ExtractMaintainers(t *testing.T) {
	c := NewMaintainerClient()

	meta := &model.PackageMetadata{
		Maintainers: []model.Maintainer{
			{Name: "alice", Email: "alice@example.com"},
			{Name: "bob", Email: "bob@example.com"},
		},
	}

	got := c.ExtractMaintainers(meta)
	if len(got) != 2 {
		t.Fatalf("got %d maintainers, want 2", len(got))
	}
	if got[0].Name != "alice" || got[1].Name != "bob" {
		t.Errorf("unexpected maintainers: %+v", got)
	}
}

func TestMaintainerClient_ExtractMaintainersNil(t *testing.T) {
	c := NewMaintainerClient()
	if got := c.ExtractMaintainers(nil); got != nil {
		t.Errorf("expected nil for nil metadata, got %+v", got)
	}
}

func TestMaintainerClient_ExtractPublishers(t *testing.T) {
	c := NewMaintainerClient()

	meta := &model.PackageMetadata{
		Versions: map[string]model.VersionDetail{
			"1.0.0": {NPMUser: &model.NPMUser{Name: "alice"}},
			"1.0.1": {NPMUser: &model.NPMUser{Name: "alice"}},
			"2.0.0": {NPMUser: &model.NPMUser{Name: "bob"}},
			"3.0.0": {NPMUser: nil},
		},
	}

	got := c.ExtractPublishers(meta)
	if len(got) != 2 {
		t.Fatalf("got %d publishers, want 2 (alice and bob deduplicated)", len(got))
	}

	names := map[string]bool{}
	for _, p := range got {
		names[p.Name] = true
	}
	if !names["alice"] || !names["bob"] {
		t.Errorf("expected alice and bob, got %+v", got)
	}
}

func TestMaintainerClient_ExtractPublishersNil(t *testing.T) {
	c := NewMaintainerClient()
	if got := c.ExtractPublishers(nil); got != nil {
		t.Errorf("expected nil for nil metadata, got %+v", got)
	}
}

func TestMaintainerClient_IsPersonalEmail(t *testing.T) {
	c := NewMaintainerClient()

	tests := []struct {
		email string
		want  bool
	}{
		{"user@gmail.com", true},
		{"user@protonmail.com", true},
		{"user@proton.me", true},
		{"user@outlook.com", true},
		{"user@hotmail.com", true},
		{"user@yahoo.com", true},
		{"user@icloud.com", true},
		{"user@me.com", true},
		{"user@live.com", true},
		{"user@company.com", false},
		{"user@chainguard.dev", false},
		{"invalid-email", false},
		{"", false},
	}
	for _, tc := range tests {
		got := c.IsPersonalEmail(tc.email)
		if got != tc.want {
			t.Errorf("IsPersonalEmail(%q) = %v, want %v", tc.email, got, tc.want)
		}
	}
}

func TestMaintainerClient_IsScopedPackage(t *testing.T) {
	c := NewMaintainerClient()

	if !c.IsScopedPackage("@anthropic-ai/sdk") {
		t.Error("expected @anthropic-ai/sdk to be scoped")
	}
	if c.IsScopedPackage("express") {
		t.Error("expected express to not be scoped")
	}
}

func TestMaintainerClient_PublishFrequency(t *testing.T) {
	c := NewMaintainerClient()

	meta := &model.PackageMetadata{
		Versions: map[string]model.VersionDetail{
			"1.0.0": {NPMUser: &model.NPMUser{Name: "alice"}},
			"1.0.1": {NPMUser: &model.NPMUser{Name: "alice"}},
			"2.0.0": {NPMUser: &model.NPMUser{Name: "bob"}},
			"3.0.0": {NPMUser: nil},
		},
	}

	aliceFreq := c.PublishFrequency(meta, "alice")
	if aliceFreq != 0.5 {
		t.Errorf("alice frequency = %f, want 0.5", aliceFreq)
	}

	bobFreq := c.PublishFrequency(meta, "bob")
	if bobFreq != 0.25 {
		t.Errorf("bob frequency = %f, want 0.25", bobFreq)
	}

	unknownFreq := c.PublishFrequency(meta, "unknown")
	if unknownFreq != 0 {
		t.Errorf("unknown frequency = %f, want 0", unknownFreq)
	}

	if c.PublishFrequency(nil, "alice") != 0 {
		t.Error("expected 0 for nil metadata")
	}
}
