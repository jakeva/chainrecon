// Package output provides formatters for rendering scan reports.
package output

import (
	"encoding/json"
	"fmt"

	"github.com/jakeva/chainrecon/internal/model"
)

// Formatter defines the interface for rendering a Report to a string.
type Formatter interface {
	// Format renders the given report as a formatted string.
	Format(report *model.Report) (string, error)
}

// JSONFormatter renders a Report as pretty-printed JSON.
type JSONFormatter struct{}

// NewJSONFormatter returns a new JSONFormatter.
func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

// Format serialises the report as indented JSON using two-space indentation.
func (f *JSONFormatter) Format(report *model.Report) (string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("json format: %w", err)
	}
	return string(data), nil
}
