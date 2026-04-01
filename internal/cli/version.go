package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is the current release version, set via ldflags at build time.
var Version = "0.1.0"

// Commit is the git commit hash, set via ldflags at build time.
var Commit = "unknown"

// Date is the build date, set via ldflags at build time.
var Date = "unknown"

// NewVersionCmd creates a cobra command that prints version and build info.
func NewVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version and build information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(),
				"chainrecon version %s\ncommit: %s\nbuilt:  %s\n",
				Version, Commit, Date)
		},
	}
}
