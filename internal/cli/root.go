// Package cli defines the cobra command tree for chainrecon.
package cli

import (
	"github.com/spf13/cobra"
)

// NewRootCmd creates and returns the root cobra command for chainrecon.
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "chainrecon",
		Short: "Supply chain attack target reconnaissance for npm packages",
		Long: `chainrecon profiles npm packages from the attacker's perspective, identifying
which packages are the most attractive and vulnerable targets for supply chain
compromise.`,
		SilenceErrors: true,
	}

	cmd.PersistentFlags().Bool("no-cache", false, "Disable local caching of API responses")

	return cmd
}
