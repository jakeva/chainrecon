// Package main is the entry point for the chainrecon CLI.
package main

import (
	"fmt"
	"os"

	"github.com/chainrecon/chainrecon/internal/cli"
)

func main() {
	root := cli.NewRootCmd()
	root.AddCommand(cli.NewScanCmd())
	root.AddCommand(cli.NewWatchCmd())
	root.AddCommand(cli.NewUpdateCmd())
	root.AddCommand(cli.NewVersionCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
