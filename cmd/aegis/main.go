// SPDX-License-Identifier: MIT
// aegis is the Aegis governance CLI.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

var rootCmd = &cobra.Command{
	Use:     "aegis",
	Short:   "Aegis governance CLI",
	Version: version,
}

func init() {
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(simulateCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(bundleCmd)
	rootCmd.AddCommand(policyCmd)
	rootCmd.AddCommand(delegationCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
