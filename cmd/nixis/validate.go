// SPDX-License-Identifier: MIT
package main

import (
	"errors"
	"fmt"

	"github.com/mayankjain0141/nixis/internal/bundle"
	"github.com/mayankjain0141/nixis/internal/cel"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate <policy-dir>",
	Short: "Validate policy YAML files and CEL expressions",
	Args:  cobra.ExactArgs(1),
	RunE:  runValidate,
}

func runValidate(cmd *cobra.Command, args []string) error {
	dir := args[0]
	templates, _, err := bundle.ParsePolicyDir(dir)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}
	env, err := cel.NewCELEnvironment()
	if err != nil {
		return err
	}
	_, skipped, err := cel.CompileAll(env, templates)
	if err != nil {
		var compErr *cel.CompileError
		if errors.As(err, &compErr) {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s:%d: %s\n",
				compErr.SourceFile, compErr.SourceLine, compErr.Cause)
			return fmt.Errorf("validation failed")
		}
		return err
	}
	if len(skipped) > 0 {
		skippedIDs := make([]string, len(skipped))
		for i, s := range skipped {
			skippedIDs[i] = s.TemplateID
		}
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "WARN: %d polic(ies) skipped — undeclared CEL variables: %v\n", len(skipped), skippedIDs)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "OK: %d policies valid (%d skipped)\n", len(templates)-len(skipped), len(skipped))
	return nil
}
