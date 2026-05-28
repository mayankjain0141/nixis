package main

import (
	"errors"
	"fmt"

	"github.com/mayjain/aegis/internal/bundle"
	"github.com/mayjain/aegis/internal/cel"
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
	_, err = cel.CompileAll(env, templates)
	if err != nil {
		var compErr *cel.CompileError
		if errors.As(err, &compErr) {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s:%d: %s\n",
				compErr.SourceFile, compErr.SourceLine, compErr.Cause)
			return fmt.Errorf("validation failed")
		}
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "OK: %d policies valid\n", len(templates))
	return nil
}
