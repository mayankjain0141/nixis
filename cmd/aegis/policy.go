package main

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/google/cel-go/checker"
	"github.com/mayjain/aegis/internal/bundle"
	"github.com/mayjain/aegis/internal/cel"
	"github.com/spf13/cobra"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Policy tools",
}

var policyCostCmd = &cobra.Command{
	Use:   "cost <cel-expression>",
	Short: "Estimate CEL expression evaluation cost",
	Args:  cobra.ExactArgs(1),
	RunE:  runPolicyCost,
}

var policyLintStrict bool

var policyLintCmd = &cobra.Command{
	Use:   "lint <policy-dir>",
	Short: "Lint policy YAML files",
	Args:  cobra.ExactArgs(1),
	RunE:  runPolicyLint,
}

func init() {
	policyLintCmd.Flags().BoolVar(&policyLintStrict, "strict", false, "Treat warnings as errors")
	policyCmd.AddCommand(policyCostCmd)
	policyCmd.AddCommand(policyLintCmd)
}

func runPolicyCost(cmd *cobra.Command, args []string) error {
	expr := args[0]

	env, err := cel.NewCELEnvironment()
	if err != nil {
		return fmt.Errorf("create CEL environment: %w", err)
	}

	rawEnv := cel.RawEnv(env)

	ast, issues := rawEnv.Parse(expr)
	if issues != nil && issues.Err() != nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "parse error: %s\n", issues.Err())
		return fmt.Errorf("invalid expression")
	}

	checkedAST, checkIssues := rawEnv.Check(ast)
	if checkIssues != nil && checkIssues.Err() != nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "type-check error: %s\n", checkIssues.Err())
		return fmt.Errorf("invalid expression")
	}

	cost, err := rawEnv.EstimateCost(checkedAST, simpleSizeEstimator{})
	if err != nil {
		return fmt.Errorf("cost estimation failed: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "cost: %d\n", cost.Max)
	return nil
}

// simpleSizeEstimator implements checker.CostEstimator for the CLI cost command.
type simpleSizeEstimator struct{}

func (simpleSizeEstimator) EstimateSize(_ checker.AstNode) *checker.SizeEstimate {
	return &checker.SizeEstimate{Min: 0, Max: 1024}
}

func (simpleSizeEstimator) EstimateCallCost(_, _ string, _ *checker.AstNode, _ []checker.AstNode) *checker.CallEstimate {
	return nil
}

var _ checker.CostEstimator = simpleSizeEstimator{}

func runPolicyLint(cmd *cobra.Command, args []string) error {
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
			loc := filepath.Base(compErr.SourceFile)
			if compErr.SourceLine > 0 {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s:%d: %s\n",
					loc, compErr.SourceLine, compErr.Cause)
			} else {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s\n", loc, compErr.Cause)
			}
			return fmt.Errorf("lint failed")
		}
		return err
	}

	if policyLintStrict {
		for _, t := range templates {
			if t.Description == "" {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: policy %q missing description (--strict)\n",
					t.SourceFile, t.ID)
				return fmt.Errorf("lint failed")
			}
		}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "OK: %d policies\n", len(templates))
	return nil
}
