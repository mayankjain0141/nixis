// SPDX-License-Identifier: MIT
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
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

var policyExportDir string
var policyExportOut string

var policyExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export policies directory to JSON",
	RunE:  runPolicyExport,
}

func init() {
	policyLintCmd.Flags().BoolVar(&policyLintStrict, "strict", false, "Treat warnings as errors")
	policyExportCmd.Flags().StringVar(&policyExportDir, "dir", "./policies", "Policy directory to read")
	policyExportCmd.Flags().StringVar(&policyExportOut, "out", "dashboard/public/policies.json", "Output file path; use - for stdout")
	policyCmd.AddCommand(policyCostCmd)
	policyCmd.AddCommand(policyLintCmd)
	policyCmd.AddCommand(policyExportCmd)
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

	_, _, err = cel.CompileAll(env, templates)
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

type policyJSON struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Layer         string `json:"layer"`
	Enabled       bool   `json:"enabled"`
	CelExpression string `json:"cel_expression,omitempty"`
	Description   string `json:"description,omitempty"`
}

func runPolicyExport(_ *cobra.Command, _ []string) error {
	templates, bindings, err := bundle.ParsePolicyDir(policyExportDir)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}

	layerByID := make(map[string]string, len(bindings))
	for _, b := range bindings {
		if b.Layer != "" {
			layerByID[b.TemplateID] = b.Layer
		}
	}

	result := make([]policyJSON, 0, len(templates))
	for _, t := range templates {
		layer := layerByID[t.ID]
		if layer == "" {
			layer = "cel"
		}
		result = append(result, policyJSON{
			ID: t.ID, Name: t.Name, Layer: layer,
			Enabled: true, CelExpression: t.Expression, Description: t.Description,
		})
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	if policyExportOut == "-" {
		_, err = fmt.Printf("%s\n", data)
		return err
	}

	if err := os.WriteFile(policyExportOut, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write error: %w", err)
	}
	fmt.Printf("Exported %d policies to %s\n", len(result), policyExportOut)
	return nil
}
