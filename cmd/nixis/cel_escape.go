// SPDX-License-Identifier: MIT
package main

import (
	"fmt"
	"strings"

	nixisCEL "github.com/mayankjain0141/nixis/internal/cel"
)

// validateOrFixExpr checks whether expr compiles (after normalization). If it does,
// it returns expr unchanged. If not, it applies fixCELEscaping and tries again.
// Returns the valid expression, or "" if both attempts fail (logged to stderr).
func validateOrFixExpr(expr, fname string) string {
	env, err := nixisCEL.NewCELEnvironment()
	if err != nil {
		return expr // environment failure is not an expression problem; pass through
	}
	rawEnv := nixisCEL.RawEnv(env)

	normalised := normaliseCELExprForFix(expr)
	_, issues := rawEnv.Parse(normalised)
	if issues == nil || issues.Err() == nil {
		return expr
	}

	fixed := fixCELEscaping(expr)
	normalisedFixed := normaliseCELExprForFix(fixed)
	_, fixIssues := rawEnv.Parse(normalisedFixed)
	if fixIssues == nil || fixIssues.Err() == nil {
		return fixed
	}

	fmt.Printf("[SKIP] %s — CEL still invalid after fix: %v\n", fname, fixIssues.Err())
	return ""
}

// fixCELEscaping repairs invalid escape sequences inside CEL double-quoted string literals
// within an expression. Any \X sequence where X is not \ or " is doubled to \\X, which
// preserves the intended regex/value character when CEL evaluates the string.
//
// Conservative rule: only \\ and \" are kept as-is inside double-quoted strings.
// All other \X (including \s, \., \b, \n, \t for regex patterns) are doubled to \\X
// so RE2 receives the intended two-character escape sequence.
func fixCELEscaping(expr string) string {
	var result strings.Builder
	result.Grow(len(expr))
	i := 0
	inDQ := false
	for i < len(expr) {
		ch := expr[i]
		switch {
		case ch == '"' && !inDQ:
			inDQ = true
			result.WriteByte(ch)
			i++
		case ch == '"' && inDQ:
			inDQ = false
			result.WriteByte(ch)
			i++
		case inDQ && ch == '\\' && i+1 < len(expr):
			next := expr[i+1]
			if next == '\\' || next == '"' {
				// Already a valid CEL escape — keep as-is.
				result.WriteByte('\\')
				result.WriteByte(next)
				i += 2
			} else {
				// Invalid CEL escape (e.g., \., \s in regex patterns).
				// Double the backslash so RE2 receives the intended char.
				result.WriteByte('\\')
				result.WriteByte('\\')
				result.WriteByte(next)
				i += 2
			}
		default:
			result.WriteByte(ch)
			i++
		}
	}
	return result.String()
}
