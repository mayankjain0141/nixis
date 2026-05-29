// SPDX-License-Identifier: MIT
package cel

import (
	celast "github.com/google/cel-go/common/ast"
)

// countExprDepth recursively walks a CEL AST expression and returns its nesting depth.
// Called only at compile time — NOT on the hot path.
func countExprDepth(expr celast.Expr, current int) int {
	if expr == nil || expr.Kind() == celast.UnspecifiedExprKind {
		return current
	}

	max := current + 1

	switch expr.Kind() {
	case celast.CallKind:
		call := expr.AsCall()
		for _, arg := range call.Args() {
			d := countExprDepth(arg, current+1)
			if d > max {
				max = d
			}
		}
		if call.IsMemberFunction() {
			d := countExprDepth(call.Target(), current+1)
			if d > max {
				max = d
			}
		}
	case celast.SelectKind:
		sel := expr.AsSelect()
		d := countExprDepth(sel.Operand(), current+1)
		if d > max {
			max = d
		}
	case celast.ListKind:
		list := expr.AsList()
		for _, elem := range list.Elements() {
			d := countExprDepth(elem, current+1)
			if d > max {
				max = d
			}
		}
	case celast.MapKind:
		m := expr.AsMap()
		for _, entry := range m.Entries() {
			me := entry.AsMapEntry()
			dk := countExprDepth(me.Key(), current+1)
			if dk > max {
				max = dk
			}
			dv := countExprDepth(me.Value(), current+1)
			if dv > max {
				max = dv
			}
		}
	case celast.ComprehensionKind:
		comp := expr.AsComprehension()
		for _, sub := range []celast.Expr{comp.IterRange(), comp.AccuInit(), comp.LoopCondition(), comp.LoopStep(), comp.Result()} {
			d := countExprDepth(sub, current+1)
			if d > max {
				max = d
			}
		}
	case celast.UnspecifiedExprKind, celast.IdentKind, celast.LiteralKind, celast.StructKind:
		// Leaf nodes or unsupported node types — no children to recurse into.
	}

	return max
}
