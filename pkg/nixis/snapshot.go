// SPDX-License-Identifier: MIT
package aegis

import (
	policy_types "github.com/mayjain/aegis/pkg/policy/types"
)

// EngineSnapshot is the single immutable evaluation state.
// ONE atomic.Pointer[EngineSnapshot] holds ALL shared state.
// Never use multiple atomic pointers for related state.
// ProgramCache is a value type embedded here — NOT a separate atomic.Pointer.
type EngineSnapshot struct {
	Version uint64 // monotonically increasing; bumped only on successful reload
}

// CompiledBundle is the output of bundle compilation, passed to Engine.Reload().
// Contains parsed policy templates and bindings from YAML files.
// Compiled CEL programs live in ProgramCache inside EngineSnapshot — NOT here.
// CompiledBundle carries raw templates/bindings; PolicyEngine compiles them during Reload().
type CompiledBundle struct {
	Version   uint64
	Hash      [32]byte
	Templates []policy_types.PolicyTemplate
	Bindings  []policy_types.PolicyBinding
}
