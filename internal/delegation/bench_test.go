package delegation_test

import (
	"testing"

	"github.com/mayjain/nixis/internal/delegation"
)

func BenchmarkDelegation_Ceiling(b *testing.B) {
	a := delegation.CapabilitySet{Operations: 0b111, Effects: 0b101, Resources: 0xFFFF, MaxRisk: 10}
	c := delegation.CapabilitySet{Operations: 0b011, Effects: 0b100, Resources: 0xFF00, MaxRisk: 5}

	b.ResetTimer()
	b.ReportAllocs()
	var result delegation.CapabilitySet
	for range b.N {
		result = a.Intersect(c)
	}
	// Prevent the compiler from optimising away the loop.
	if result.Operations == 0 && result.Effects == 0 && result.Resources == 0 {
		b.Fatal("unexpected zero result")
	}
}
