package nixis_test

import (
	"testing"

	"github.com/mayankjain0141/nixis/pkg/nixis"
)

// TestINV_001_ActionDenyIsZeroValue verifies the zero value of Action is ActionDeny (fail-secure).
func TestINV_001_ActionDenyIsZeroValue(t *testing.T) {
	var a nixis.Action
	if a != nixis.ActionDeny {
		t.Fatalf("INV-001 violated: zero value of Action is %d, want ActionDeny (0)", int(a))
	}
}

// TestINV_002_SecurityLabelZeroIsMinPrivilege verifies all SecurityLabel fields are 0 at zero value.
func TestINV_002_SecurityLabelZeroIsMinPrivilege(t *testing.T) {
	var label nixis.SecurityLabel
	if label.Confidentiality != 0 {
		t.Errorf("INV-002 violated: Confidentiality = %d, want 0", label.Confidentiality)
	}
	if label.Integrity != 0 {
		t.Errorf("INV-002 violated: Integrity = %d, want 0", label.Integrity)
	}
	if label.Category != 0 {
		t.Errorf("INV-002 violated: Category = %d, want 0", label.Category)
	}
}
