package nixis_test

import (
	"encoding/json"
	"testing"

	"github.com/mayjain/nixis/pkg/nixis"
)

func TestAction_ZeroValue(t *testing.T) {
	var a nixis.Action
	if a != nixis.ActionDeny {
		t.Fatalf("zero value of Action must be ActionDeny (0), got %d", a)
	}
}

func TestSecurityLabel_ZeroIsMinPrivilege(t *testing.T) {
	var label nixis.SecurityLabel
	if label.Confidentiality != 0 || label.Integrity != 0 || label.Category != 0 {
		t.Fatal("zero-value SecurityLabel must have all fields = 0 (minimum privilege)")
	}
}

func TestAction_MarshalJSON(t *testing.T) {
	cases := []struct {
		action nixis.Action
		want   string
	}{
		{nixis.ActionDeny, `"deny"`},
		{nixis.ActionAllow, `"allow"`},
		{nixis.ActionRequireApproval, `"require_approval"`},
		{nixis.ActionAudit, `"audit"`},
	}
	for _, c := range cases {
		got, err := json.Marshal(c.action)
		if err != nil {
			t.Fatalf("MarshalJSON(%v): %v", c.action, err)
		}
		if string(got) != c.want {
			t.Errorf("MarshalJSON(%v) = %s, want %s", c.action, got, c.want)
		}
	}
}

func TestAction_UnmarshalJSON(t *testing.T) {
	cases := []struct {
		wire string
		want nixis.Action
	}{
		{`"deny"`, nixis.ActionDeny},
		{`"allow"`, nixis.ActionAllow},
		{`"require_approval"`, nixis.ActionRequireApproval},
		{`"audit"`, nixis.ActionAudit},
	}
	for _, c := range cases {
		var a nixis.Action
		if err := json.Unmarshal([]byte(c.wire), &a); err != nil {
			t.Fatalf("UnmarshalJSON(%s): %v", c.wire, err)
		}
		if a != c.want {
			t.Errorf("UnmarshalJSON(%s) = %v, want %v", c.wire, a, c.want)
		}
	}
}

func TestAction_UnmarshalJSON_Unknown(t *testing.T) {
	var a nixis.Action
	if err := json.Unmarshal([]byte(`"unknown"`), &a); err != nil {
		t.Fatalf("UnmarshalJSON(unknown): unexpected error %v", err)
	}
	if a != nixis.ActionDeny {
		t.Errorf("UnmarshalJSON(unknown) = %v, want ActionDeny (fail-secure)", a)
	}
}

func TestDecision_LabelsIsScalar(t *testing.T) {
	d := nixis.Decision{
		Labels: nixis.SecurityLabel{Confidentiality: 1, Integrity: 1},
	}
	_ = d.Labels.Confidentiality
}
