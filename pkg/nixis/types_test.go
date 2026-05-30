package aegis_test

import (
	"encoding/json"
	"testing"

	"github.com/mayjain/aegis/pkg/aegis"
)

func TestAction_ZeroValue(t *testing.T) {
	var a aegis.Action
	if a != aegis.ActionDeny {
		t.Fatalf("zero value of Action must be ActionDeny (0), got %d", a)
	}
}

func TestSecurityLabel_ZeroIsMinPrivilege(t *testing.T) {
	var label aegis.SecurityLabel
	if label.Confidentiality != 0 || label.Integrity != 0 || label.Category != 0 {
		t.Fatal("zero-value SecurityLabel must have all fields = 0 (minimum privilege)")
	}
}

func TestAction_MarshalJSON(t *testing.T) {
	cases := []struct {
		action aegis.Action
		want   string
	}{
		{aegis.ActionDeny, `"deny"`},
		{aegis.ActionAllow, `"allow"`},
		{aegis.ActionRequireApproval, `"require_approval"`},
		{aegis.ActionAudit, `"audit"`},
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
		want aegis.Action
	}{
		{`"deny"`, aegis.ActionDeny},
		{`"allow"`, aegis.ActionAllow},
		{`"require_approval"`, aegis.ActionRequireApproval},
		{`"audit"`, aegis.ActionAudit},
	}
	for _, c := range cases {
		var a aegis.Action
		if err := json.Unmarshal([]byte(c.wire), &a); err != nil {
			t.Fatalf("UnmarshalJSON(%s): %v", c.wire, err)
		}
		if a != c.want {
			t.Errorf("UnmarshalJSON(%s) = %v, want %v", c.wire, a, c.want)
		}
	}
}

func TestAction_UnmarshalJSON_Unknown(t *testing.T) {
	var a aegis.Action
	if err := json.Unmarshal([]byte(`"unknown"`), &a); err != nil {
		t.Fatalf("UnmarshalJSON(unknown): unexpected error %v", err)
	}
	if a != aegis.ActionDeny {
		t.Errorf("UnmarshalJSON(unknown) = %v, want ActionDeny (fail-secure)", a)
	}
}

func TestDecision_LabelsIsScalar(t *testing.T) {
	d := aegis.Decision{
		Labels: aegis.SecurityLabel{Confidentiality: 1, Integrity: 1},
	}
	_ = d.Labels.Confidentiality
}
