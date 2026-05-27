package adapters_test

import (
	"testing"

	"github.com/mayjain/aegis/pkg/adapters"
)

func TestCatalog_Loads(t *testing.T) {
	defs, err := adapters.Catalog()
	if err != nil {
		t.Fatalf("Catalog(): %v", err)
	}
	if len(defs) < 349 {
		t.Errorf("catalog has %d entries, want >= 349", len(defs))
	}
}

func TestCatalog_CoordinationTools(t *testing.T) {
	defs, _ := adapters.Catalog()
	index := make(map[string]adapters.AdapterDef, len(defs))
	for _, d := range defs {
		index[d.Tool] = d
	}

	coordTools := []string{"TaskCreate", "TaskUpdate", "TaskGet", "TaskList",
		"SendMessage", "TeamCreate", "TeamDelete", "Agent", "Skill", "ExitPlanMode"}
	for _, tool := range coordTools {
		d, ok := index[tool]
		if !ok {
			t.Errorf("coordination tool %q missing from catalog", tool)
			continue
		}
		if d.Family != "claude-code-coordination" {
			t.Errorf("%s: family = %q, want claude-code-coordination", tool, d.Family)
		}
		if d.ResourceType != "agent_coordination" {
			t.Errorf("%s: resource_type = %q, want agent_coordination", tool, d.ResourceType)
		}
	}
}

func TestCatalog_SendMessage_ContentInternal(t *testing.T) {
	defs, _ := adapters.Catalog()
	for _, d := range defs {
		if d.Tool == "SendMessage" {
			for _, e := range d.Effects {
				if e == "content_publish" {
					t.Error("SendMessage must NOT have effect content_publish - use content_internal")
				}
			}
			hasContentInternal := false
			for _, e := range d.Effects {
				if e == "content_internal" {
					hasContentInternal = true
					break
				}
			}
			if !hasContentInternal {
				t.Error("SendMessage must have effect content_internal")
			}
			return
		}
	}
	t.Error("SendMessage not found in catalog")
}

func TestCatalog_NoEmptyTools(t *testing.T) {
	defs, _ := adapters.Catalog()
	for i, d := range defs {
		if d.Tool == "" {
			t.Errorf("entry %d has empty Tool name", i)
		}
		if d.Family == "" {
			t.Errorf("entry %d (%s) has empty Family", i, d.Tool)
		}
	}
}

func TestCatalog_CoordinationToolsRiskLevel(t *testing.T) {
	defs, _ := adapters.Catalog()
	index := make(map[string]adapters.AdapterDef, len(defs))
	for _, d := range defs {
		index[d.Tool] = d
	}

	riskLowTools := []string{"TaskCreate", "TaskUpdate", "SendMessage",
		"TeamCreate", "TeamDelete", "Agent", "Skill"}
	for _, tool := range riskLowTools {
		d, ok := index[tool]
		if !ok {
			continue
		}
		if d.RiskLevel != "low" {
			t.Errorf("%s: risk_level = %q, want low", tool, d.RiskLevel)
		}
	}

	riskNoneTools := []string{"TaskGet", "TaskList", "ExitPlanMode"}
	for _, tool := range riskNoneTools {
		d, ok := index[tool]
		if !ok {
			continue
		}
		if d.RiskLevel != "none" {
			t.Errorf("%s: risk_level = %q, want none", tool, d.RiskLevel)
		}
	}
}

func TestCatalog_CoordinationToolsOperations(t *testing.T) {
	defs, _ := adapters.Catalog()
	index := make(map[string]adapters.AdapterDef, len(defs))
	for _, d := range defs {
		index[d.Tool] = d
	}

	expected := map[string]string{
		"TaskCreate":   "create",
		"TaskUpdate":   "update",
		"TaskGet":      "read",
		"TaskList":     "read",
		"SendMessage":  "publish",
		"TeamCreate":   "create",
		"TeamDelete":   "delete",
		"Agent":        "create",
		"Skill":        "exec",
		"ExitPlanMode": "exec",
	}

	for tool, wantOp := range expected {
		d, ok := index[tool]
		if !ok {
			t.Errorf("coordination tool %q missing from catalog", tool)
			continue
		}
		if d.Operation != wantOp {
			t.Errorf("%s: operation = %q, want %q", tool, d.Operation, wantOp)
		}
	}
}

func TestCatalog_CoordinationToolsEffects(t *testing.T) {
	defs, _ := adapters.Catalog()
	index := make(map[string]adapters.AdapterDef, len(defs))
	for _, d := range defs {
		index[d.Tool] = d
	}

	hasEffect := func(effects []string, e string) bool {
		for _, eff := range effects {
			if eff == e {
				return true
			}
		}
		return false
	}

	if d := index["TaskCreate"]; !hasEffect(d.Effects, "state_change") {
		t.Error("TaskCreate must have state_change effect")
	}
	if d := index["TaskUpdate"]; !hasEffect(d.Effects, "state_change") {
		t.Error("TaskUpdate must have state_change effect")
	}
	if d := index["TaskGet"]; len(d.Effects) != 0 {
		t.Errorf("TaskGet must have no effects, got %v", d.Effects)
	}
	if d := index["TaskList"]; len(d.Effects) != 0 {
		t.Errorf("TaskList must have no effects, got %v", d.Effects)
	}
	if d := index["TeamCreate"]; !hasEffect(d.Effects, "process_coordination") {
		t.Error("TeamCreate must have process_coordination effect")
	}
	if d := index["TeamDelete"]; !hasEffect(d.Effects, "process_coordination") {
		t.Error("TeamDelete must have process_coordination effect")
	}
	if d := index["Agent"]; !hasEffect(d.Effects, "process_coordination") {
		t.Error("Agent must have process_coordination effect")
	}
}
