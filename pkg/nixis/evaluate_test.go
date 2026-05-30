// SPDX-License-Identifier: MIT
package aegis

import (
	"context"
	"testing"
)

// --- mock engines for InProcessEvaluator tests ---

type mockAlwaysAllow struct{}

func (mockAlwaysAllow) Evaluate(_ context.Context, _ CheckRequest) CheckResponse {
	return CheckResponse{
		Decision:       Decision{Action: ActionAllow},
		LatencyNs:      100,
		EnforcingLayer: EnforcingLayerAdapter,
	}
}

type mockAlwaysDeny struct{}

func (mockAlwaysDeny) Evaluate(_ context.Context, _ CheckRequest) CheckResponse {
	return CheckResponse{
		Decision: Decision{
			Action:   ActionDeny,
			Reason:   "always deny",
			PolicyID: "test:deny-all",
		},
		LatencyNs:      200,
		EnforcingLayer: EnforcingLayerCEL,
	}
}

type mockContextAware struct{}

func (mockContextAware) Evaluate(ctx context.Context, _ CheckRequest) CheckResponse {
	if ctx.Err() != nil {
		return CheckResponse{
			Decision: Decision{
				Action: ActionDeny,
				Reason: "context cancelled",
			},
		}
	}
	return CheckResponse{
		Decision: Decision{Action: ActionAllow},
	}
}

func TestInProcessEvaluator_Allow(t *testing.T) {
	t.Parallel()

	eval := NewInProcessEvaluator(mockAlwaysAllow{})
	resp := eval.Check(context.Background(), CheckRequest{
		Tool:      "Read",
		SessionID: "test-session",
	})

	if resp.Decision.Action != ActionAllow {
		t.Errorf("expected ActionAllow, got %d", resp.Decision.Action)
	}
	if resp.LatencyNs != 100 {
		t.Errorf("latency_ns = %d, want 100", resp.LatencyNs)
	}
}

func TestInProcessEvaluator_Deny(t *testing.T) {
	t.Parallel()

	eval := NewInProcessEvaluator(mockAlwaysDeny{})
	resp := eval.Check(context.Background(), CheckRequest{
		Tool:      "Shell",
		SessionID: "test-session",
	})

	if resp.Decision.Action != ActionDeny {
		t.Errorf("expected ActionDeny, got %d", resp.Decision.Action)
	}
	if resp.Decision.Reason != "always deny" {
		t.Errorf("reason = %q, want 'always deny'", resp.Decision.Reason)
	}
	if resp.Decision.PolicyID != "test:deny-all" {
		t.Errorf("policy_id = %q, want 'test:deny-all'", resp.Decision.PolicyID)
	}
}

func TestInProcessEvaluator_ContextCancellation(t *testing.T) {
	t.Parallel()

	eval := NewInProcessEvaluator(mockContextAware{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancel

	resp := eval.Check(ctx, CheckRequest{
		Tool:      "Shell",
		SessionID: "test-session",
	})

	if resp.Decision.Action != ActionDeny {
		t.Errorf("expected ActionDeny on cancelled context, got %d", resp.Decision.Action)
	}
	if resp.Decision.Reason != "context cancelled" {
		t.Errorf("reason = %q, want 'context cancelled'", resp.Decision.Reason)
	}
}
