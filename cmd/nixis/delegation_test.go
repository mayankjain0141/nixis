package main

import (
	"bytes"
	"testing"
)

// runRevoke calls runDelegationRevoke directly and captures output.
func runRevoke(t *testing.T, chainID string) error {
	t.Helper()
	delegRevokeChainID = chainID
	delegationRevokeCmd.SetOut(&bytes.Buffer{})
	delegationRevokeCmd.SetErr(&bytes.Buffer{})
	return runDelegationRevoke(delegationRevokeCmd, nil)
}

// runList calls runDelegationList directly and captures output.
func runList(t *testing.T) (string, error) {
	t.Helper()
	outBuf := &bytes.Buffer{}
	delegationListCmd.SetOut(outBuf)
	delegationListCmd.SetErr(&bytes.Buffer{})
	err := runDelegationList(delegationListCmd, nil)
	return outBuf.String(), err
}

func TestCLI_DelegationRevoke_NoChainID(t *testing.T) {
	err := runRevoke(t, "")
	if err == nil {
		t.Fatal("expected error for missing --chain-id, got nil")
	}
	if err.Error() != "--chain-id is required" {
		t.Errorf("unexpected error message: %q", err.Error())
	}
}

func TestCLI_DelegationRevoke_DaemonUnreachable(t *testing.T) {
	// Point at an address that has no listener — connection must fail fast.
	origURL := daemonBaseURL
	daemonBaseURL = func() string { return "http://127.0.0.1:19091" }
	defer func() { daemonBaseURL = origURL }()

	err := runRevoke(t, "some-chain-id")
	if err == nil {
		t.Fatal("expected error when daemon is unreachable, got nil")
	}
	if !containsAny(err.Error(), "cannot connect", "connection refused", "dial") {
		t.Errorf("expected connection error, got: %v", err)
	}
}

func TestCLI_DelegationList_DaemonUnreachable(t *testing.T) {
	origURL := daemonBaseURL
	daemonBaseURL = func() string { return "http://127.0.0.1:19091" }
	defer func() { daemonBaseURL = origURL }()

	_, err := runList(t)
	if err == nil {
		t.Fatal("expected error when daemon is unreachable, got nil")
	}
	if !containsAny(err.Error(), "cannot connect", "connection refused", "dial") {
		t.Errorf("expected connection error, got: %v", err)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
