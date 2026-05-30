package nixis_test

import (
	"testing"

	"github.com/mayjain/nixis/pkg/nixis"
)

// TestExtractScanTarget_SendMessage verifies that the "message" field is extracted
// from SendMessage args, not the full JSON blob.
func TestExtractScanTarget_SendMessage(t *testing.T) {
	args := []byte(`{"to":"teammate","summary":"short","message":"secret content here"}`)
	got := nixis.ExtractScanTarget("SendMessage", args)
	if string(got) != "secret content here" {
		t.Errorf("ExtractScanTarget(SendMessage) = %q, want %q", string(got), "secret content here")
	}
}

// TestExtractScanTarget_SendMessage_InvalidJSON verifies that malformed JSON causes
// the full args to be returned (fail-secure: scan everything).
func TestExtractScanTarget_SendMessage_InvalidJSON(t *testing.T) {
	args := []byte(`not valid json`)
	got := nixis.ExtractScanTarget("SendMessage", args)
	if string(got) != string(args) {
		t.Errorf("ExtractScanTarget(SendMessage, invalid JSON) = %q, want raw args %q", string(got), string(args))
	}
}

// TestExtractScanTarget_Bash verifies that non-SendMessage tools return full args unchanged.
func TestExtractScanTarget_Bash(t *testing.T) {
	args := []byte(`{"command":"echo hello"}`)
	got := nixis.ExtractScanTarget("Bash", args)
	if string(got) != string(args) {
		t.Errorf("ExtractScanTarget(Bash) = %q, want full args %q", string(got), string(args))
	}
}
