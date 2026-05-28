package classify

import (
	"testing"
)

// TestClassify_SendMessage_HasMessageContent verifies that the SendMessage tool
// classification includes the message_content effect (WS-33 gap closure).
func TestClassify_SendMessage_HasMessageContent(t *testing.T) {
	c := newTestClassifier(t)

	entry, ok := c.Classify("SendMessage")
	if !ok {
		t.Fatal("SendMessage: expected AdapterMatch=true, got false")
	}
	if !effectsContain(entry.Effects, EffectMessageContent) {
		t.Errorf("SendMessage must have EffectMessageContent (%q) in Effects, got %v", EffectMessageContent, entry.Effects)
	}
}
