package bundle_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mayjain/aegis/internal/bundle"
	"github.com/mayjain/aegis/pkg/aegis"
	policy_types "github.com/mayjain/aegis/pkg/policy/types"
)

// makeSignedBundle creates a tar.gz containing bundle.yaml with policyYAML,
// signs SHA-256(content) with priv, and returns (content, sig).
func makeSignedBundle(t *testing.T, priv ed25519.PrivateKey, policyYAML string) (content []byte, sig []byte) {
	t.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	data := []byte(policyYAML)
	hdr := &tar.Header{
		Name:     "bundle.yaml",
		Mode:     0600,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar WriteHeader: %v", err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatalf("tar Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}

	content = buf.Bytes()
	digest := sha256.Sum256(content)
	sig = ed25519.Sign(priv, digest[:])
	return content, sig
}

// mockEngine is a PolicyReloader that records calls and can inject errors or callbacks.
type mockEngine struct {
	reloadCalls int
	reloadErr   error
	lastBundle  *aegis.CompiledBundle
	reloadFn    func(*aegis.CompiledBundle) // optional callback invoked on each Reload
}

func (m *mockEngine) Reload(_ context.Context, b *aegis.CompiledBundle) error {
	if m.reloadErr != nil {
		return m.reloadErr
	}
	m.reloadCalls++
	m.lastBundle = b
	if m.reloadFn != nil {
		m.reloadFn(b)
	}
	return nil
}

// goodYAML is a minimal valid PolicyTemplate YAML.
const goodYAML = `apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
  name: test-policy
spec:
  description: "Test"
  matchConstraints:
    tools: ["Bash"]
  validations:
    - expression: 'false'
      action: DENY
`

// TestBundle_FSM_StatesExist verifies all 9 activation state constants are distinct strings.
func TestBundle_FSM_StatesExist(t *testing.T) {
	states := []bundle.ActivationState{
		bundle.StateIdle,
		bundle.StateDownloading,
		bundle.StateVerifying,
		bundle.StateStaging,
		bundle.StateCompiling,
		bundle.StateHealthChecking,
		bundle.StateActivating,
		bundle.StateRollback,
		bundle.StateDenyAll,
	}

	seen := make(map[bundle.ActivationState]bool)
	for _, s := range states {
		if string(s) == "" {
			t.Errorf("state constant is empty string")
		}
		if seen[s] {
			t.Errorf("duplicate state value: %q", s)
		}
		seen[s] = true
	}
	if len(seen) != 9 {
		t.Errorf("expected 9 distinct states, got %d", len(seen))
	}
}

// TestBundle_VerifyBeforeParse verifies that a tampered bundle fails signature
// verification and ParsePolicyDir is never called.
func TestBundle_VerifyBeforeParse(t *testing.T) {
	pub, priv := mustGenKey(t)
	content, _ := makeSignedBundle(t, priv, goodYAML)

	// Tamper with the content — flip a byte in the middle
	tampered := make([]byte, len(content))
	copy(tampered, content)
	tampered[len(tampered)/2] ^= 0xFF

	// Recompute the correct sig of the tampered content — use a DIFFERENT key so it fails
	_, wrongPriv := mustGenKey(t)
	digest := sha256.Sum256(tampered)
	badSig := ed25519.Sign(wrongPriv, digest[:])

	storageDir := t.TempDir()
	parseCalled := false

	eng := &mockEngine{}
	cfg := bundle.BundleConfig{
		SourceURL:    "file://" + filepath.Join(t.TempDir(), "bundle.tar.gz"),
		PollInterval: time.Minute,
		TrustedKeys:  []ed25519.PublicKey{pub},
		StorageDir:   storageDir,
		KeepCount:    3,
	}

	bl, err := bundle.NewBundleLoader(cfg, eng)
	if err != nil {
		t.Fatalf("NewBundleLoader: %v", err)
	}

	// Inject a parseDirFn that records if it was called.
	bundle.SetParseDirFn(bl, func(_ string) ([]policy_types.PolicyTemplate, []policy_types.PolicyBinding, error) {
		parseCalled = true
		return nil, nil, nil
	})

	// Drive the loader's verification directly using the exported test helper.
	ok := bundle.VerifyContent(bl, tampered, badSig)
	if ok {
		t.Fatal("expected verification to fail for tampered+wrong-key bundle")
	}
	if parseCalled {
		t.Fatal("ParsePolicyDir must not be called when verification fails")
	}

	// Confirm correct content with the right key verifies.
	digest2 := sha256.Sum256(content)
	goodSig := ed25519.Sign(priv, digest2[:])
	if !bundle.VerifyContent(bl, content, goodSig) {
		t.Fatal("expected verification to succeed for correct content+key")
	}
}

// TestBundle_HealthGate_Rollback verifies that a health gate failure restores the previous bundle.
func TestBundle_HealthGate_Rollback(t *testing.T) {
	_, priv := mustGenKey(t)
	pub := priv.Public().(ed25519.PublicKey)

	content, sig := makeSignedBundle(t, priv, goodYAML)

	// Set up file source
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.tar.gz")
	sigPath := bundlePath + ".sig"
	if err := os.WriteFile(bundlePath, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, sig, 0600); err != nil {
		t.Fatal(err)
	}

	eng := &mockEngine{}
	storageDir := t.TempDir()

	// First activation must succeed so there IS a previous bundle.
	cfg := bundle.BundleConfig{
		SourceURL:    "file://" + bundlePath,
		PollInterval: time.Minute,
		TrustedKeys:  []ed25519.PublicKey{pub},
		StorageDir:   storageDir,
		KeepCount:    3,
	}
	bl, err := bundle.NewBundleLoader(cfg, eng)
	if err != nil {
		t.Fatalf("NewBundleLoader: %v", err)
	}

	// First activation: no test vectors → succeeds, engine called once.
	ctx := context.Background()
	bundle.RunOnce(bl, ctx)
	if eng.reloadCalls != 1 {
		t.Fatalf("expected 1 engine reload after first activation, got %d", eng.reloadCalls)
	}

	// Second activation attempt with a failing health gate.
	// Modify file mtime so the loader sees it as changed.
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(bundlePath, future, future); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(sigPath, future, future); err != nil {
		t.Fatal(err)
	}

	failingVectors := []bundle.TestVector{
		{
			Request:        aegis.CheckRequest{Tool: "Bash"},
			ExpectedAction: aegis.ActionAllow, // will never match deny-all default
		},
	}
	bundle.SetTestVectors(bl, failingVectors)
	bundle.SetEvalFn(bl, func(_ *aegis.CompiledBundle, _ aegis.CheckRequest) aegis.Action {
		return aegis.ActionDeny // always returns deny, expected is allow → mismatch
	})

	bundle.RunOnce(bl, ctx)
	// Engine should still be at 1 call (rollback, not a new activation)
	if eng.reloadCalls != 1 {
		t.Fatalf("expected engine still at 1 reload after health gate failure, got %d", eng.reloadCalls)
	}
	// State should be Idle (rollback with previous bundle available)
	if state := bl.CurrentState(); state != bundle.StateIdle {
		t.Fatalf("expected StateIdle after rollback, got %s", state)
	}
}

// TestBundle_FirstActivation_DenyAll verifies that when the first bundle fails the
// health gate (no previous bundle), the loader enters StateDenyAll.
func TestBundle_FirstActivation_DenyAll(t *testing.T) {
	_, priv := mustGenKey(t)
	pub := priv.Public().(ed25519.PublicKey)

	content, sig := makeSignedBundle(t, priv, goodYAML)

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.tar.gz")
	sigPath := bundlePath + ".sig"
	if err := os.WriteFile(bundlePath, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, sig, 0600); err != nil {
		t.Fatal(err)
	}

	eng := &mockEngine{}
	storageDir := t.TempDir()

	failingVectors := []bundle.TestVector{
		{
			Request:        aegis.CheckRequest{Tool: "Bash"},
			ExpectedAction: aegis.ActionAllow,
		},
	}

	cfg := bundle.BundleConfig{
		SourceURL:    "file://" + bundlePath,
		PollInterval: time.Minute,
		TrustedKeys:  []ed25519.PublicKey{pub},
		StorageDir:   storageDir,
		KeepCount:    3,
		TestVectors:  failingVectors,
	}
	bl, err := bundle.NewBundleLoader(cfg, eng)
	if err != nil {
		t.Fatalf("NewBundleLoader: %v", err)
	}

	bundle.SetEvalFn(bl, func(_ *aegis.CompiledBundle, _ aegis.CheckRequest) aegis.Action {
		return aegis.ActionDeny
	})

	ctx := context.Background()
	bundle.RunOnce(bl, ctx)

	if !bl.IsDenyAll() {
		t.Fatalf("expected IsDenyAll()=true after first activation fails health gate, got state=%s",
			bl.CurrentState())
	}
}

// TestBundle_GC verifies that after 5 activations with KeepCount=3,
// only 3 bundles remain in the storageDir.
func TestBundle_GC(t *testing.T) {
	_, priv := mustGenKey(t)
	pub := priv.Public().(ed25519.PublicKey)

	storageDir := t.TempDir()
	dir := t.TempDir()

	eng := &mockEngine{}
	cfg := bundle.BundleConfig{
		SourceURL:    "file://" + filepath.Join(dir, "bundle.tar.gz"),
		PollInterval: time.Minute,
		TrustedKeys:  []ed25519.PublicKey{pub},
		StorageDir:   storageDir,
		KeepCount:    3,
	}
	bl, err := bundle.NewBundleLoader(cfg, eng)
	if err != nil {
		t.Fatalf("NewBundleLoader: %v", err)
	}

	ctx := context.Background()
	bundlePath := filepath.Join(dir, "bundle.tar.gz")
	sigPath := bundlePath + ".sig"

	for i := 0; i < 5; i++ {
		// Vary the content slightly so each activation has a different hash.
		yaml := goodYAML + "\n# iteration " + string(rune('0'+i))
		content, sig := makeSignedBundle(t, priv, yaml)
		if err := os.WriteFile(bundlePath, content, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sigPath, sig, 0600); err != nil {
			t.Fatal(err)
		}

		// Reset mtime so loader sees it as changed.
		future := time.Now().Add(time.Duration(i+1) * time.Second)
		if err := os.Chtimes(bundlePath, future, future); err != nil {
			t.Fatal(err)
		}
		// Reset loader's lastMtime to force re-fetch.
		bundle.ResetLastMtime(bl)

		bundle.RunOnce(bl, ctx)
		// Brief delay so StoredAt timestamps differ for GC ordering.
		time.Sleep(2 * time.Millisecond)
	}

	count := bundle.StoreCount(bl)
	if count != 3 {
		t.Fatalf("expected 3 bundles after GC with KeepCount=3, got %d", count)
	}
}

// TestBundle_ActivationCallsEngineReload verifies that a successful activation
// calls engine.Reload() with the compiled bundle, not any direct Store().
func TestBundle_ActivationCallsEngineReload(t *testing.T) {
	_, priv := mustGenKey(t)
	pub := priv.Public().(ed25519.PublicKey)

	content, sig := makeSignedBundle(t, priv, goodYAML)

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.tar.gz")
	sigPath := bundlePath + ".sig"
	if err := os.WriteFile(bundlePath, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, sig, 0600); err != nil {
		t.Fatal(err)
	}

	eng := &mockEngine{}
	storageDir := t.TempDir()

	cfg := bundle.BundleConfig{
		SourceURL:    "file://" + bundlePath,
		PollInterval: time.Minute,
		TrustedKeys:  []ed25519.PublicKey{pub},
		StorageDir:   storageDir,
		KeepCount:    3,
	}
	bl, err := bundle.NewBundleLoader(cfg, eng)
	if err != nil {
		t.Fatalf("NewBundleLoader: %v", err)
	}

	ctx := context.Background()
	bundle.RunOnce(bl, ctx)

	if eng.reloadCalls != 1 {
		t.Fatalf("expected engine.Reload called once, got %d", eng.reloadCalls)
	}
	if eng.lastBundle == nil {
		t.Fatal("engine.Reload received nil bundle")
	}
}

// TestBundle_MultiKey verifies that a bundle signed with key #2 of 3 trusted keys verifies successfully.
func TestBundle_MultiKey(t *testing.T) {
	pub1, _ := mustGenKey(t)
	pub2, priv2 := mustGenKey(t)
	pub3, _ := mustGenKey(t)

	content, sig := makeSignedBundle(t, priv2, goodYAML)

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.tar.gz")
	sigPath := bundlePath + ".sig"
	if err := os.WriteFile(bundlePath, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, sig, 0600); err != nil {
		t.Fatal(err)
	}

	eng := &mockEngine{}
	storageDir := t.TempDir()

	cfg := bundle.BundleConfig{
		SourceURL:    "file://" + bundlePath,
		PollInterval: time.Minute,
		TrustedKeys:  []ed25519.PublicKey{pub1, pub2, pub3},
		StorageDir:   storageDir,
		KeepCount:    3,
	}
	bl, err := bundle.NewBundleLoader(cfg, eng)
	if err != nil {
		t.Fatalf("NewBundleLoader: %v", err)
	}

	ctx := context.Background()
	bundle.RunOnce(bl, ctx)

	if eng.reloadCalls != 1 {
		t.Fatalf("expected activation with key #2 of 3, got %d engine reloads", eng.reloadCalls)
	}
}

// TestBundle_FileSource_MtimeDetection verifies file:// mtime-based change detection.
// Unchanged file → no re-activation; modified file → activation triggered.
func TestBundle_FileSource_MtimeDetection(t *testing.T) {
	_, priv := mustGenKey(t)
	pub := priv.Public().(ed25519.PublicKey)

	content, sig := makeSignedBundle(t, priv, goodYAML)

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.tar.gz")
	sigPath := bundlePath + ".sig"
	if err := os.WriteFile(bundlePath, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, sig, 0600); err != nil {
		t.Fatal(err)
	}

	eng := &mockEngine{}
	storageDir := t.TempDir()

	cfg := bundle.BundleConfig{
		SourceURL:    "file://" + bundlePath,
		PollInterval: time.Minute,
		TrustedKeys:  []ed25519.PublicKey{pub},
		StorageDir:   storageDir,
		KeepCount:    3,
	}
	bl, err := bundle.NewBundleLoader(cfg, eng)
	if err != nil {
		t.Fatalf("NewBundleLoader: %v", err)
	}

	ctx := context.Background()

	// First activation — should succeed.
	bundle.RunOnce(bl, ctx)
	if eng.reloadCalls != 1 {
		t.Fatalf("expected 1 reload on first activation, got %d", eng.reloadCalls)
	}

	// Second poll — file unchanged → no re-activation.
	bundle.RunOnce(bl, ctx)
	if eng.reloadCalls != 1 {
		t.Fatalf("expected still 1 reload when file unchanged, got %d", eng.reloadCalls)
	}

	// Modify file mtime — should trigger re-activation.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(bundlePath, future, future); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(sigPath, future, future); err != nil {
		t.Fatal(err)
	}

	bundle.RunOnce(bl, ctx)
	if eng.reloadCalls != 2 {
		t.Fatalf("expected 2 reloads after file mtime change, got %d", eng.reloadCalls)
	}
}

// makeSignedMultiBundle creates a tar.gz containing multiple named YAML files,
// signs SHA-256(content) with priv, and returns (content, sig).
func makeSignedMultiBundle(t *testing.T, priv ed25519.PrivateKey, files map[string]string) (content []byte, sig []byte) {
	t.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for name, yaml := range files {
		data := []byte(yaml)
		hdr := &tar.Header{
			Name:     name,
			Mode:     0600,
			Size:     int64(len(data)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader %s: %v", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("tar Write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}

	content = buf.Bytes()
	digest := sha256.Sum256(content)
	sig = ed25519.Sign(priv, digest[:])
	return content, sig
}

// TestBundle_Parse_LayerField verifies that spec.layer in policy YAML is mapped
// to PolicyBinding.Layer when parsing.
func TestBundle_Parse_LayerField(t *testing.T) {
	ceilingYAML := `apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
  name: ceiling-policy
spec:
  layer: ceiling
  description: "Ceiling layer policy"
  matchConstraints:
    tools: ["Bash"]
  validations:
    - expression: 'false'
      action: DENY
`
	dir := t.TempDir()
	path := filepath.Join(dir, "ceiling.yaml")
	if err := os.WriteFile(path, []byte(ceilingYAML), 0600); err != nil {
		t.Fatal(err)
	}

	_, binding, err := bundle.ParsePolicyFile(path)
	if err != nil {
		t.Fatalf("ParsePolicyFile: %v", err)
	}
	if binding == nil {
		t.Fatal("expected non-nil binding")
	}
	if binding.Layer != bundle.LayerCeiling {
		t.Fatalf("expected Layer=%q, got %q", bundle.LayerCeiling, binding.Layer)
	}

	// Unknown layer falls back to "cel".
	unknownYAML := `apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
  name: unknown-layer-policy
spec:
  layer: bogus
  description: "Unknown layer"
  matchConstraints:
    tools: ["Bash"]
  validations:
    - expression: 'false'
      action: DENY
`
	path2 := filepath.Join(dir, "unknown.yaml")
	if err := os.WriteFile(path2, []byte(unknownYAML), 0600); err != nil {
		t.Fatal(err)
	}
	_, binding2, err := bundle.ParsePolicyFile(path2)
	if err != nil {
		t.Fatalf("ParsePolicyFile: %v", err)
	}
	if binding2 == nil {
		t.Fatal("expected non-nil binding for unknown layer")
	}
	if binding2.Layer != bundle.LayerCEL {
		t.Fatalf("expected unknown layer to fall back to %q, got %q", bundle.LayerCEL, binding2.Layer)
	}
}

// TestBundle_LayerPriorityOrder verifies that after compilation the bindings in
// a CompiledBundle are sorted ceiling → team → project → cel.
func TestBundle_LayerPriorityOrder(t *testing.T) {
	_, priv := mustGenKey(t)
	pub := priv.Public().(ed25519.PublicKey)

	// Build a bundle with policies in deliberately wrong order: cel, project, team, ceiling.
	celYAML := `apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
  name: cel-policy
spec:
  description: "CEL layer"
  matchConstraints:
    tools: ["Bash"]
  validations:
    - expression: 'false'
      action: DENY
`
	projectYAML := `apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
  name: project-policy
spec:
  layer: project
  description: "Project layer"
  matchConstraints:
    tools: ["Bash"]
  validations:
    - expression: 'false'
      action: DENY
`
	teamYAML := `apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
  name: team-policy
spec:
  layer: team
  description: "Team layer"
  matchConstraints:
    tools: ["Bash"]
  validations:
    - expression: 'false'
      action: DENY
`
	ceilingYAML := `apiVersion: aegis.io/v1
kind: PolicyTemplate
metadata:
  name: ceiling-policy
spec:
  layer: ceiling
  description: "Ceiling layer"
  matchConstraints:
    tools: ["Bash"]
  validations:
    - expression: 'false'
      action: DENY
`

	content, sig := makeSignedMultiBundle(t, priv, map[string]string{
		"cel.yaml":     celYAML,
		"project.yaml": projectYAML,
		"team.yaml":    teamYAML,
		"ceiling.yaml": ceilingYAML,
	})

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.tar.gz")
	sigPath := bundlePath + ".sig"
	if err := os.WriteFile(bundlePath, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, sig, 0600); err != nil {
		t.Fatal(err)
	}

	var capturedBundle *aegis.CompiledBundle
	eng := &mockEngine{
		reloadFn: func(b *aegis.CompiledBundle) {
			capturedBundle = b
		},
	}

	storageDir := t.TempDir()
	cfg := bundle.BundleConfig{
		SourceURL:    "file://" + bundlePath,
		PollInterval: time.Minute,
		TrustedKeys:  []ed25519.PublicKey{pub},
		StorageDir:   storageDir,
		KeepCount:    3,
	}
	bl, err := bundle.NewBundleLoader(cfg, eng)
	if err != nil {
		t.Fatalf("NewBundleLoader: %v", err)
	}

	ctx := context.Background()
	bundle.RunOnce(bl, ctx)

	if capturedBundle == nil {
		t.Fatal("engine.Reload was not called — activation failed")
	}
	if len(capturedBundle.Bindings) != 4 {
		t.Fatalf("expected 4 bindings, got %d", len(capturedBundle.Bindings))
	}

	// Verify ordering: ceiling → team → project → cel
	want := []string{
		bundle.LayerCeiling,
		bundle.LayerTeam,
		bundle.LayerProject,
		bundle.LayerCEL,
	}
	for i, b := range capturedBundle.Bindings {
		if b.Layer != want[i] {
			t.Errorf("binding[%d]: expected layer %q, got %q", i, want[i], b.Layer)
		}
	}
}

// TestBundle_KeySource_MultiKey verifies KeySource.Verify() accepts up to 3 keys
// and returns nil-equivalent (true) when any key matches.
func TestBundle_KeySource_MultiKey(t *testing.T) {
	pub1, _ := mustGenKey(t)
	pub2, priv2 := mustGenKey(t)
	pub3, _ := mustGenKey(t)

	ks, err := bundle.NewKeySource(pub1, pub2, pub3)
	if err != nil {
		t.Fatalf("NewKeySource: %v", err)
	}

	msg := []byte("test-message")
	sig := ed25519.Sign(priv2, msg)

	if !ks.Verify(msg, sig) {
		t.Fatal("expected Verify to return true when signed by key #2 of 3")
	}

	// Wrong message should fail.
	if ks.Verify([]byte("wrong"), sig) {
		t.Fatal("expected Verify to return false for wrong message")
	}
}
