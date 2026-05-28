package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mayjain/aegis/pkg/aegis"
	policy_types "github.com/mayjain/aegis/pkg/policy/types"
)

// PolicyReloader is the interface that BundleLoader uses to push compiled bundles
// into the policy engine. Defined here to avoid a circular import with internal/policy.
type PolicyReloader interface {
	Reload(ctx context.Context, bundle *aegis.CompiledBundle) error
}

// TestVector is a request/expected-action pair used as a health gate before activation.
type TestVector struct {
	Request        aegis.CheckRequest
	ExpectedAction aegis.Action
}

// BundleConfig configures a BundleLoader.
type BundleConfig struct {
	SourceURL    string        // "file:///path" or "https://..."
	PollInterval time.Duration // default 60s
	TrustedKeys  []ed25519.PublicKey
	StorageDir   string       // content-addressable store dir
	KeepCount    int          // default 3
	TestVectors  []TestVector // optional health gate
}

// parseDirFunc is the signature for the injected parser (for testing).
type parseDirFunc func(dir string) ([]policy_types.PolicyTemplate, []policy_types.PolicyBinding, error)

// evalFunc evaluates a single request against a compiled bundle and returns the action.
// Injected for testing; real health gate uses the compile-and-eval mini path.
type evalFn func(bundle *aegis.CompiledBundle, req aegis.CheckRequest) aegis.Action

// BundleLoader fetches, verifies, compiles, and activates policy bundles.
// It runs a polling loop in Start() and manages the 9-state activation FSM.
type BundleLoader struct {
	cfg    BundleConfig
	engine PolicyReloader
	fsm    *ActivationFSM
	store  *bundleStore
	keys   *KeySource

	// current holds the active manifest (nil until first successful activation).
	current atomic.Pointer[BundleManifest]
	// prevBundle holds the previous compiled bundle for rollback context.
	prevBundle atomic.Pointer[aegis.CompiledBundle]

	// lastEtag is the ETag from the last successful HTTP fetch (conditional GET).
	lastEtag string
	// lastMtime is the mtime recorded at the last file:// source check.
	lastMtime time.Time

	// httpClient is injectable for testing.
	httpClient *http.Client

	// parseDirFn is injectable for testing (defaults to ParsePolicyDir).
	parseDirFn parseDirFunc

	// evalFn evaluates a request for health gate checks; injectable for testing.
	testEvalFn evalFn
}

// NewBundleLoader creates a BundleLoader and validates the config.
func NewBundleLoader(cfg BundleConfig, engine PolicyReloader) (*BundleLoader, error) {
	if cfg.SourceURL == "" {
		return nil, errors.New("bundle: SourceURL is required")
	}
	if len(cfg.TrustedKeys) == 0 {
		return nil, errors.New("bundle: at least one TrustedKey is required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 60 * time.Second
	}
	if cfg.KeepCount <= 0 {
		cfg.KeepCount = 3
	}
	if cfg.StorageDir == "" {
		return nil, errors.New("bundle: StorageDir is required")
	}

	keys, err := NewKeySource(cfg.TrustedKeys...)
	if err != nil {
		return nil, fmt.Errorf("bundle: key source: %w", err)
	}

	store, err := newBundleStore(cfg.StorageDir, cfg.KeepCount)
	if err != nil {
		return nil, fmt.Errorf("bundle: store: %w", err)
	}

	bl := &BundleLoader{
		cfg:        cfg,
		engine:     engine,
		fsm:        NewActivationFSM(),
		store:      store,
		keys:       keys,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	return bl, nil
}

// Start runs the polling loop until ctx is cancelled.
// It attempts one immediate activation on startup, then polls on PollInterval.
func (b *BundleLoader) Start(ctx context.Context) error {
	b.tryActivate(ctx)

	ticker := time.NewTicker(b.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			b.tryActivate(ctx)
		}
	}
}

// CurrentBundle returns the active BundleManifest, or nil if none has activated.
func (b *BundleLoader) CurrentBundle() *BundleManifest {
	return b.current.Load()
}

// CurrentState returns the current FSM state.
func (b *BundleLoader) CurrentState() ActivationState {
	return b.fsm.State()
}

// IsDenyAll returns true when the FSM is in StateDenyAll.
func (b *BundleLoader) IsDenyAll() bool {
	return b.fsm.State() == StateDenyAll
}

// tryActivate runs one full activation attempt through the FSM.
// On error the FSM transitions to Rollback, then either restores the previous
// bundle or enters DenyAll when there is no previous bundle.
func (b *BundleLoader) tryActivate(ctx context.Context) {
	current := b.fsm.State()
	if current == StateDenyAll {
		b.fsm.force(StateIdle)
	} else if current != StateIdle {
		return
	}

	if err := b.fsm.Transition(StateIdle, StateDownloading); err != nil {
		return
	}

	content, sig, changed, err := b.fetch(ctx)
	if err != nil {
		log.Printf("bundle: fetch error: %v", err)
		b.fsm.force(StateIdle)
		return
	}
	if !changed {
		b.fsm.force(StateIdle)
		return
	}

	// VERIFYING — Ed25519 signature check BEFORE any YAML parsing (INV-009)
	if err := b.fsm.Transition(StateDownloading, StateVerifying); err != nil {
		b.rollback()
		return
	}
	digest := sha256.Sum256(content)
	if !b.keys.Verify(digest[:], sig) {
		log.Printf("bundle: signature verification failed")
		b.rollback()
		return
	}
	hashHex := hex.EncodeToString(digest[:])

	// STAGING — extract tar.gz to a temp directory (content already verified)
	if err := b.fsm.Transition(StateVerifying, StateStaging); err != nil {
		b.rollback()
		return
	}
	extractDir, err := extractBundle(content)
	if err != nil {
		log.Printf("bundle: extract failed: %v", err)
		b.rollback()
		return
	}
	defer func() {
		if rmErr := os.RemoveAll(extractDir); rmErr != nil {
			log.Printf("bundle: cleanup extract dir: %v", rmErr)
		}
	}()

	// Persist to content-addressable store after signature verification.
	_, _ = b.store.save(hashHex, content, sig, BundleManifest{
		Hash:     hashHex,
		StoredAt: time.Now(),
	})

	// COMPILING — parse YAML and build CompiledBundle
	if err := b.fsm.Transition(StateStaging, StateCompiling); err != nil {
		b.rollback()
		return
	}
	compiled, policyCount, err := b.compile(extractDir, digest)
	if err != nil {
		log.Printf("bundle: compile failed: %v", err)
		b.rollback()
		return
	}

	// HEALTH_CHECKING — run test vectors against the new bundle
	if err := b.fsm.Transition(StateCompiling, StateHealthChecking); err != nil {
		b.rollback()
		return
	}
	if err := b.healthCheck(compiled); err != nil {
		log.Printf("bundle: health gate failed: %v", err)
		b.rollback()
		return
	}

	// ACTIVATING — push to engine
	if err := b.fsm.Transition(StateHealthChecking, StateActivating); err != nil {
		b.rollback()
		return
	}
	if err := b.engine.Reload(ctx, compiled); err != nil {
		log.Printf("bundle: engine reload failed: %v", err)
		b.rollback()
		return
	}

	// GC old bundles from the store.
	_ = b.store.gc()

	// Store manifest and mark current as the new previous for future rollbacks.
	manifest := &BundleManifest{
		Hash:        hashHex,
		Version:     compiled.Version,
		PolicyCount: policyCount,
		StoredAt:    time.Now(),
	}
	b.current.Store(manifest)
	b.prevBundle.Store(compiled)

	log.Printf("bundle.activated: version=%d hash=%s policy_count=%d",
		compiled.Version, hashHex, policyCount)

	b.fsm.force(StateIdle)
}

// fetch retrieves bundle content and its signature from the configured source.
// Returns (content, sig, changed, err). changed=false means the source is unmodified.
func (b *BundleLoader) fetch(ctx context.Context) (content, sig []byte, changed bool, err error) {
	if strings.HasPrefix(b.cfg.SourceURL, "file://") {
		return b.fetchFile()
	}
	return b.fetchHTTP(ctx)
}

func (b *BundleLoader) fetchFile() (content, sig []byte, changed bool, err error) {
	path := strings.TrimPrefix(b.cfg.SourceURL, "file://")

	info, statErr := os.Stat(path)
	if statErr != nil {
		return nil, nil, false, fmt.Errorf("bundle file stat: %w", statErr)
	}

	if !b.lastMtime.IsZero() && !info.ModTime().After(b.lastMtime) {
		return nil, nil, false, nil
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		return nil, nil, false, fmt.Errorf("bundle file read: %w", readErr)
	}

	sigPath := path + ".sig"
	sigData, sigErr := os.ReadFile(sigPath)
	if sigErr != nil {
		return nil, nil, false, fmt.Errorf("bundle sig read: %w", sigErr)
	}

	b.lastMtime = info.ModTime()
	return data, sigData, true, nil
}

func (b *BundleLoader) fetchHTTP(ctx context.Context) (content, sig []byte, changed bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.cfg.SourceURL, nil)
	if err != nil {
		return nil, nil, false, fmt.Errorf("bundle http request: %w", err)
	}
	if b.lastEtag != "" {
		req.Header.Set("If-None-Match", b.lastEtag)
	}

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, nil, false, fmt.Errorf("bundle http fetch: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("bundle: close response body: %v", closeErr)
		}
	}()

	if resp.StatusCode == http.StatusNotModified {
		return nil, nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, false, fmt.Errorf("bundle http: unexpected status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, false, fmt.Errorf("bundle http read body: %w", err)
	}

	sigReq, err := http.NewRequestWithContext(ctx, http.MethodGet, b.cfg.SourceURL+".sig", nil)
	if err != nil {
		return nil, nil, false, fmt.Errorf("bundle http sig request: %w", err)
	}
	sigResp, err := b.httpClient.Do(sigReq)
	if err != nil {
		return nil, nil, false, fmt.Errorf("bundle http sig fetch: %w", err)
	}
	defer func() {
		if closeErr := sigResp.Body.Close(); closeErr != nil {
			log.Printf("bundle: close sig response body: %v", closeErr)
		}
	}()

	sigData, err := io.ReadAll(sigResp.Body)
	if err != nil {
		return nil, nil, false, fmt.Errorf("bundle http sig read: %w", err)
	}

	b.lastEtag = resp.Header.Get("ETag")
	return data, sigData, true, nil
}

// compile parses the extracted bundle directory and builds a CompiledBundle.
func (b *BundleLoader) compile(dir string, digest [32]byte) (*aegis.CompiledBundle, int, error) {
	parseFn := b.parseDirFn
	if parseFn == nil {
		parseFn = ParsePolicyDir
	}

	templates, bindings, err := parseFn(dir)
	if err != nil {
		return nil, 0, fmt.Errorf("bundle parse: %w", err)
	}

	// Sort bindings by layer priority: ceiling(0) → team(1) → project(2) → cel(3).
	// This ensures ceiling-layer DENY decisions fire before lower layers can allow,
	// implementing the hierarchical policy merge without engine changes.
	sort.SliceStable(bindings, func(i, j int) bool {
		pi, ok := LayerPriority[bindings[i].Layer]
		if !ok {
			pi = LayerPriority[LayerCEL]
		}
		pj, ok := LayerPriority[bindings[j].Layer]
		if !ok {
			pj = LayerPriority[LayerCEL]
		}
		return pi < pj
	})

	prev := b.prevBundle.Load()
	version := uint64(1)
	if prev != nil {
		version = prev.Version + 1
	}

	compiled := &aegis.CompiledBundle{
		Version:   version,
		Hash:      digest,
		Templates: templates,
		Bindings:  bindings,
	}
	return compiled, len(templates), nil
}

// healthCheck runs each TestVector against the compiled bundle.
// Returns an error if any vector's actual action differs from expected.
func (b *BundleLoader) healthCheck(compiled *aegis.CompiledBundle) error {
	if len(b.cfg.TestVectors) == 0 {
		return nil
	}

	evalFn := b.testEvalFn
	if evalFn == nil {
		return errors.New("bundle: health gate requires testEvalFn when TestVectors are set")
	}

	for i, tv := range b.cfg.TestVectors {
		got := evalFn(compiled, tv.Request)
		if got != tv.ExpectedAction {
			return fmt.Errorf("health gate vector %d: expected %v, got %v", i, tv.ExpectedAction, got)
		}
	}
	return nil
}

// rollback restores the previous state or enters DenyAll when there is no previous bundle.
func (b *BundleLoader) rollback() {
	b.fsm.force(StateRollback)

	if b.prevBundle.Load() == nil {
		b.fsm.force(StateDenyAll)
		return
	}

	// Previous bundle is already live in the engine; just reset to Idle.
	b.fsm.force(StateIdle)
}

// extractBundle extracts a tar.gz archive from content into a temp directory.
// Returns the path of the temp directory. Caller must remove it when done.
func extractBundle(content []byte) (string, error) {
	dir, err := os.MkdirTemp("", "aegis-bundle-*")
	if err != nil {
		return "", fmt.Errorf("extract: mkdtemp: %w", err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("extract: gzip: %w", err)
	}
	defer func() {
		if closeErr := gr.Close(); closeErr != nil {
			log.Printf("bundle: close gzip reader: %v", closeErr)
		}
	}()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = os.RemoveAll(dir)
			return "", fmt.Errorf("extract: tar next: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := hdr.Name
		if strings.Contains(name, "..") {
			continue
		}
		destPath := fmt.Sprintf("%s/%s", dir, name)
		fileData, err := io.ReadAll(tr)
		if err != nil {
			_ = os.RemoveAll(dir)
			return "", fmt.Errorf("extract: read %s: %w", name, err)
		}
		if err := os.WriteFile(destPath, fileData, 0600); err != nil {
			_ = os.RemoveAll(dir)
			return "", fmt.Errorf("extract: write %s: %w", name, err)
		}
	}
	return dir, nil
}
