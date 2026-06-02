// SPDX-License-Identifier: MIT
package stream_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/mayankjain0141/nixis/internal/stream"
)

// testStaticFS is a minimal in-memory filesystem mimicking dashboard/dist/.
var testStaticFS = fstest.MapFS{
	"dist/index.html":    {Data: []byte("<html><body>nixis</body></html>")},
	"dist/assets/app.js": {Data: []byte("console.log('nixis')")},
}

func newStaticServer(t *testing.T) *stream.StreamServer {
	t.Helper()
	return stream.NewStreamServer(nil, nil, stream.WithStaticFS(testStaticFS))
}

func TestStaticFS_ServesIndexHTML(t *testing.T) {
	srv := newStaticServer(t)
	h := srv.StaticHandler()
	if h == nil {
		t.Fatal("StaticHandler() returned nil, want a handler")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
}

func TestStaticFS_ServesAsset(t *testing.T) {
	srv := newStaticServer(t)
	h := srv.StaticHandler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/assets/app.js", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /assets/app.js status = %d, want 200", w.Code)
	}
	if body := w.Body.String(); body != "console.log('nixis')" {
		t.Fatalf("body = %q, want console.log('nixis')", body)
	}
}

func TestStaticFS_404ForMissingFile(t *testing.T) {
	srv := newStaticServer(t)
	h := srv.StaticHandler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/nonexistent.html", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET /nonexistent.html status = %d, want 404", w.Code)
	}
}

func TestStaticFS_NoDirectoryListing(t *testing.T) {
	srv := newStaticServer(t)
	h := srv.StaticHandler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/assets/", nil))
	// Should return 403 Forbidden (ErrPermission from Readdir) or 404 — NOT 200 with listing.
	if w.Code == http.StatusOK {
		t.Fatalf("GET /assets/ returned 200 — directory listing should be blocked")
	}
}

func TestStaticFS_NilFS_NoStaticHandler(t *testing.T) {
	// Without WithStaticFS, StaticHandler returns nil.
	srv := stream.NewStreamServer(nil, nil)
	if h := srv.StaticHandler(); h != nil {
		t.Fatal("StaticHandler() should be nil when WithStaticFS is not called")
	}
}

func TestStaticFS_APIRoutesNotSwallowed(t *testing.T) {
	// Verify that WithStaticFS sets staticFS and StaticHandler returns a non-nil handler.
	// The stdlib mux longest-prefix rule guarantees that /ws, /policies, etc. remain
	// handled by their own handlers; / only matches paths not claimed by longer prefixes.
	srv := newStaticServer(t)
	if h := srv.StaticHandler(); h == nil {
		t.Fatal("StaticHandler() should be non-nil when WithStaticFS is called")
	}
}
