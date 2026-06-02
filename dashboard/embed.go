// SPDX-License-Identifier: MIT
package dashboard

import "embed"

// FS is the pre-built React dashboard, embedded at compile time.
// Build with: cd dashboard && npm run build
//
// The directory is structured as dist/ — callers should use fs.Sub to
// strip the prefix before serving:
//
//	sub, _ := fs.Sub(dashboard.FS, "dist")
//	http.Handle("/", http.FileServer(http.FS(sub)))
//
//go:embed dist
var FS embed.FS
