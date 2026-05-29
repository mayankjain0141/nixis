// SPDX-License-Identifier: MIT
// Package integration contains end-to-end integration tests that exercise
// all four Phase 4/5 integrations against a real in-process daemon:
//   - Hot-reload watcher (fsnotify + debounce)
//   - OTel instrument registration and evaluation counting
//   - Delegation HTTP API (/api/v1/delegation/list, /api/v1/delegation/revoke)
//   - /healthz structured JSON
//   - gRPC ext_authz server (Envoy Authorization service)
package integration
