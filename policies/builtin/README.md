# Built-in Policy Bundle

This directory contains the Nixis built-in policy bundle. All policies here are Ed25519-signed and loaded at daemon startup. **Project-level policies cannot override or disable built-in policies.**

## Policies

| File | Default | Behavior |
|------|---------|----------|
| `git-branch-protection.yaml` | **ENABLED** | DENY deletion/force-push of protected branches; REQUIRE_APPROVAL for other branch deletions; ALLOW for safe branches (worktree-*, feature/*, etc.) |
| `dev-port-cleanup.yaml` | AUDIT | AUDIT kills on known dev ports (3000, 3001, 5173, 7474, 8000, 8080, 9000); REQUIRE_APPROVAL for other ports |
| `cross-project-credential-access.yaml` | ALLOW | REQUIRE_APPROVAL for credential-pattern file searches outside the current project root; ALLOW within project |
| `localhost-api-testing.yaml` | AUDIT | AUDIT API key use against localhost/loopback; REQUIRE_APPROVAL against external endpoints. **Bundle-only: cannot be modified at project level.** |

## Signing and Integrity

Built-in policies are Ed25519-signed as part of the bundle distribution. The daemon verifies the signature at startup and rejects any tampered or unsigned bundle. This prevents project-level config modifications from affecting these controls.

## Bundle-Only Restriction

`localhost-api-testing.yaml` carries the `nixis.io/builtin-only: "true"` annotation. It cannot be overridden, disabled, or replicated at project level. Any project-level policy containing `skipTaint: true` will fail policy validation — this directive is banned per FINAL_SPEC_HARDENING.md P1-3.

## Taint Behavior

Taint propagation is independent of policy verdicts. When a secret is detected in a command (e.g., an `sk-...` API key), the session is tainted regardless of whether the verdict is ALLOW, AUDIT, or REQUIRE_APPROVAL. The localhost exception in `localhost-api-testing.yaml` controls verdict only, not taint.

## Reference

See `docs/FINAL_SPEC_HARDENING.md` for authoritative behavior specifications, including edge cases, blind spots, and accepted limitations for each policy.
