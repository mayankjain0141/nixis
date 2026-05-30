# Policy Authoring Guide

Nixis policies are YAML files that define what tool calls to intercept and how to evaluate them using [CEL](https://github.com/google/cel-go) (Common Expression Language) expressions.

## Policy File Anatomy

Every policy follows this structure:

```yaml
apiVersion: nixis.io/v1
kind: PolicyTemplate
metadata:
  name: my-policy-name
  annotations:
    nixis.io/default-enabled: "true"   # loaded automatically
    nixis.io/bundle: builtin            # bundle membership
spec:
  description: "Human-readable description"
  matchConstraints:
    tools: ["Bash", "Read", "Edit"]     # which tools this policy applies to
  variables:
    - name: someCondition
      expression: >-
        request.args.command.matches("(?i)dangerous-pattern")
  validations:
    - expression: 'someCondition'
      message: 'Why this was blocked'
      action: DENY
  defaultAction: ALLOW
```

**Key concepts:**

- **matchConstraints** — Which tool names trigger this policy (exact match)
- **variables** — Named CEL expressions evaluated once and reusable in validations
- **validations** — Ordered rules. First matching expression determines the verdict.
- **defaultAction** — What happens if no validation matches (usually ALLOW)

## Actions

| Action | Meaning | Exit behavior |
|--------|---------|---------------|
| `ALLOW` | Tool call proceeds | Hook exits 0 |
| `DENY` | Tool call blocked before execution | Hook exits 2 |
| `REQUIRE_APPROVAL` | Pauses for human confirmation | Prompts user in IDE |
| `AUDIT` | Allows but records to audit trail | Hook exits 0, event logged |

**Design invariant:** The zero-value action is DENY. If the policy engine encounters an error, evaluation failure, or uninitialized state, the default is to block — not to allow.

## CEL Expression Context

Inside CEL expressions, you have access to:

| Field | Type | Description |
|-------|------|-------------|
| `request.tool` | `string` | Tool name (e.g., "Bash", "Read", "Edit", "WebSearch") |
| `request.args` | `map` | Tool arguments as key-value pairs |
| `request.args.command` | `string` | Shell command (for Bash tool) |
| `request.args.path` | `string` | File path (for Read/Edit tools) |
| `request.session_id` | `string` | Current session identifier |
| `request.working_dir` | `string` | Agent's working directory |
| `request.secret_detected` | `bool` | Whether the secret scanner found credentials in args |

**Common CEL patterns:**

```cel
// String matching (regex)
request.args.command.matches("(?i)\\brm\\s+-rf\\b")

// Path checking
request.args.path.startsWith("/etc/") || request.args.path.endsWith(".env")

// Combining conditions
request.args.command.contains("curl") && request.secret_detected

// Negation
!request.args.command.matches("(?i)--dry-run")
```

## Built-In Policies Walkthrough

Nixis ships with 19 policies enabled by default. Here are three that demonstrate different patterns:

### 1. Credential Exfiltration Block

**File:** `policies/builtin/block-credential-exfiltration.yaml`

Blocks `Read` or `Edit` access to sensitive files. Uses multiple variables to categorize credential types:

```yaml
variables:
  - name: isEnvFile
    expression: >-
      request.args.path.matches("(?i)\\.env(\\..*)?$")
  - name: isPrivateKey
    expression: >-
      request.args.path.matches("(?i)\\.(pem|key|p12|pfx|ppk)$") ||
      request.args.path.matches("(?i)(id_rsa|id_ed25519|id_ecdsa)(\\.[a-z]+)?$")
  - name: isCloudCredential
    expression: >-
      request.args.path.matches("(?i)\\.(aws|azure)/credentials") ||
      request.args.path.matches("(?i)\\.gcp/.*\\.json$")
```

### 2. Package Installation Approval

**File:** `policies/builtin/require-approval-package-install.yaml`

New packages need human review (supply chain risk); lockfile installs are just audited:

```yaml
validations:
  - expression: 'isNpmInstallNew'
    message: 'New npm package installation requires approval — verify package legitimacy'
    action: REQUIRE_APPROVAL
  - expression: 'isNpmInstallLockfile || isYarnInstall'
    message: 'Installing from lockfile — audit trail'
    action: AUDIT
```

### 3. Destructive Command Block

**File:** `policies/builtin/block-destructive-commands.yaml`

```yaml
variables:
  - name: isDiskWipe
    expression: >-
      request.args.command.matches("(?i)\\bdd\\b.*if=/dev/(zero|random|urandom).*of=/dev/")
  - name: isForkBomb
    expression: >-
      request.args.command.matches(":\\(\\)\\{.*:\\|:.*\\}") ||
      request.args.command.matches("\\$\\{.*:.*\\|.*:.*\\}")
```

## Writing Your Own Policy

**Step 1:** Create a YAML file in your policy directory:

```bash
touch policies/custom/my-org-rules.yaml
```

**Step 2:** Define the policy. A complete example requiring approval for `git push --force`:

```yaml
apiVersion: nixis.io/v1
kind: PolicyTemplate
metadata:
  name: require-approval-force-push
  annotations:
    nixis.io/default-enabled: "true"
spec:
  description: "Require human approval for git force-push"
  matchConstraints:
    tools: ["Bash"]
  variables:
    - name: isForcePush
      expression: >-
        request.args.command.matches("(?i)\\bgit\\s+push\\b.*--force") ||
        request.args.command.matches("(?i)\\bgit\\s+push\\s+-f\\b")
  validations:
    - expression: 'isForcePush'
      message: 'Force-push requires approval — this rewrites remote history'
      action: REQUIRE_APPROVAL
  defaultAction: ALLOW
```

**Step 3:** Validate it:

```bash
./bin/nixis validate --dir policies/custom/
```

**Step 4:** The daemon hot-reloads automatically (fsnotify). No restart needed.

## Testing Policies

Use `nixis simulate` to dry-run tool calls against the running daemon:

```bash
# Test a force-push (should trigger REQUIRE_APPROVAL)
./bin/nixis simulate Bash --session test-fp \
  --args '{"command": "git push --force origin main"}'

# Test a normal push (should ALLOW)
./bin/nixis simulate Bash --session test-push \
  --args '{"command": "git push origin feature-branch"}'

# Test reading a .env file (should DENY via IFC)
./bin/nixis simulate Read --session test-env \
  --args '{"file_path": "/app/.env.production"}'
```

## Hot Reload

The daemon watches the policy directory using `fsnotify`. When you save a policy file:

1. File change detected
2. All policies re-parsed and CEL expressions re-compiled
3. New policy snapshot atomically swapped in (via `atomic.Pointer.Store()`)
4. In-flight evaluations complete against the old snapshot — no request is ever evaluated against a partially-loaded state

**If a reload fails** (invalid YAML, CEL syntax error), the previous valid snapshot is retained. The daemon logs the error but continues serving with the last-known-good policies.

## Policy Bundles

Policies can be grouped into signed bundles for distribution:

```bash
# Create a bundle from a directory
./bin/nixis bundle create --dir policies/custom/ --output my-org.bundle

# Verify bundle integrity
./bin/nixis bundle verify my-org.bundle
```

## Importing from Other Formats

Nixis can translate policies from OPA/Rego, Kyverno, and Falco formats using an LLM:

```bash
# Requires LITELLM_API_KEY in .env
./bin/nixis policy import --source opa --input my-rego-policy.rego --output policies/imported/
```

This produces Nixis-native YAML that you can review and customize.

## Advanced: Label-Aware Policies

Policies can reference the session's security label for IFC-aware decisions:

```yaml
variables:
  - name: sessionIsTainted
    expression: >-
      request.label.confidentiality > 0
  - name: isNetworkAccess
    expression: >-
      request.args.command.matches("(?i)\\b(curl|wget|nc|ssh)\\b")
validations:
  - expression: 'sessionIsTainted && isNetworkAccess'
    message: 'Network access blocked — session has accessed sensitive data'
    action: DENY
```

Once a session reads sensitive data, it cannot exfiltrate via network — the IFC taint tracks across tool calls regardless of how the network access is phrased.

## Policy File Locations

| Path | Purpose |
|------|---------|
| `policies/builtin/` | Default-enabled policies shipped with Nixis |
| `policies/imported/` | Policies translated from other formats |
| `policies/custom/` | Your organization's custom policies (create this) |

The daemon loads all subdirectories recursively.
