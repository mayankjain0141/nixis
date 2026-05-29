# Security Policy

## Supported Versions

Only the latest release on the `main` branch receives security fixes. Older tags are not backported.

| Version | Supported |
| ------- | --------- |
| latest (main) | Yes |
| older tags | No |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities by email to: **security@mayjain.dev**

Include as much detail as possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected component (daemon, CLI, dashboard, CEL evaluator)
- Any suggested mitigations you have identified

### Response timeline

- **Acknowledgment**: within 48 hours of receipt
- **Initial assessment**: within 5 business days
- **Fix or mitigation**: timeline communicated during initial assessment; critical issues targeted within 14 days

### What to expect

- You will receive a confirmation that your report was received
- We will keep you informed as we investigate and work toward a fix
- We will credit reporters in the release notes unless you prefer to remain anonymous
- There is no bug bounty program — this is an open-source project maintained without commercial backing

### Out of scope

- Vulnerabilities in third-party dependencies (report upstream; we will update our dependency once a fix is available)
- Issues that require physical access to the machine running the daemon
- Denial-of-service via resource exhaustion on policy evaluation (file a regular issue)
