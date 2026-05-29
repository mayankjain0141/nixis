# Contributing to Aegis

Thank you for your interest in contributing. This document covers prerequisites, build steps, and the PR process.

## Prerequisites

- **Go 1.25+** (version pinned in `go.mod`)
- **Node.js 20+** (for the dashboard)
- **golangci-lint** — install via `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest` or follow the [official docs](https://golangci-lint.run/welcome/install/)
- **npm** (bundled with Node.js)

## Building

### Backend (Go daemon + CLI)

```bash
go build ./...
```

### Dashboard (Next.js / React)

```bash
cd dashboard
npm install
npm run build
```

## Running tests

### Backend

```bash
go test -race ./...
```

The race detector is required. Tests that fail under `-race` are not acceptable.

### Dashboard

```bash
cd dashboard
npm run test          # vitest unit tests
npm run type-check    # TypeScript type checking
```

## Linting

### Backend

```bash
golangci-lint run ./...
```

### Dashboard

```bash
cd dashboard
npm run lint
```

## Code style

- **No `//nolint:` directives** in production code. Fix the lint issue instead.
- **No `@ts-ignore` or `eslint-disable`** comments. Fix the type or lint issue instead.
- Go code follows standard `gofmt` formatting (`golangci-lint` enforces this).
- TypeScript code follows the ESLint config in `dashboard/eslint.config.js`.

### A note on `IMPORT_TODO:` markers

Policy files in this repository contain markers like `IMPORT_TODO: <description>`. These are intentional workflow artifacts used by the policy import tooling — they are not bugs or incomplete work. Do not remove or "fix" them.

## Pull request process

1. Fork the repository and create a branch from `main`.
2. Make your changes. Ensure all tests pass and the linter is clean.
3. Open a pull request against `main`. Fill out the PR template.
4. A maintainer will review within a few business days.
5. Once approved, the maintainer will merge.

For significant changes (new features, API changes, architectural decisions), open an issue first to discuss the approach before investing implementation time.

## Commit messages

Use the conventional commits format: `type(scope): description`

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

Example: `fix(evaluator): handle nil resource in CEL context`
