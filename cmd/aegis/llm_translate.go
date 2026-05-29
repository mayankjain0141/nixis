// SPDX-License-Identifier: MIT
package main

// LLMTranslator calls the Claude API to translate policy snippets to CEL.
// It uses a repair loop: if cel-go compilation fails, it sends the error back
// to the LLM to fix, up to maxRetries attempts total.
//
// The disk cache stores successful translations keyed by SHA-256(input) so
// repeated imports of the same snippet never make a network call.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	aegisCEL "github.com/mayjain/aegis/internal/cel"
)

// anthropicURL is the endpoint for Claude API calls. Overridable in tests.
var anthropicURL = "https://api.anthropic.com/v1/messages"

// llmSystemPrompt is the invariant part of every translation request.
const llmSystemPrompt = `You are a policy translator for Aegis, a security governance system for AI agents.
Convert the given policy snippet to a CEL (Common Expression Language) expression.

Available CEL variables:
- tool (string): the tool being called, e.g. "Bash", "Read", "Write", "WebFetch"
- request.args (map<string, any>): tool arguments
  - request.args.command (string): for Bash tool
  - request.args.path (string): for Read/Write/Edit tools
  - request.args.url (string): for WebFetch tool
  - request.args.content (string): for Write/Edit tools
- request.session_id (string): session identifier

Available custom CEL functions:
- bash.isGitForcePush(command string) bool
- bash.isGitBranchDelete(command string) bool
- bash.gitBranchTarget(command string) string

CEL expression must evaluate to true when the policy should DENY/trigger.
Return ONLY the CEL expression, no explanation, no markdown, no quotes.

Examples:
Input: "Block rm -rf commands"
Output: tool == "Bash" && request.args.command.matches("rm\\s+-rf")

Input: "Block access to .env files"
Output: (tool == "Read" || tool == "Write" || tool == "Edit") && request.args.path.matches("(?i)\\.env$")

Input: "Block force push to main branch"
Output: tool == "Bash" && bash.isGitForcePush(request.args.command) && bash.gitBranchTarget(request.args.command).matches("(?i)^(main|master)$")`

// anthropicRequest is the JSON body for a Claude API call.
type anthropicRequest struct {
	Model            string             `json:"model,omitempty"`
	MaxTokens        int                `json:"max_tokens"`
	System           string             `json:"system"`
	Messages         []anthropicMessage `json:"messages"`
	AnthropicVersion string             `json:"anthropic_version,omitempty"`
}

// anthropicMessage is one message in the conversation.
type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// anthropicResponse is the minimal subset of the Claude API response we parse.
type anthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
}

// translationCacheEntry is the format stored in ~/.aegis/import-cache/<hash>.json.
type translationCacheEntry struct {
	InputHash       string    `json:"input_hash"`
	SourceFormat    string    `json:"source_format"`
	SourceSnippet   string    `json:"source_snippet"`
	CELExpression   string    `json:"cel_expression"`
	Attempts        int       `json:"attempts"`
	Model           string    `json:"model"`
	TranslatedAt    time.Time `json:"translated_at"`
	CompileVerified bool      `json:"compile_verified"`
}

// LLMTranslator translates opaque policy snippets to CEL using the Claude API.
type LLMTranslator struct {
	model         string
	maxRetries    int
	apiKey        string
	vertexProject string
	vertexRegion  string
	cacheDir      string
	celEnv        *aegisCEL.CELEnvironment
}

// NewLLMTranslator constructs an LLMTranslator. It returns an error only if the
// CEL environment cannot be initialised (which indicates a hard programming error).
// A missing ANTHROPIC_API_KEY is NOT an error here — Translate() will warn and skip.
func NewLLMTranslator(model string, maxRetries int) (*LLMTranslator, error) {
	celEnv, err := aegisCEL.NewCELEnvironment()
	if err != nil {
		return nil, fmt.Errorf("llm-translate: create CEL environment: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	cacheDir := filepath.Join(home, ".aegis", "import-cache")

	return &LLMTranslator{
		model:         model,
		maxRetries:    maxRetries,
		apiKey:        os.Getenv("ANTHROPIC_API_KEY"),
		vertexProject: os.Getenv("ANTHROPIC_VERTEX_PROJECT_ID"),
		vertexRegion:  os.Getenv("CLOUD_ML_REGION"),
		cacheDir:      cacheDir,
		celEnv:        celEnv,
	}, nil
}

// Translate converts snippet (a natural-language or format-specific policy fragment)
// into a CEL expression. sourceFormat is included in the prompt and cache entry for
// traceability (e.g. "opa-gatekeeper", "sigma", "falco").
//
// Returns (celExpr, attempts, nil) on success.
// Returns ("", 0, err) if the API key is missing, the API is unreachable, or all
// retries are exhausted — in which case the caller should fall back to IMPORT_TODO.
//
// Translate is NOT safe for concurrent calls on the same LLMTranslator (cache reads
// and writes are not locked). Import commands run single-threaded, so this is fine.
func (t *LLMTranslator) Translate(ctx context.Context, snippet, sourceFormat string) (celExpr string, attempts int, err error) {
	if t.apiKey == "" && t.vertexProject == "" {
		return "", 0, fmt.Errorf("ANTHROPIC_API_KEY not set — skipping LLM translation")
	}

	// Check the disk cache first.
	hash := snippetHash(snippet, sourceFormat)
	if cached, ok := t.loadCache(hash); ok {
		return cached.CELExpression, cached.Attempts, nil
	}

	// Build the initial user message.
	userMsg := buildInitialPrompt(snippet, sourceFormat)

	var (
		lastExpr  string
		lastError string
	)

	for attempt := 1; attempt <= t.maxRetries; attempt++ {
		var msgContent string
		if attempt == 1 {
			msgContent = userMsg
		} else {
			msgContent = buildRepairPrompt(lastError, lastExpr, snippet)
		}

		expr, callErr := t.callAPI(ctx, msgContent)
		if callErr != nil {
			return "", attempt, fmt.Errorf("LLM API call failed (attempt %d): %w", attempt, callErr)
		}
		expr = strings.TrimSpace(expr)

		// Validate the expression by normalising and parsing with the CEL environment.
		compileErr := t.validateExpression(expr)
		if compileErr == nil {
			// Success — persist to cache and return.
			t.saveCache(translationCacheEntry{
				InputHash:       hash,
				SourceFormat:    sourceFormat,
				SourceSnippet:   snippet,
				CELExpression:   expr,
				Attempts:        attempt,
				Model:           t.model,
				TranslatedAt:    time.Now().UTC(),
				CompileVerified: true,
			})
			return expr, attempt, nil
		}

		lastExpr = expr
		lastError = compileErr.Error()
	}

	return "", t.maxRetries, fmt.Errorf("CEL compile failed after %d attempts: %s", t.maxRetries, lastError)
}

// callAPI sends one message turn to the Claude API and returns the text response.
// It enforces a 30-second timeout (respecting the parent context).
// When ANTHROPIC_API_KEY is set it uses the direct API; otherwise it falls back
// to Vertex AI using a Bearer token from `gcloud auth print-access-token`.
func (t *LLMTranslator) callAPI(ctx context.Context, userContent string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var (
		endpoint     string
		authKey      string
		authVal      string
		anthropicVer string
		bodyModel    string
	)

	if t.apiKey != "" {
		endpoint = anthropicURL
		authKey = "x-api-key"
		authVal = t.apiKey
		anthropicVer = "2023-06-01"
		bodyModel = t.model
	} else {
		// Vertex AI path — get a Bearer token via gcloud.
		out, tokenErr := exec.CommandContext(reqCtx, "gcloud", "auth", "print-access-token").Output()
		if tokenErr != nil {
			return "", fmt.Errorf("gcloud auth print-access-token: %w", tokenErr)
		}
		token := strings.TrimSpace(string(out))

		// Vertex AI uses a fixed region for Anthropic models; "global" is not a valid location.
		region := t.vertexRegion
		if region == "" || region == "global" {
			region = "us-east5"
		}
		// Vertex AI model IDs use "@" separator (e.g. claude-haiku-4-5@20251001).
		vertexModel := vertexModelID(t.model)
		endpoint = fmt.Sprintf("https://%s-aiplatform.googleapis.com/v1/projects/%s/locations/%s/publishers/anthropic/models/%s:rawPredict",
			region, t.vertexProject, region, vertexModel)
		authKey = "Authorization"
		authVal = "Bearer " + token
		anthropicVer = "vertex-2023-10-16"
		bodyModel = "" // Vertex AI reads model from the URL path
	}

	body := anthropicRequest{
		Model:            bodyModel,
		MaxTokens:        512,
		System:           llmSystemPrompt,
		AnthropicVersion: anthropicVer,
		Messages: []anthropicMessage{
			{Role: "user", Content: userContent},
		},
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set(authKey, authVal)
	req.Header.Set("anthropic-version", anthropicVer)
	req.Header.Set("content-type", "application/json")

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, truncateStr(string(respBody), 200))
	}

	var apiResp anthropicResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	if len(apiResp.Content) == 0 || apiResp.Content[0].Text == "" {
		return "", fmt.Errorf("empty response from API")
	}

	return apiResp.Content[0].Text, nil
}

// validateExpression normalises a policy-YAML expression (which may use request.args.* notation)
// and attempts to parse it with the CEL environment. Returns nil if the expression is valid.
//
// Normalisation matches what internal/bundle/parse.go does at policy load time:
//   - request.args.command → args["command"]
//   - request.args         → args
func (t *LLMTranslator) validateExpression(expr string) error {
	normalised := normaliseCELExpr(expr)
	rawEnv := aegisCEL.RawEnv(t.celEnv)
	_, issues := rawEnv.Parse(normalised)
	if issues != nil && issues.Err() != nil {
		return issues.Err()
	}
	return nil
}

// normaliseCELExpr applies the same rewriting that bundle/parse.go performs so that
// expressions using the human-friendly request.args.* notation can be compiled against
// the actual CEL environment which declares the flat variable `args`.
func normaliseCELExpr(expr string) string {
	// Order matters: replace the more-specific prefix before the shorter one.
	expr = strings.ReplaceAll(expr, "request.args.command", `args["command"]`)
	expr = strings.ReplaceAll(expr, "request.args.path", `args["path"]`)
	expr = strings.ReplaceAll(expr, "request.args.url", `args["url"]`)
	expr = strings.ReplaceAll(expr, "request.args.content", `args["content"]`)
	expr = strings.ReplaceAll(expr, "request.args.query", `args["query"]`)
	expr = strings.ReplaceAll(expr, "request.args", "args")
	expr = strings.ReplaceAll(expr, "request.session_id", "session_id")
	return expr
}

// buildInitialPrompt constructs the first user message for a translation request.
func buildInitialPrompt(snippet, sourceFormat string) string {
	if sourceFormat != "" {
		return fmt.Sprintf("Source format: %s\nPolicy snippet to translate:\n%s", sourceFormat, snippet)
	}
	return fmt.Sprintf("Policy snippet to translate:\n%s", snippet)
}

// buildRepairPrompt constructs the follow-up message when CEL compilation failed.
func buildRepairPrompt(compileError, failedExpr, originalSnippet string) string {
	return fmt.Sprintf(
		"The CEL expression you generated failed to compile with this error:\n%s\n\nFailed expression:\n%s\n\nOriginal policy to translate:\n%s\n\nFix the CEL expression. Return ONLY the corrected CEL expression, no explanation.",
		compileError, failedExpr, originalSnippet,
	)
}

// snippetHash returns the hex SHA-256 of "format\x00snippet" for cache keying.
func snippetHash(snippet, sourceFormat string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, sourceFormat)
	h.Write([]byte{0})
	_, _ = io.WriteString(h, snippet)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// loadCache reads a cached translation from disk. Returns (entry, true) on hit.
func (t *LLMTranslator) loadCache(hash string) (translationCacheEntry, bool) {
	path := filepath.Join(t.cacheDir, hash+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return translationCacheEntry{}, false
	}
	var entry translationCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return translationCacheEntry{}, false
	}
	return entry, true
}

// saveCache writes a translation cache entry to disk. Errors are silently ignored
// because a cache miss is always recoverable by calling the API again.
func (t *LLMTranslator) saveCache(entry translationCacheEntry) {
	if err := os.MkdirAll(t.cacheDir, 0700); err != nil {
		return
	}
	path := filepath.Join(t.cacheDir, entry.InputHash+".json")
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0600)
}

// vertexModelID converts a standard Claude model ID to the Vertex AI format.
// Vertex AI uses "@" as the separator before the date suffix rather than "-".
// e.g. "claude-haiku-4-5-20251001" → "claude-haiku-4-5@20251001"
func vertexModelID(model string) string {
	// Date suffixes are 8-digit strings; replace the last "-YYYYMMDD" with "@YYYYMMDD".
	if len(model) > 9 {
		suffix := model[len(model)-8:]
		allDigits := true
		for _, c := range suffix {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && model[len(model)-9] == '-' {
			return model[:len(model)-9] + "@" + suffix
		}
	}
	return model
}

// truncateStr returns s truncated to at most n bytes, appending "..." if truncated.
func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
