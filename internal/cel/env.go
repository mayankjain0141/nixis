// Package cel implements the CEL (Common Expression Language) policy evaluator for Aegis.
//
// Hot path contract: Evaluate() must not allocate. Activation maps are pooled via sync.Pool.
// Banned in this package: fmt.Sprintf, encoding/json.Marshal (golangci-lint enforced).
//
// ProgramCache is a VALUE TYPE embedded in EngineSnapshot (INV-008). It is NOT a separately-
// swapped atomic.Pointer — the whole EngineSnapshot is swapped atomically by WS-05.
//
// CEL evaluation is PURE (INV-10): same inputs → same outputs. time.Now(), math/rand,
// goroutine scheduling, and I/O are forbidden inside CEL custom functions.
package cel

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/mayjain/aegis/internal/ifc"
	aegistypes "github.com/mayjain/aegis/pkg/aegis"
)

const (
	maxExpressionLength = 4096
	maxASTDepth         = 32
	maxCostBudget       = uint64(10000)
)

// CELEnvironment holds the compiled CEL environment with all type declarations and
// custom functions. Immutable after construction.
type CELEnvironment struct {
	env *cel.Env
}

// NewCELEnvironment constructs an immutable CEL environment with Aegis-specific type
// declarations and all custom functions registered.
func NewCELEnvironment() (*CELEnvironment, error) {
	env, err := cel.NewEnv(
		// Variable declarations matching the activation map keys populated in ActivationBuilder.
		cel.Variable("tool", cel.StringType),
		cel.Variable("args", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("session_id", cel.StringType),
		cel.Variable("confidentiality", cel.IntType),
		cel.Variable("integrity", cel.IntType),
		cel.Variable("categories", cel.IntType),
		cel.Variable("risk_level", cel.StringType),
		cel.Variable("effects", cel.ListType(cel.StringType)),

		// bash.* namespace
		bashExtension(),

		// path.* namespace
		pathExtension(),

		// label.* and ifc.* namespace
		labelExtension(),
	)
	if err != nil {
		return nil, err
	}
	return &CELEnvironment{env: env}, nil
}

// bashExtension returns the CEL library for bash.* functions.
func bashExtension() cel.EnvOption {
	return cel.Lib(&bashLib{})
}

// pathExtension returns the CEL library for path.* functions.
func pathExtension() cel.EnvOption {
	return cel.Lib(&pathLib{})
}

// labelExtension returns the CEL library for label.* and ifc.* functions.
func labelExtension() cel.EnvOption {
	return cel.Lib(&labelLib{})
}

// --- bash library ---

type bashLib struct{}

func (b *bashLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("bash.isSafeReadOnly",
			cel.Overload("bash_isSafeReadOnly_string",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					cmd, ok := v.(types.String)
					if !ok {
						return types.False
					}
					return types.Bool(bashIsSafeReadOnly(string(cmd)))
				}),
			),
		),
		cel.Function("bash.extractTool",
			cel.Overload("bash_extractTool_string",
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					cmd, ok := v.(types.String)
					if !ok {
						return types.String("")
					}
					return types.String(bashExtractTool(string(cmd)))
				}),
			),
		),
		cel.Function("bash.hasFlag",
			cel.Overload("bash_hasFlag_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
					cmd, ok1 := lhs.(types.String)
					flag, ok2 := rhs.(types.String)
					if !ok1 || !ok2 {
						return types.False
					}
					return types.Bool(bashHasFlag(string(cmd), string(flag)))
				}),
			),
		),
		cel.Function("bash.argCount",
			cel.Overload("bash_argCount_string",
				[]*cel.Type{cel.StringType},
				cel.IntType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					cmd, ok := v.(types.String)
					if !ok {
						return types.IntZero
					}
					return types.Int(bashArgCount(string(cmd)))
				}),
			),
		),
		cel.Function("bash.targetPort",
			cel.Overload("bash_targetPort_string",
				[]*cel.Type{cel.StringType},
				cel.IntType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					cmd, ok := v.(types.String)
					if !ok {
						return types.IntZero
					}
					return types.Int(bashTargetPort(string(cmd)))
				}),
			),
		),
		cel.Function("bash.targetUrl",
			cel.Overload("bash_targetUrl_string",
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					cmd, ok := v.(types.String)
					if !ok {
						return types.String("")
					}
					return types.String(bashTargetURL(string(cmd)))
				}),
			),
		),
		cel.Function("bash.gitBranchTarget",
			cel.Overload("bash_gitBranchTarget_string",
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					cmd, ok := v.(types.String)
					if !ok {
						return types.String("")
					}
					return types.String(bashGitBranchTarget(string(cmd)))
				}),
			),
		),
		cel.Function("bash.findSearchRoot",
			cel.Overload("bash_findSearchRoot_string",
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					cmd, ok := v.(types.String)
					if !ok {
						return types.String("")
					}
					return types.String(bashFindSearchRoot(string(cmd)))
				}),
			),
		),
		cel.Function("bash.isGitForcePush",
			cel.Overload("bash_isGitForcePush_string",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					cmd, ok := v.(types.String)
					if !ok {
						return types.False
					}
					return types.Bool(bashIsGitForcePush(string(cmd)))
				}),
			),
		),
		cel.Function("bash.isGitBranchDelete",
			cel.Overload("bash_isGitBranchDelete_string",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					cmd, ok := v.(types.String)
					if !ok {
						return types.False
					}
					return types.Bool(bashIsGitBranchDelete(string(cmd)))
				}),
			),
		),
	}
}

func (b *bashLib) ProgramOptions() []cel.ProgramOption { return nil }

// --- path library ---

type pathLib struct{}

func (p *pathLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("path.isWithinProject",
			cel.Overload("path_isWithinProject_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
					path, ok1 := lhs.(types.String)
					root, ok2 := rhs.(types.String)
					if !ok1 || !ok2 {
						return types.False
					}
					return types.Bool(pathIsWithinProject(string(path), string(root)))
				}),
			),
		),
	}
}

func (p *pathLib) ProgramOptions() []cel.ProgramOption { return nil }

// --- label/ifc library ---

type labelLib struct{}

func (l *labelLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		// label.dominates(a_conf int, a_int int, a_cat int, b_conf int, b_int int, b_cat int) bool
		// Wraps ifc.Dominates on two SecurityLabels encoded as separate int fields.
		cel.Function("label.dominates",
			cel.Overload("label_dominates_ints",
				[]*cel.Type{cel.IntType, cel.IntType, cel.IntType, cel.IntType, cel.IntType, cel.IntType},
				cel.BoolType,
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					if len(args) != 6 {
						return types.False
					}
					aC, aI, aCat, bC, bI, bCat := intVal(args[0]), intVal(args[1]), intVal(args[2]),
						intVal(args[3]), intVal(args[4]), intVal(args[5])
					subject := aegistypes.SecurityLabel{
						Confidentiality: uint16(aC), //nolint:gosec // bounded by CEL int semantics; callers control inputs
						Integrity:       uint16(aI),
						Category:        uint32(aCat),
					}
					object := aegistypes.SecurityLabel{
						Confidentiality: uint16(bC),
						Integrity:       uint16(bI),
						Category:        uint32(bCat),
					}
					return types.Bool(ifc.Dominates(subject, object))
				}),
			),
		),
		// label.join(a_conf, a_int, a_cat, b_conf, b_int, b_cat) — returns [conf, int, cat] as list<int>
		cel.Function("label.join",
			cel.Overload("label_join_ints",
				[]*cel.Type{cel.IntType, cel.IntType, cel.IntType, cel.IntType, cel.IntType, cel.IntType},
				cel.ListType(cel.IntType),
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					if len(args) != 6 {
						return types.DefaultTypeAdapter.NativeToValue([]ref.Val{})
					}
					aC, aI, aCat, bC, bI, bCat := intVal(args[0]), intVal(args[1]), intVal(args[2]),
						intVal(args[3]), intVal(args[4]), intVal(args[5])
					a := aegistypes.SecurityLabel{
						Confidentiality: uint16(aC),
						Integrity:       uint16(aI),
						Category:        uint32(aCat),
					}
					b := aegistypes.SecurityLabel{
						Confidentiality: uint16(bC),
						Integrity:       uint16(bI),
						Category:        uint32(bCat),
					}
					result := ifc.Join(a, b)
					items := []ref.Val{
						types.Int(result.Confidentiality),
						types.Int(result.Integrity),
						types.Int(result.Category),
					}
					return types.DefaultTypeAdapter.NativeToValue(items)
				}),
			),
		),
		// ifc.highWaterMark(session_id string) — returns the confidentiality int of the session label
		cel.Function("ifc.highWaterMark",
			cel.Overload("ifc_highWaterMark_string",
				[]*cel.Type{cel.StringType},
				cel.IntType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					// highWaterMark operates on the shared SessionLabels at eval time.
					// The sessionLabels pointer is captured in the closure via globalSessions.
					// This is pure in the sense that it reads the current IFC state — same
					// session, same committed label, same output (monotone).
					sid, ok := v.(types.String)
					if !ok {
						return types.IntZero
					}
					if globalSessions == nil {
						return types.IntZero
					}
					label := globalSessions.Current(string(sid))
					return types.Int(label.Confidentiality)
				}),
			),
		),
	}
}

func (l *labelLib) ProgramOptions() []cel.ProgramOption { return nil }

// globalSessions is set once at NewCELEnvironment call time by SetSessionLabels.
// It is read-only on the hot path. This avoids threading *ifc.SessionLabels through
// every CEL activation map (which would allocate).
var globalSessions *ifc.SessionLabels

// SetSessionLabels injects the session label registry for use by ifc.highWaterMark.
// Must be called before any CEL evaluation that uses ifc.highWaterMark.
// Thread-safe: write happens at startup before any goroutines call Evaluate.
func SetSessionLabels(s *ifc.SessionLabels) {
	globalSessions = s
}

// intVal safely converts a ref.Val to int64.
func intVal(v ref.Val) int64 {
	i, ok := v.(types.Int)
	if !ok {
		return 0
	}
	return int64(i)
}

// --- bash function implementations ---
// All functions are pure, O(1), deterministic. No I/O, no time.Now(), no goroutines.

var reReadOnlyCmds = regexp.MustCompile(
	`^(ls|ll|la|cat|head|tail|grep|find|echo|pwd|wc|sort|uniq|diff|less|more|file|stat|du|df|id|whoami|uname|hostname|date|env|printenv|which|type|man|help|true|false|test|read|source|\.)(\s|$)`,
)

// bashIsSafeReadOnly returns true if cmd matches a known read-only command classification.
func bashIsSafeReadOnly(cmd string) bool {
	trimmed := strings.TrimSpace(cmd)
	return reReadOnlyCmds.MatchString(trimmed)
}

// bashExtractTool returns the first token (the executable) of cmd.
func bashExtractTool(cmd string) string {
	trimmed := strings.TrimSpace(cmd)
	if trimmed == "" {
		return ""
	}
	idx := strings.IndexByte(trimmed, ' ')
	if idx < 0 {
		return trimmed
	}
	return trimmed[:idx]
}

// bashHasFlag returns true if cmd contains the given flag token.
func bashHasFlag(cmd, flag string) bool {
	tokens := strings.Fields(cmd)
	for _, t := range tokens {
		if t == flag {
			return true
		}
	}
	return false
}

// bashArgCount returns the number of arguments (tokens after the command name).
func bashArgCount(cmd string) int {
	fields := strings.Fields(cmd)
	if len(fields) <= 1 {
		return 0
	}
	return len(fields) - 1
}

// reTargetPort matches port-targeted kill patterns:
//
//	lsof -ti:PORT | xargs kill
//	kill -9 $(lsof -ti:PORT)
//	fuser -k PORT/tcp
var reTargetPort = []*regexp.Regexp{
	regexp.MustCompile(`lsof\s+-ti?:(\d+)`),
	regexp.MustCompile(`fuser\s+-k\s+(\d+)/tcp`),
}

// bashTargetPort extracts the port number from port-targeted kill patterns.
// Returns 0 if no port pattern is detected. O(1), <500ns.
func bashTargetPort(cmd string) int {
	for _, re := range reTargetPort {
		if m := re.FindStringSubmatch(cmd); m != nil {
			p, err := strconv.Atoi(m[1])
			if err == nil {
				return p
			}
		}
	}
	return 0
}

// reTargetURL matches curl/wget URL arguments.
var reTargetURL = regexp.MustCompile(`(?:curl|wget)\s+(?:[^\s]+\s+)*?(https?://[^\s'"]+|https?://[^\s'"]+)`)

// bashTargetURL extracts the URL from a curl/wget command. Returns empty if no URL found.
func bashTargetURL(cmd string) string {
	// Scan for http:// or https:// tokens.
	tokens := strings.Fields(cmd)
	for _, t := range tokens {
		if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
			return t
		}
	}
	// Fallback to regex for quoted URLs.
	if m := reTargetURL.FindStringSubmatch(cmd); m != nil {
		return m[1]
	}
	return ""
}

// bashGitBranchTarget extracts the branch name from git branch/push commands.
// Handles all 8 refspec forms per FINAL_SPEC_HARDENING.md §P1-4.
// Branch matching is case-insensitive (returns lowercase).
func bashGitBranchTarget(cmd string) string {
	tokens := strings.Fields(cmd)
	if len(tokens) < 2 {
		return ""
	}

	// Only handle git commands.
	if tokens[0] != "git" {
		return ""
	}

	if len(tokens) < 3 {
		return ""
	}

	switch tokens[1] {
	case "branch":
		return extractBranchFromBranchCmd(tokens[2:])
	case "push":
		return extractBranchFromPushCmd(tokens[2:])
	}
	return ""
}

// extractBranchFromBranchCmd extracts the branch from `git branch [flags] <name>` args.
func extractBranchFromBranchCmd(args []string) string {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return strings.ToLower(a)
	}
	return ""
}

// extractBranchFromPushCmd extracts the branch from `git push [flags] [remote] [refspec]` args.
func extractBranchFromPushCmd(args []string) string {
	// Strip flags like --force, -f, --tags, etc.
	nonFlags := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		nonFlags = append(nonFlags, a)
	}
	// nonFlags[0] is the remote (e.g. "origin"), nonFlags[1] is the refspec if present.
	// Forms handled:
	//   git push origin main           → main
	//   git push origin +main          → main
	//   git push origin :main          → main  (empty src = delete)
	//   git push origin HEAD:main      → main
	//   git push origin HEAD:refs/heads/main → main
	if len(nonFlags) < 2 {
		// No explicit refspec — check if remote arg itself carries +refspec.
		for _, a := range nonFlags {
			if strings.HasPrefix(a, "+") {
				return strings.ToLower(strings.TrimPrefix(a, "+"))
			}
		}
		return ""
	}
	refspec := nonFlags[len(nonFlags)-1]
	return parseRefspec(refspec)
}

// parseRefspec parses a git refspec into the destination branch name.
func parseRefspec(refspec string) string {
	// +main  → main (force refspec)
	refspec = strings.TrimPrefix(refspec, "+")

	// :main  → main (delete remote)
	refspec = strings.TrimPrefix(refspec, ":")

	// HEAD:main → main
	// HEAD:refs/heads/main → main
	if idx := strings.Index(refspec, ":"); idx >= 0 {
		refspec = refspec[idx+1:]
	}

	// refs/heads/main → main
	refspec = strings.TrimPrefix(refspec, "refs/heads/")

	return strings.ToLower(refspec)
}

// bashIsGitForcePush returns true if cmd is a git force push in any form.
// Forms: --force, -f, +refspec.
func bashIsGitForcePush(cmd string) bool {
	tokens := strings.Fields(cmd)
	if len(tokens) < 2 || tokens[0] != "git" || tokens[1] != "push" {
		return false
	}
	for _, t := range tokens[2:] {
		if t == "--force" || t == "-f" {
			return true
		}
		// +refspec form (e.g. "+main", "+refs/heads/main")
		if strings.HasPrefix(t, "+") && !strings.HasPrefix(t, "+-") {
			return true
		}
	}
	return false
}

// bashIsGitBranchDelete returns true if cmd is a branch delete in any form.
// Forms: git branch -D <name>, git branch -d <name>, git push origin :branch.
func bashIsGitBranchDelete(cmd string) bool {
	tokens := strings.Fields(cmd)
	if len(tokens) < 2 || tokens[0] != "git" {
		return false
	}
	switch tokens[1] {
	case "branch":
		for _, t := range tokens[2:] {
			if t == "-D" || t == "-d" {
				return true
			}
		}
	case "push":
		// git push origin :branch — delete via empty src
		for _, t := range tokens[2:] {
			if strings.HasPrefix(t, ":") && len(t) > 1 {
				return true
			}
		}
	}
	return false
}

// bashFindSearchRoot extracts the search root directory from a `find` command.
// Returns empty string if not a find command.
// Symlinks in the path are resolved via filepath.EvalSymlinks (fail-secure: returns "" on error).
func bashFindSearchRoot(cmd string) string {
	tokens := strings.Fields(cmd)
	if len(tokens) < 2 || tokens[0] != "find" {
		return ""
	}
	// The first non-flag argument after "find" is the path.
	for _, t := range tokens[1:] {
		if strings.HasPrefix(t, "-") {
			continue
		}
		resolved, err := filepath.EvalSymlinks(t)
		if err != nil {
			// Fail-secure: path may not exist yet (e.g. in expressions); return as-is.
			return filepath.Clean(t)
		}
		return resolved
	}
	return ""
}

// pathIsWithinProject returns true if path is within root after canonicalization.
// Returns false on any symlink resolution error (fail-secure, INV-014).
func pathIsWithinProject(path, root string) bool {
	canonicalSearch, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return false
	}
	canonicalProject, err := filepath.EvalSymlinks(filepath.Clean(root))
	if err != nil {
		return false
	}
	if !strings.HasSuffix(canonicalProject, "/") {
		canonicalProject += "/"
	}
	return strings.HasPrefix(canonicalSearch, canonicalProject) || canonicalSearch == strings.TrimSuffix(canonicalProject, "/")
}
