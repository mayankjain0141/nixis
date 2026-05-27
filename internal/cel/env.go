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
	"sync/atomic"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/mayjain/aegis/internal/ifc"
	aegistypes "github.com/mayjain/aegis/pkg/aegis"
	"google.golang.org/protobuf/proto"
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
//
// protoTypes registers additional proto.Message descriptors with the CEL type system.
// Phase 1 passes no types (all variables are primitive CEL types). Future phases may
// register proto-derived types for structured policy variables.
func NewCELEnvironment(protoTypes ...proto.Message) (*CELEnvironment, error) {
	opts := []cel.EnvOption{
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
	}

	// Register proto.Message type descriptors if provided.
	if len(protoTypes) > 0 {
		anySlice := make([]any, len(protoTypes))
		for i, t := range protoTypes {
			anySlice[i] = t
		}
		opts = append(opts, cel.Types(anySlice...))
	}

	env, err := cel.NewEnv(opts...)
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
						Confidentiality: clampUint16(aC),
						Integrity:       clampUint16(aI),
						Category:        clampUint32(aCat),
					}
					object := aegistypes.SecurityLabel{
						Confidentiality: clampUint16(bC),
						Integrity:       clampUint16(bI),
						Category:        clampUint32(bCat),
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
						return types.DefaultTypeAdapter.NativeToValue([]int64{})
					}
					aC, aI, aCat, bC, bI, bCat := intVal(args[0]), intVal(args[1]), intVal(args[2]),
						intVal(args[3]), intVal(args[4]), intVal(args[5])
					a := aegistypes.SecurityLabel{
						Confidentiality: clampUint16(aC),
						Integrity:       clampUint16(aI),
						Category:        clampUint32(aCat),
					}
					b := aegistypes.SecurityLabel{
						Confidentiality: clampUint16(bC),
						Integrity:       clampUint16(bI),
						Category:        clampUint32(bCat),
					}
					result := ifc.Join(a, b)
					// Return as []int64 so CEL's NativeToValue produces a typed list<int>.
					// Using []ref.Val would produce an untyped list that fails type-checking
					// against the declared return type list<int>.
					return types.DefaultTypeAdapter.NativeToValue([]int64{
						int64(result.Confidentiality),
						int64(result.Integrity),
						int64(result.Category),
					})
				}),
			),
		),
		// ifc.highWaterMark(session_id string) — returns the confidentiality int of the session label.
		// Monotone: labels only increase, so repeated calls for the same session ID are non-decreasing.
		cel.Function("ifc.highWaterMark",
			cel.Overload("ifc_highWaterMark_string",
				[]*cel.Type{cel.StringType},
				cel.IntType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					sid, ok := v.(types.String)
					if !ok {
						return types.IntZero
					}
					s := globalSessions.Load()
					if s == nil {
						return types.IntZero
					}
					label := s.Current(string(sid))
					return types.Int(label.Confidentiality)
				}),
			),
		),
	}
}

func (l *labelLib) ProgramOptions() []cel.ProgramOption { return nil }

// globalSessions holds the session label registry for ifc.highWaterMark.
// atomic.Pointer ensures safe concurrent access between goroutines that call
// Evaluate (readers) and any call to SetSessionLabels (writer).
var globalSessions atomic.Pointer[ifc.SessionLabels]

// SetSessionLabels injects the session label registry for use by ifc.highWaterMark.
// Safe to call at any time; the pointer swap is atomic.
func SetSessionLabels(s *ifc.SessionLabels) {
	globalSessions.Store(s)
}

// intVal safely converts a ref.Val to int64.
func intVal(v ref.Val) int64 {
	i, ok := v.(types.Int)
	if !ok {
		return 0
	}
	return int64(i)
}

// clampUint16 converts an int64 to uint16 by clamping to [0, 65535].
// CEL int values are int64; SecurityLabel dimensions are uint16.
// Values outside the uint16 range are policy author errors; we clamp rather
// than panic or truncate silently, so the result is deterministic and well-defined.
func clampUint16(n int64) uint16 {
	if n < 0 {
		return 0
	}
	if n > 65535 {
		return 65535
	}
	return uint16(n)
}

// clampUint32 converts an int64 to uint32 by clamping to [0, 4294967295].
func clampUint32(n int64) uint32 {
	if n < 0 {
		return 0
	}
	if n > 4294967295 {
		return 4294967295
	}
	return uint32(n)
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

// reTargetURL matches a URL (http:// or https://) following curl or wget and any flags/headers.
// Capture group 1 is the URL. The non-greedy .*? skips over flags and header values.
var reTargetURL = regexp.MustCompile(`(?:curl|wget)\b.*?(https?://[^\s'"]+)`)

// bashTargetURL extracts the URL from a curl/wget command. Returns empty if no URL found.
func bashTargetURL(cmd string) string {
	// Fast path: scan space-delimited tokens for a URL prefix.
	// This correctly handles unquoted URLs without regex backtracking.
	tokens := strings.Fields(cmd)
	for _, t := range tokens {
		if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
			return t
		}
	}
	// Fallback: regex for URLs that are embedded mid-token or quoted.
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
	// Separate flags (start with "-") from positional arguments.
	// Positional args are: [remote, refspec] in that order.
	nonFlags := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		nonFlags = append(nonFlags, a)
	}

	// Forms handled (after flag removal):
	//   git push origin main             → nonFlags=[origin, main]       → main
	//   git push origin +main            → nonFlags=[origin, +main]      → main
	//   git push origin :main            → nonFlags=[origin, :main]      → main
	//   git push origin HEAD:main        → nonFlags=[origin, HEAD:main]  → main
	//   git push origin HEAD:refs/heads/main → nonFlags=[origin, HEAD:refs/heads/main] → main
	//
	// When there is no explicit refspec (nonFlags has only the remote), git pushes the
	// current branch to its upstream — we cannot determine the branch from the command
	// text alone, so return "".
	if len(nonFlags) < 2 {
		return ""
	}
	// The last non-flag argument is the refspec (or branch name).
	refspec := nonFlags[len(nonFlags)-1]
	return parseRefspec(refspec)
}

// parseRefspec parses a git refspec into the destination branch name (lowercase).
func parseRefspec(refspec string) string {
	// +main → main (force-push refspec prefix)
	refspec = strings.TrimPrefix(refspec, "+")

	// :main → main (delete remote branch via empty src)
	refspec = strings.TrimPrefix(refspec, ":")

	// HEAD:main or HEAD:refs/heads/main → take the part after ":"
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

// bashFindSearchRoot extracts the search root directory from a `find` command and resolves
// symlinks. Returns empty string if not a find command or if path resolution fails.
//
// Fail-secure (INV-014): on any filepath.EvalSymlinks error (path does not exist, broken
// symlink, permission denied), the function returns "" rather than a raw unresolved path.
// A policy comparing the result to a project root would then treat the unknown location
// conservatively (outside project), rather than making a decision based on an unverified path.
func bashFindSearchRoot(cmd string) string {
	tokens := strings.Fields(cmd)
	if len(tokens) < 2 || tokens[0] != "find" {
		return ""
	}
	// The first non-flag argument after "find" is the search path.
	for _, t := range tokens[1:] {
		if strings.HasPrefix(t, "-") {
			continue
		}
		resolved, err := filepath.EvalSymlinks(filepath.Clean(t))
		if err != nil {
			// Fail-secure: do NOT return filepath.Clean(t).
			// An unresolved path returned to a policy is indistinguishable from a real path,
			// and could allow boundary-check bypass if the policy uses string prefix matching.
			return ""
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
	return strings.HasPrefix(canonicalSearch, canonicalProject) ||
		canonicalSearch == strings.TrimSuffix(canonicalProject, "/")
}
