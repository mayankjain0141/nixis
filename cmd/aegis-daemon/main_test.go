package main

import "testing"

func TestDaemon_ExitCodes_Defined(t *testing.T) {
	tests := []struct {
		name  string
		code  int
		value int
	}{
		{"exitSuccess", exitSuccess, 0},
		{"exitStartupFailure", exitStartupFailure, 1},
		{"exitRuntimeFailure", exitRuntimeFailure, 2},
		{"exitConfigError", exitConfigError, 3},
	}

	for _, tt := range tests {
		if tt.code != tt.value {
			t.Errorf("%s = %d, want %d", tt.name, tt.code, tt.value)
		}
	}
}

func TestExpandHome(t *testing.T) {
	tests := []struct {
		input    string
		wantHome bool
	}{
		{"", false},
		{"/absolute/path", false},
		{"relative/path", false},
		{"~/foo", true},
	}

	for _, tt := range tests {
		result := expandHome(tt.input)
		if tt.wantHome {
			if result == tt.input {
				t.Errorf("expandHome(%q) = %q, want home expansion", tt.input, result)
			}
		} else {
			if result != tt.input {
				t.Errorf("expandHome(%q) = %q, want %q", tt.input, result, tt.input)
			}
		}
	}
}
