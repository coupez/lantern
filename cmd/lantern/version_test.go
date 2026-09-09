package main

import (
	"runtime/debug"
	"testing"
)

func TestVersionReflectsInstallOrRelease(t *testing.T) {
	for _, tc := range []struct{ override, module, want string }{
		{"v0.1.0", "v0.0.0-test", "v0.1.0"},
		{"", "v0.1.0", "v0.1.0"},
		{"", "v0.0.0-20260908120000-abcdef123456", "v0.0.0-20260908120000-abcdef123456"},
		{"", "(devel)", "0.1.0-dev"},
		{"", "", "0.1.0-dev"},
	} {
		if got := versionLabel(tc.override, &debug.BuildInfo{Main: debug.Module{Version: tc.module}}); got != tc.want {
			t.Fatal(tc, got)
		}
	}
	if got := versionLabel("", nil); got != "0.1.0-dev" {
		t.Fatal(got)
	}
}
