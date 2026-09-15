package component

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
)

const (
	fctlSDKRevision        = "e9b1395f46f3100b381dbe00f5213de28e6df0e1"
	fctlCanonicalWITSHA256 = "38fdf377264eeada82b23fef153e6bf106ed0624e8916ff62cabdf210d6255f5"
)

func readRepositoryFile(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func TestFlakePinsTheCompleteComponentToolchain(t *testing.T) {
	contents := readRepositoryFile(t, "../../../flake.nix") +
		readRepositoryFile(t, "../../../nix/fctl-component-tools.nix")
	for _, required := range []string{
		"fctlSDKRevision = \"" + fctlSDKRevision + "\"",
		"./nix/fctl-component-tools.nix",
		"inherit (componentTools) componentize-go wasi-virt wasm-tools;",
		"wasm-opt = pkgs.binaryen;",
		"wasmToolsVersion = \"1.239.0\"",
		"sha256-9wJSNC/clO8M7E840i1lRWJQT7AdRQX468swmZ4O1rg=",
		"sha256-xIfTYJMVP47timzquEYEb9M8BHsj83NjgD44lbzgd+Y=",
	} {
		if !strings.Contains(contents, required) {
			t.Errorf("flake.nix does not pin required component authoring input %q", required)
		}
	}
}

// The authoring toolchain is built from Rust sources. Carrying it in the
// default shell makes every Go CI job fetch crates, so a crates.io rate limit
// fails builds that never touch the component. It belongs to the component
// build gate alone.
func TestDefaultDevShellExcludesTheComponentToolchain(t *testing.T) {
	flake := readRepositoryFile(t, "../../../flake.nix")
	index := strings.Index(flake, "devShells = ")
	if index < 0 {
		t.Fatal("flake.nix declares no devShells output")
	}
	devShells := flake[index:]
	for _, forbidden := range []string{"componentize-go", "wasi-virt", "wasm-tools", "binaryen"} {
		if strings.Contains(devShells, forbidden) {
			t.Errorf("default dev shell still carries component authoring tool %q", forbidden)
		}
	}
}

func TestRootGatesSeparateTheComponentBuildFromPreCommit(t *testing.T) {
	justfile := readRepositoryFile(t, "../../../Justfile")
	preCommit := ""
	for _, line := range strings.Split(justfile, "\n") {
		if strings.HasPrefix(line, "pre-commit:") {
			preCommit = line
			break
		}
	}
	if preCommit == "" {
		t.Fatal("root Justfile declares no pre-commit recipe")
	}
	if !strings.Contains(preCommit, "fctl-audit-test") {
		t.Errorf("root pre-commit omits the fctl plugin test gate: %q", preCommit)
	}
	if strings.Contains(preCommit, "fctl-component-build") {
		t.Errorf("root pre-commit must not run the heavier component build gate: %q", preCommit)
	}
	for _, required := range []string{
		"fctl-component-build:",
		"nix shell .#componentize-go .#wasi-virt .#wasm-tools .#wasm-opt",
		"cd plugins/fctl && just build-component",
	} {
		if !strings.Contains(justfile, required) {
			t.Errorf("root component build gate omits %q", required)
		}
	}
}

func TestPluginWITMatchesTheCanonicalFCTLContract(t *testing.T) {
	contents, err := os.ReadFile("../wit/plugin.wit")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != fctlCanonicalWITSHA256 {
		t.Fatalf("plugin.wit SHA-256 = %s, want canonical fctl %s contract %s", got, fctlSDKRevision[:8], fctlCanonicalWITSHA256)
	}
}
