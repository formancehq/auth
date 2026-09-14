package component

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
)

const (
	fctlSDKRevision        = "545521bfa222250af6b4419b194c7967cded0379"
	fctlCanonicalWITSHA256 = "38fdf377264eeada82b23fef153e6bf106ed0624e8916ff62cabdf210d6255f5"
)

func TestAuthoringDevShellPinsTheCompleteComponentToolchain(t *testing.T) {
	flake, err := os.ReadFile("../../../flake.nix")
	if err != nil {
		t.Fatal(err)
	}
	toolDefinitions, err := os.ReadFile("../../../nix/fctl-component-tools.nix")
	if err != nil {
		t.Fatal(err)
	}
	contents := string(flake) + string(toolDefinitions)
	for _, required := range []string{
		"fctlSDKRevision = \"" + fctlSDKRevision + "\"",
		"./nix/fctl-component-tools.nix",
		"componentTools.componentize-go",
		"componentTools.wasi-virt",
		"componentTools.wasm-tools",
		"binaryen",
		"wasmToolsVersion = \"1.239.0\"",
		"sha256-9wJSNC/clO8M7E840i1lRWJQT7AdRQX468swmZ4O1rg=",
		"sha256-xIfTYJMVP47timzquEYEb9M8BHsj83NjgD44lbzgd+Y=",
	} {
		if !strings.Contains(contents, required) {
			t.Errorf("flake.nix does not pin required component authoring input %q", required)
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
