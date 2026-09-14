package component

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestComponentImportValidatorAcceptsOnlyTheFiveRuntimeImports(t *testing.T) {
	t.Parallel()
	valid := "wasi:clocks/wall-clock@0.2.12\n" +
		"wasi:random/random@0.2.12\n" +
		"wasi:cli/environment@0.2.12\n" +
		"wasi:io/poll@0.2.12\n" +
		"wasi:clocks/monotonic-clock@0.2.12\n"
	for _, test := range []struct {
		name, imports string
		wantOK        bool
	}{
		{name: "exact", imports: valid, wantOK: true},
		{name: "extra network import", imports: valid + "wasi:sockets/tcp@0.2.12\n"},
		{name: "missing import", imports: "wasi:clocks/wall-clock@0.2.12\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "imports.txt")
			if err := os.WriteFile(path, []byte(test.imports), 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("../scripts/validate-imports.sh", path)
			err := command.Run()
			if (err == nil) != test.wantOK {
				t.Fatalf("validator error = %v, want success %t", err, test.wantOK)
			}
		})
	}
}
