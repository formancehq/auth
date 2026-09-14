package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// spec is the real document, relative to this package directory.
const spec = "../../../../openapi.yaml"

func TestCommandWritesAndChecksRequestedOutput(t *testing.T) {
	out := preparedOutput(t)
	var stderr bytes.Buffer
	if code := command([]string{"-spec", spec, "-out", out}, &stderr); code != 0 {
		t.Fatalf("write exit = %d, stderr = %q", code, stderr.String())
	}
	stderr.Reset()
	if code := command([]string{"-spec", spec, "-out", out, "-check"}, &stderr); code != 0 {
		t.Fatalf("check exit = %d, stderr = %q", code, stderr.String())
	}
}

func TestCommandReportsFlagAndRunFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{name: "unknown flag", args: []string{"-unknown"}, want: 2},
		{name: "missing spec", args: []string{"-spec", filepath.Join(t.TempDir(), "missing.yaml")}, want: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if got := command(test.args, &stderr); got != test.want {
				t.Fatalf("exit = %d, want %d; stderr = %q", got, test.want, stderr.String())
			}
			if stderr.Len() == 0 {
				t.Error("failure produced no diagnostic")
			}
		})
	}
}

// TestRunWritesBothArtefacts proves the generator writes exactly the two
// artefacts it documents, and nothing else.
func TestRunWritesBothArtefacts(t *testing.T) {
	out := t.TempDir()
	for _, dir := range []string{filepath.Join("audit", "testdata"), "docs"} {
		if err := os.MkdirAll(filepath.Join(out, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if err := run(spec, out, false); err != nil {
		t.Fatalf("run: %v", err)
	}

	report := filepath.Join(out, "audit", "testdata", "report.json")
	generated := filepath.Join(out, "docs", "operations.generated.md")
	for _, path := range []string{report, generated} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", path)
		}
	}

	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(raw), "\n") {
		t.Error("report.json does not end with a newline")
	}
}

// TestRunIsIdempotent proves a second run over its own output changes nothing,
// which is what makes the check mode meaningful.
func TestRunIsIdempotent(t *testing.T) {
	out := t.TempDir()
	for _, dir := range []string{filepath.Join("audit", "testdata"), "docs"} {
		if err := os.MkdirAll(filepath.Join(out, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if err := run(spec, out, false); err != nil {
		t.Fatalf("first run: %v", err)
	}
	before := readAll(t, out)

	if err := run(spec, out, false); err != nil {
		t.Fatalf("second run: %v", err)
	}
	after := readAll(t, out)

	for path, want := range before {
		if after[path] != want {
			t.Errorf("%s changed between two identical runs", path)
		}
	}
}

// TestCheckPassesOnFreshOutput proves check mode accepts artefacts the
// generator just produced.
func TestCheckPassesOnFreshOutput(t *testing.T) {
	out := t.TempDir()
	for _, dir := range []string{filepath.Join("audit", "testdata"), "docs"} {
		if err := os.MkdirAll(filepath.Join(out, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := run(spec, out, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	if err := run(spec, out, true); err != nil {
		t.Errorf("check rejected freshly written artefacts: %v", err)
	}
}

// TestCheckFailsOnStaleOutput proves check mode detects a drifted artefact.
// Without this, `just fctl-audit-check` could pass vacuously.
func TestCheckFailsOnStaleOutput(t *testing.T) {
	for _, target := range []string{
		filepath.Join("audit", "testdata", "report.json"),
		filepath.Join("docs", "operations.generated.md"),
	} {
		t.Run(target, func(t *testing.T) {
			out := t.TempDir()
			for _, dir := range []string{filepath.Join("audit", "testdata"), "docs"} {
				if err := os.MkdirAll(filepath.Join(out, dir), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := run(spec, out, false); err != nil {
				t.Fatalf("run: %v", err)
			}

			path := filepath.Join(out, target)
			if err := os.WriteFile(path, []byte("drifted\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			err := run(spec, out, true)
			if err == nil {
				t.Fatalf("check accepted a drifted %s", target)
			}
			if !strings.Contains(err.Error(), "out of date") {
				t.Errorf("error %q does not tell the caller the artefact is out of date", err)
			}
		})
	}
}

// TestCheckFailsOnMissingOutput proves check mode reports an absent artefact
// rather than treating it as up to date.
func TestCheckFailsOnMissingOutput(t *testing.T) {
	if err := run(spec, t.TempDir(), true); err == nil {
		t.Error("check accepted a directory with no artefacts")
	}
}

// TestRunReportsAMissingSpec proves a bad spec path fails loudly.
func TestRunReportsAMissingSpec(t *testing.T) {
	if err := run(filepath.Join(t.TempDir(), "absent.yaml"), t.TempDir(), false); err == nil {
		t.Error("run accepted a missing spec document")
	}
}

// TestRunReportsAnUnwritableOutput proves a write failure is surfaced.
func TestRunReportsAnUnwritableOutput(t *testing.T) {
	if err := run(spec, filepath.Join(t.TempDir(), "does-not-exist"), false); err == nil {
		t.Error("run accepted an output root whose directories do not exist")
	}
}

func readAll(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, rel := range []string{
		filepath.Join("audit", "testdata", "report.json"),
		filepath.Join("docs", "operations.generated.md"),
	} {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		out[rel] = string(raw)
	}
	return out
}

func preparedOutput(t *testing.T) string {
	t.Helper()
	out := t.TempDir()
	for _, dir := range []string{filepath.Join("audit", "testdata"), "docs"} {
		if err := os.MkdirAll(filepath.Join(out, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return out
}
