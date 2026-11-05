// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package importcheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const checker = "github.com/microsoft/go-infra/cmd/check-imports@v0.0.13"

// Run on Windows with go test -count=1 ./internal/importcheck because the checker
// reads backend sources in a subprocess, which Go's test cache does not track.
func TestBackendImportsAllowed(t *testing.T) {
	output, err := runChecker(
		"-pkg", "./internal/bcrypt", "-allow", "strconv,syscall,unicode/utf16,unsafe",
		"-pkg", "./internal/sysdll", "-allow", "syscall,unsafe",
		"-pkg", "./internal/subtle", "-allow", "unsafe",
		"-pkg", "./cng/bbig", "-allow", "math/big",
		"-pkg", "./cng",
	)
	if err != nil {
		t.Fatalf("backend import check failed: %v\n%s", err, output)
	}
}

func TestCheckerRejectsDisallowedImport(t *testing.T) {
	output, err := runChecker("-pkg", "./internal/sysdll", "-allow", "")
	if err == nil {
		t.Fatalf("checker unexpectedly accepted the imports:\n%s", output)
	}
	if !strings.Contains(string(output), "FAIL: ./internal/sysdll imports disallowed package: syscall") {
		t.Fatalf("checker did not report the forbidden import: %v\n%s", err, output)
	}
}

func runChecker(args ...string) ([]byte, error) {
	workingDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	repoRoot, err := filepath.Abs(filepath.Join(workingDir, "../.."))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("go", append([]string{"run", checker}, args...)...)
	cmd.Dir = repoRoot
	return cmd.CombinedOutput()
}
