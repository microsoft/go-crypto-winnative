// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"strings"
	"testing"
)

func TestAddBufferSizeChecks(t *testing.T) {
	const src = `package bcrypt
func Read(input, output []byte) (ntstatus error) {
	syscall.SyscallN(proc, uintptr(unsafe.Pointer(&input[0])), uintptr(len(input)))
	return
}
func Format(buf []uint16) (n uint32, err error) {
	return
}
func Close(handle uintptr) (ntstatus error) {
	return
}
`
	got, err := addBufferSizeChecks([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	code := string(got)
	for _, want := range []string{
		"if ntstatus = CheckBufferSizes(len(input), len(output)); ntstatus != nil",
		"if err = CheckBufferSizes(len(buf)); err != nil",
		"syscall.SyscallN(proc, uintptr(unsafe.Pointer(&input[0])), uintptr(len(input)))",
	} {
		if !strings.Contains(code, want) {
			t.Errorf("missing %q in generated code:\n%s", want, code)
		}
	}
	if strings.Count(code, "CheckBufferSizes(") != 2 {
		t.Errorf("unexpected buffer checks:\n%s", code)
	}
	if strings.Index(code, "CheckBufferSizes(") > strings.Index(code, "syscall.SyscallN(") {
		t.Error("buffer check occurs after the native call")
	}
}

func TestAddBufferSizeChecksMissingError(t *testing.T) {
	for _, src := range []string{
		"package bcrypt; func Bad(b []byte) {}",
		"package bcrypt; func Bad(b []byte) error { return nil }",
		"not Go source",
	} {
		if _, err := addBufferSizeChecks([]byte(src)); err == nil {
			t.Errorf("expected an error for %q", src)
		}
	}
}
