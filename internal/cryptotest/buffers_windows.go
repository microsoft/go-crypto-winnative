// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package cryptotest

import (
	"syscall"
	"testing"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/sysdll"
)

// OversizedBuffer reserves a 4 GiB buffer and capacity for a 16-byte AEAD tag
// without committing the full range. Only the first page is writable.
func OversizedBuffer(t *testing.T) []byte {
	t.Helper()
	if unsafe.Sizeof(uintptr(0)) == 4 {
		t.Skip("oversized buffers require a 64-bit address space")
	}
	dll := syscall.NewLazyDLL(sysdll.Add("ntdll.dll"))
	alloc := dll.NewProc("NtAllocateVirtualMemory")
	free := dll.NewProc("NtFreeVirtualMemory")
	size := (uint64(1) << 32) + 16
	const (
		memCommit     = 0x1000
		memReserve    = 0x2000
		memRelease    = 0x8000
		pageNoAccess  = 0x01
		pageReadWrite = 0x04
	)
	var addr unsafe.Pointer
	regionSize := uintptr(size)
	currentProcess := ^uintptr(0)
	status, _, _ := alloc.Call(currentProcess, uintptr(unsafe.Pointer(&addr)), 0, uintptr(unsafe.Pointer(&regionSize)), memReserve, pageNoAccess)
	if int32(status) < 0 || addr == nil {
		t.Skipf("cannot reserve buffer address space: NTSTATUS %#x", uint32(status))
	}
	t.Cleanup(func() {
		var size uintptr
		status, _, _ := free.Call(currentProcess, uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)), memRelease)
		if int32(status) < 0 {
			t.Errorf("NtFreeVirtualMemory: NTSTATUS %#x", uint32(status))
		}
	})
	prefixAddr, prefixSize := addr, uintptr(1)
	status, _, _ = alloc.Call(currentProcess, uintptr(unsafe.Pointer(&prefixAddr)), 0, uintptr(unsafe.Pointer(&prefixSize)), memCommit, pageReadWrite)
	if int32(status) < 0 {
		t.Skipf("cannot commit buffer prefix: NTSTATUS %#x", uint32(status))
	}
	buf := unsafe.Slice((*byte)(addr), int(size))
	return buf[:len(buf)-16]
}
