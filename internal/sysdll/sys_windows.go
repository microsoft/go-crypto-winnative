// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package sysdll is a custom version of the standard library internal/syscall/windows/sysdll package.
package sysdll

import (
	"syscall"
	"unsafe"
)

var (
	// kernel32.dll is a known system DLL used by Go,
	// so protected against DLL preloading attacks.
	modkernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetSystemDirectoryW = modkernel32.NewProc("GetSystemDirectoryW")
)

func getSystemDirectoryW(dir *uint16, dirLen uint32) (len uint32, err error) {
	r0, _, e1 := syscall.Syscall(procGetSystemDirectoryW.Addr(), 2, uintptr(unsafe.Pointer(dir)), uintptr(dirLen), 0)
	len = uint32(r0)
	if len == 0 {
		err = e1
	}
	return
}

// getSystemDirectory retrieves the path to current location of the system
// directory, which is typically, though not always, `C:\Windows\System32`.
func getSystemDirectory() string {
	n := uint32(syscall.MAX_PATH)
	for {
		b := make([]uint16, n)
		l, e := getSystemDirectoryW(&b[0], n)
		if e != nil {
			panic(e)
		}
		if l <= n {
			return syscall.UTF16ToString(b[:l])
		}
		n = l
	}
}

// Add returns the absolute path of the dll.
// The returned path points to the system directory,
// so it is secure against DLL preloading attacks.
func Add(dll string) string {
	return getSystemDirectory() + "\\" + dll
}
