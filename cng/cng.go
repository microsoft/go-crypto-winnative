// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"syscall"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

// ulong casts v into a Win32 ULONG, which is a 32-bit unsigned integer.
// If the cast would overflow, v is truncated to the fit into an uint32.
func ulong(v int) (ul uint32, truncated bool) {
	const maxULong = 1<<32 - 1
	if v > maxULong {
		return maxULong, true
	}
	return uint32(v), false
}

type algCacheEntry struct {
	id    string
	flags uint32
}

func utf16PtrFromString(s string) *uint16 {
	str, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		panic(err)
	}
	return str
}

func getUint32(h bcrypt.HANDLE, name string) (uint32, error) {
	var prop, discard uint32
	err := bcrypt.GetProperty(h, utf16PtrFromString(name), (*[4]byte)(unsafe.Pointer(&prop))[:], &discard, 0)
	return prop, err
}
