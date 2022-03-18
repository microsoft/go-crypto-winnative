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
