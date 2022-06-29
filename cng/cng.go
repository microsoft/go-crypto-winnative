// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"math"
	"reflect"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

func FIPS() (bool, error) {
	var enabled bool
	err := bcrypt.GetFipsAlgorithmMode(&enabled)
	if err != nil {
		return false, err
	}
	return enabled, nil
}

// lenU32 clamps s length so it can fit into a Win32 ULONG,
// which is a 32-bit unsigned integer, without overflowing.
func lenU32(s []byte) int {
	if len(s) > math.MaxUint32 {
		return math.MaxUint32
	}
	return len(s)
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

func utf16FromString(s string) []uint16 {
	str, err := syscall.UTF16FromString(s)
	if err != nil {
		panic(err)
	}
	return str
}

func setString(h bcrypt.HANDLE, name, val string) error {
	str := utf16FromString(val)
	defer runtime.KeepAlive(str)
	in := make([]byte, len(val)+1)
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&in))
	sh.Data = uintptr(unsafe.Pointer(&str[0]))
	return bcrypt.SetProperty(h, utf16PtrFromString(name), in, 0)
}

func getUint32(h bcrypt.HANDLE, name string) (uint32, error) {
	var prop, discard uint32
	err := bcrypt.GetProperty(h, utf16PtrFromString(name), (*[4]byte)(unsafe.Pointer(&prop))[:], &discard, 0)
	return prop, err
}
