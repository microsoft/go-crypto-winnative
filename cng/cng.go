// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"reflect"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

var algCache sync.Map

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
