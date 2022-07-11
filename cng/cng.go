// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"math"
	"reflect"
	"runtime"
	"sync"
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

var algCache sync.Map

type newAlgEntryFn func(h bcrypt.ALG_HANDLE) (interface{}, error)

func loadOrStoreAlg(id string, flags bcrypt.AlgorithmProviderFlags, mode string, fn newAlgEntryFn) (interface{}, error) {
	var entryKey = struct {
		id    string
		flags bcrypt.AlgorithmProviderFlags
		mode  string
	}{id, flags, mode}

	if v, ok := algCache.Load(entryKey); ok {
		return v, nil
	}
	var h bcrypt.ALG_HANDLE
	err := bcrypt.OpenAlgorithmProvider(&h, utf16PtrFromString(id), nil, flags)
	if err != nil {
		return nil, err
	}
	v, err := fn(h)
	if err != nil {
		bcrypt.CloseAlgorithmProvider(h, 0)
		return nil, err
	}
	if existing, loaded := algCache.LoadOrStore(entryKey, v); loaded {
		// We can safely use a provider that has already been cached in another concurrent goroutine.
		bcrypt.CloseAlgorithmProvider(h, 0)
		v = existing
	}
	return v, nil
}

func utf16PtrFromString(s string) *uint16 {
	return &utf16FromString(s)[0]
}

func utf16FromString(s string) []uint16 {
	a := make([]uint16, 0, 32)
	for _, v := range s {
		if v == 0 || v > 127 {
			panic("utf16FromString only supports ASCII characters, got " + s)
		}
		a = append(a, uint16(v))
	}
	return a
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
