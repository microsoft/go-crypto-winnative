// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"errors"
	"math"
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

// len32 clamps s length so it can fit into a Win32 LONG,
// which is a 32-bit signed integer, without overflowing.
func len32(s []byte) int {
	if len(s) > math.MaxInt32 {
		return math.MaxInt32
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

// utf16FromString converts the string using a stack-allocated slice of 64 bytes.
// It should only be used to convert known BCrypt identifiers which only contains ASCII characters.
// utf16FromString allocates if s is longer than 31 characters.
func utf16FromString(s string) []uint16 {
	// Once https://go.dev/issues/51896 lands and our support matrix allows it,
	// we can replace part of this function by utf16.AppendRune
	a := make([]uint16, 0, 32)
	for _, v := range s {
		if v == 0 || v > 127 {
			panic("utf16FromString only supports ASCII characters, got " + s)
		}
		a = append(a, uint16(v))
	}
	// Finish with a NULL byte.
	a = append(a, 0)
	return a
}

func setString(h bcrypt.HANDLE, name, val string) error {
	str := utf16FromString(val)
	defer runtime.KeepAlive(str)
	// str is a []uint16, which takes 2 bytes per element.
	n := len(str) * 2
	in := unsafe.Slice((*byte)(unsafe.Pointer(&str[0])), n)
	return bcrypt.SetProperty(h, utf16PtrFromString(name), in, 0)
}

func getUint32(h bcrypt.HANDLE, name string) (uint32, error) {
	var prop, discard uint32
	err := bcrypt.GetProperty(h, utf16PtrFromString(name), (*[4]byte)(unsafe.Pointer(&prop))[:], &discard, 0)
	return prop, err
}

const sizeOfKEY_LENGTHS_STRUCT = unsafe.Sizeof(bcrypt.KEY_LENGTHS_STRUCT{})

func getKeyLengths(h bcrypt.HANDLE) (lengths bcrypt.KEY_LENGTHS_STRUCT, err error) {
	var discard uint32
	ptr := (*[sizeOfKEY_LENGTHS_STRUCT]byte)(unsafe.Pointer(&lengths))
	err = bcrypt.GetProperty(bcrypt.HANDLE(h), utf16PtrFromString(bcrypt.KEY_LENGTHS), ptr[:], &discard, 0)
	if err != nil {
		return
	}
	if lengths.MinLength > lengths.MaxLength || (lengths.Increment == 0 && lengths.MinLength != lengths.MaxLength) {
		err = errors.New("invalid BCRYPT_KEY_LENGTHS_STRUCT")
		return
	}
	return lengths, nil
}

func keyIsAllowed(lengths bcrypt.KEY_LENGTHS_STRUCT, bits uint32) bool {
	if bits < lengths.MinLength || bits > lengths.MaxLength {
		return false
	}
	if lengths.Increment == 0 {
		return bits == lengths.MinLength
	}
	return (bits-lengths.MinLength)%lengths.Increment == 0
}
