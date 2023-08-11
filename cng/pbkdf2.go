// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"errors"
	"hash"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

func loadPBKDF2() (bcrypt.ALG_HANDLE, error) {
	h, err := loadOrStoreAlg(bcrypt.PBKDF2_ALGORITHM, 0, "", func(h bcrypt.ALG_HANDLE) (interface{}, error) {
		return h, nil
	})
	if err != nil {
		return 0, err
	}
	return h.(bcrypt.ALG_HANDLE), nil
}

func PBKDF2(password, salt []byte, iter, keyLen int, h func() hash.Hash) ([]byte, error) {
	ch := h()
	hashID := hashToID(ch)
	if hashID == "" {
		return nil, errors.New("cng: unsupported hash function")
	}
	alg, err := loadPBKDF2()
	if err != nil {
		return nil, err
	}
	var kh bcrypt.KEY_HANDLE
	if err := bcrypt.GenerateSymmetricKey(alg, &kh, nil, password, 0); err != nil {
		return nil, err
	}
	defer bcrypt.DestroyKey(kh)
	u16HashID := utf16FromString(hashID)
	buffers := [...]bcrypt.Buffer{
		{
			Type:   bcrypt.KDF_ITERATION_COUNT,
			Data:   uintptr(unsafe.Pointer(&iter)),
			Length: 8,
		},
		{
			Type:   bcrypt.KDF_SALT,
			Data:   uintptr(unsafe.Pointer(&salt[0])),
			Length: uint32(len(salt)),
		},
		{
			Type:   bcrypt.KDF_HASH_ALGORITHM,
			Data:   uintptr(unsafe.Pointer(&u16HashID[0])),
			Length: uint32(len(u16HashID) * 2),
		},
	}
	params := &bcrypt.BufferDesc{
		Count:   uint32(len(buffers)),
		Buffers: &buffers[0],
	}
	out := make([]byte, keyLen)
	var size uint32
	err = bcrypt.KeyDerivation(kh, params, out, &size, 0)
	if err != nil {
		return nil, err
	}
	return out[:size], nil
}
