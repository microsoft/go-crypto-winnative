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
	return loadOrStoreAlg(bcrypt.PBKDF2_ALGORITHM, bcrypt.ALG_NONE_FLAG, "", func(h bcrypt.ALG_HANDLE) (bcrypt.ALG_HANDLE, error) {
		return h, nil
	})
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
	buffers := make([]bcrypt.Buffer, 0, 3)
	buffers = append(buffers,
		bcrypt.Buffer{
			Type:   bcrypt.KDF_ITERATION_COUNT,
			Data:   uintptr(unsafe.Pointer(&iter)),
			Length: 8,
		},
		bcrypt.Buffer{
			Type:   bcrypt.KDF_HASH_ALGORITHM,
			Data:   uintptr(unsafe.Pointer(&u16HashID[0])),
			Length: uint32(len(u16HashID) * 2),
		})
	if len(salt) > 0 {
		// The salt is optional.
		buffers = append(buffers, bcrypt.Buffer{
			Type:   bcrypt.KDF_SALT,
			Data:   uintptr(unsafe.Pointer(&salt[0])),
			Length: uint32(len(salt)),
		})
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
