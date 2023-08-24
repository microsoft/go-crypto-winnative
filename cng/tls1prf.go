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

func loadTLS1PRF(id string) (bcrypt.ALG_HANDLE, error) {
	h, err := loadOrStoreAlg(id, 0, "", func(h bcrypt.ALG_HANDLE) (interface{}, error) {
		return h, nil
	})
	if err != nil {
		return 0, err
	}
	return h.(bcrypt.ALG_HANDLE), nil
}

func TLS1PRF(secret, label, seed []byte, keyLen int, h func() hash.Hash) ([]byte, error) {
	algID := bcrypt.TLS1_1_KDF_ALGORITHM
	var hashID string
	if h != nil {
		// TLS 1.0/1.1 PRF doesn't allow to specify the hash function,
		// it always uses MD5SHA1. If h is nil, then assume
		// that the caller wants to use TLS 1.1 PRF.
		if hashID = hashToID(h()); hashID == "" {
			return nil, errors.New("cng: unsupported hash function")
		}
		algID = bcrypt.TLS1_2_KDF_ALGORITHM
	}

	alg, err := loadTLS1PRF(algID)
	if err != nil {
		return nil, err
	}
	var kh bcrypt.KEY_HANDLE
	if err := bcrypt.GenerateSymmetricKey(alg, &kh, nil, secret, 0); err != nil {
		return nil, err
	}

	buffers := make([]bcrypt.Buffer, 0, 3)
	if len(label) > 0 {
		buffers = append(buffers, bcrypt.Buffer{
			Type:   bcrypt.KDF_TLS_PRF_LABEL,
			Data:   uintptr(unsafe.Pointer(&label[0])),
			Length: uint32(len(label)),
		})
	}
	if len(seed) > 0 {
		buffers = append(buffers, bcrypt.Buffer{
			Type:   bcrypt.KDF_TLS_PRF_SEED,
			Data:   uintptr(unsafe.Pointer(&seed[0])),
			Length: uint32(len(seed)),
		})
	}
	if algID == bcrypt.TLS1_2_KDF_ALGORITHM {
		u16HashID := utf16FromString(hashID)
		buffers = append(buffers, bcrypt.Buffer{
			Type:   bcrypt.KDF_HASH_ALGORITHM,
			Data:   uintptr(unsafe.Pointer(&u16HashID[0])),
			Length: uint32(len(u16HashID) * 2),
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
