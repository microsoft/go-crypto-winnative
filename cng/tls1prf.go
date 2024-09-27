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
	return loadOrStoreAlg(id, bcrypt.ALG_NONE_FLAG, "", func(h bcrypt.ALG_HANDLE) (bcrypt.ALG_HANDLE, error) {
		return h, nil
	})
}

// TLS1PRF implements the TLS 1.0/1.1 pseudo-random function if h is nil,
// else it implements the TLS 1.2 pseudo-random function.
// The pseudo-random number will be written to result and will be of length len(result).
func TLS1PRF(result, secret, label, seed []byte, h func() hash.Hash) error {
	// TLS 1.0/1.1 PRF uses MD5SHA1.
	algID := bcrypt.TLS1_1_KDF_ALGORITHM
	var hashID string
	if h != nil {
		// If h is specified, assume the caller wants to use TLS 1.2 PRF.
		// TLS 1.0/1.1 PRF doesn't allow specifying the hash function.
		if hashID = hashToID(h()); hashID == "" {
			return errors.New("cng: unsupported hash function")
		}
		algID = bcrypt.TLS1_2_KDF_ALGORITHM
	}

	alg, err := loadTLS1PRF(algID)
	if err != nil {
		return err
	}
	var kh bcrypt.KEY_HANDLE
	if err := bcrypt.GenerateSymmetricKey(alg, &kh, nil, secret, 0); err != nil {
		return err
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
	var size uint32
	err = bcrypt.KeyDerivation(kh, params, result, &size, 0)
	if err != nil {
		return err
	}
	// The Go standard library expects TLS1PRF to return the requested number of bytes,
	// fail if it doesn't. While there is no known situation where this will happen,
	// BCryptKeyDerivation handles multiple algorithms and there could be a subtle mismatch
	// after more code changes in the future.
	if size != uint32(len(result)) {
		return errors.New("tls1-prf: derived less bytes than requested")
	}
	return nil
}
