// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"errors"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

type cipherAlgorithm struct {
	handle            bcrypt.ALG_HANDLE
	allowedKeyLengths bcrypt.KEY_LENGTHS_STRUCT
}

func loadCipher(id, mode string) (cipherAlgorithm, error) {
	v, err := loadOrStoreAlg(id, bcrypt.ALG_NONE_FLAG, mode, func(h bcrypt.ALG_HANDLE) (interface{}, error) {
		if mode != "" {
			// Windows 8 added support to set the CipherMode value on a key,
			// but Windows 7 requires that it be set on the algorithm before key creation.
			err := setString(bcrypt.HANDLE(h), bcrypt.CHAINING_MODE, mode)
			if err != nil {
				return nil, err
			}
		}
		lengths, err := getKeyLengths(bcrypt.HANDLE(h))
		if err != nil {
			return nil, err
		}
		return cipherAlgorithm{h, lengths}, nil
	})
	if err != nil {
		return cipherAlgorithm{}, err
	}
	return v.(cipherAlgorithm), nil
}

func newCipherHandle(id, mode string, key []byte) (bcrypt.KEY_HANDLE, error) {
	h, err := loadCipher(id, mode)
	if err != nil {
		return 0, err
	}
	if !keyIsAllowed(h.allowedKeyLengths, uint32(len(key)*8)) {
		return 0, errors.New("crypto/cipher: invalid key size")
	}
	var kh bcrypt.KEY_HANDLE
	err = bcrypt.GenerateSymmetricKey(h.handle, &kh, nil, key, 0)
	if err != nil {
		return 0, err
	}
	return kh, nil
}
