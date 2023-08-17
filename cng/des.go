// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"crypto/cipher"
	"errors"
	"runtime"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
	"github.com/microsoft/go-crypto-winnative/internal/subtle"
)

const desBlockSize = 8

type desAlgorithm struct {
	handle            bcrypt.ALG_HANDLE
	allowedKeyLengths bcrypt.KEY_LENGTHS_STRUCT
}

func loadDES(want3DES bool) (desAlgorithm, error) {
	id := bcrypt.DES_ALGORITHM
	if want3DES {
		id = bcrypt.DES3_ALGORITHM
	}
	v, err := loadOrStoreAlg(id, bcrypt.ALG_NONE_FLAG, "", func(h bcrypt.ALG_HANDLE) (interface{}, error) {
		lengths, err := getKeyLengths(bcrypt.HANDLE(h))
		if err != nil {
			return nil, err
		}
		return desAlgorithm{h, lengths}, nil
	})
	if err != nil {
		return desAlgorithm{}, nil
	}
	return v.(desAlgorithm), nil
}

type desCipher struct {
	kh  bcrypt.KEY_HANDLE
	key []byte
}

func NewDESCipher(key []byte) (cipher.Block, error) {
	return newDESCipher(key, false)
}

func NewTripleDESCipher(key []byte) (cipher.Block, error) {
	return newDESCipher(key, true)
}

func newDESCipher(key []byte, want3DES bool) (cipher.Block, error) {
	h, err := loadDES(want3DES)
	if err != nil {
		return nil, err
	}
	if !keyIsAllowed(h.allowedKeyLengths, uint32(len(key)*8)) {
		return nil, errors.New("crypto/des: invalid key size")
	}
	c := &desCipher{key: make([]byte, len(key))}
	copy(c.key, key)
	err = bcrypt.GenerateSymmetricKey(h.handle, &c.kh, nil, c.key, 0)
	if err != nil {
		return nil, err
	}
	runtime.SetFinalizer(c, (*desCipher).finalize)
	return c, nil
}

func (c *desCipher) finalize() {
	bcrypt.DestroyKey(c.kh)
}

func (c *desCipher) BlockSize() int { return desBlockSize }

func (c *desCipher) Encrypt(dst, src []byte) {
	if len(src) < desBlockSize {
		panic("crypto/des: input not full block")
	}
	if len(dst) < desBlockSize {
		panic("crypto/des: output not full block")
	}
	if subtle.InexactOverlap(dst, src) {
		panic("crypto/des: invalid buffer overlap")
	}
	var ret uint32
	err := bcrypt.Encrypt(c.kh, src, nil, nil, dst, &ret, 0)
	if err != nil {
		panic(err)
	}
	if int(ret) != len(src) {
		panic("crypto/des: plaintext not fully encrypted")
	}
	runtime.KeepAlive(c)
}

func (c *desCipher) Decrypt(dst, src []byte) {
	if len(src) < desBlockSize {
		panic("crypto/des: input not full block")
	}
	if len(dst) < desBlockSize {
		panic("crypto/des: output not full block")
	}
	if subtle.InexactOverlap(dst, src) {
		panic("crypto/des: invalid buffer overlap")
	}

	var ret uint32
	err := bcrypt.Decrypt(c.kh, src, nil, nil, dst, &ret, 0)
	if err != nil {
		panic(err)
	}
	if int(ret) != len(src) {
		panic("crypto/des: plaintext not fully decrypted")
	}
	runtime.KeepAlive(c)
}
