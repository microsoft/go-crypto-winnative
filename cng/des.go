// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"bytes"
	"crypto/cipher"
	"runtime"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
	"github.com/microsoft/go-crypto-winnative/internal/subtle"
)

const desBlockSize = 8

type desCipher struct {
	kh  bcrypt.KEY_HANDLE
	alg string
	key []byte
}

func NewDESCipher(key []byte) (cipher.Block, error) {
	kh, err := newCipherHandle(bcrypt.DES_ALGORITHM, bcrypt.CHAIN_MODE_ECB, key)
	if err != nil {
		return nil, err
	}
	c := &desCipher{kh: kh, alg: bcrypt.DES_ALGORITHM, key: bytes.Clone(key)}
	runtime.AddCleanup(c, destroyKey, kh)
	return c, nil
}

func NewTripleDESCipher(key []byte) (cipher.Block, error) {
	kh, err := newCipherHandle(bcrypt.DES3_ALGORITHM, bcrypt.CHAIN_MODE_ECB, key)
	if err != nil {
		return nil, err
	}
	c := &desCipher{kh: kh, alg: bcrypt.DES3_ALGORITHM, key: bytes.Clone(key)}
	runtime.AddCleanup(c, destroyKey, kh)
	return c, nil
}

func (c *desCipher) BlockSize() int { return desBlockSize }

func (c *desCipher) Encrypt(dst, src []byte) {
	if len(src) < desBlockSize {
		panic("crypto/des: input not full block")
	}
	if len(dst) < desBlockSize {
		panic("crypto/des: output not full block")
	}
	// cypher.Block.Encrypt() is documented to encrypt one full block
	// at a time, so we truncate the input and output to the block size.
	dst, src = dst[:desBlockSize], src[:desBlockSize]
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
	// cypher.Block.Decrypt() is documented to decrypt one full block
	// at a time, so we truncate the input and output to the block size.
	dst, src = dst[:desBlockSize], src[:desBlockSize]
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

func (c *desCipher) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	return newCBC(true, c.alg, c.key, iv)
}

func (c *desCipher) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	return newCBC(false, c.alg, c.key, iv)
}
