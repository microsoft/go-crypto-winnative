// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"crypto/cipher"
	"runtime"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
	"github.com/microsoft/go-crypto-winnative/internal/subtle"
)

const desBlockSize = 8

type desCipher struct {
	kh bcrypt.KEY_HANDLE
}

func NewDESCipher(key []byte) (cipher.Block, error) {
	kh, err := newCipherHandle(bcrypt.DES_ALGORITHM, "", key)
	if err != nil {
		return nil, err
	}
	c := &desCipher{kh: kh}
	runtime.SetFinalizer(c, (*desCipher).finalize)
	return c, nil
}

func NewTripleDESCipher(key []byte) (cipher.Block, error) {
	kh, err := newCipherHandle(bcrypt.DES3_ALGORITHM, "", key)
	if err != nil {
		return nil, err
	}
	c := &desCipher{kh: kh}
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
