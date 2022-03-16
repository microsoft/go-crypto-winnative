// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"crypto/cipher"
	"errors"
	"runtime"
	"sync"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
	"github.com/microsoft/go-crypto-winnative/internal/subtle"
)

const aesBlockSize = 16

var aesCache sync.Map

type aesAlgorithm struct {
	h               bcrypt.ALG_HANDLE
	allowedKeySized []int
}

type aesCacheEntry struct {
	id   string
	mode string
}

func loadAes(id string, mode string) (h aesAlgorithm, err error) {
	if v, ok := aesCache.Load(aesCacheEntry{id, mode}); ok {
		return v.(aesAlgorithm), nil
	}
	err = bcrypt.OpenAlgorithmProvider(&h.h, utf16PtrFromString(id), nil, bcrypt.ALG_NONE_FLAG)
	if err != nil {
		return
	}
	// Windows 8 added support to set the CipherMode value on a key,
	// but Windows 7 requires that it be set on the algorithm before key creation.
	err = setString(bcrypt.HANDLE(h.h), bcrypt.CHAINING_MODE, mode)
	if err != nil {
		return
	}
	var info bcrypt.KEY_LENGTHS_STRUCT
	var discard uint32
	err = bcrypt.GetProperty(bcrypt.HANDLE(h.h), utf16PtrFromString(bcrypt.KEY_LENGTHS), (*(*[1<<31 - 1]byte)(unsafe.Pointer(&info)))[:unsafe.Sizeof(info)], &discard, 0)
	if err != nil {
		return
	}
	for size := info.MinLength; size <= info.MaxLength; size += info.Increment {
		h.allowedKeySized = append(h.allowedKeySized, int(size))
	}
	aesCache.Store(aesCacheEntry{id, mode}, h)
	return
}

type aesCipher struct {
	kh  bcrypt.KEY_HANDLE
	key []byte
}

func NewAESCipher(key []byte) (cipher.Block, error) {
	h, err := loadAes(bcrypt.AES_ALGORITHM, bcrypt.CHAIN_MODE_ECB)
	if err != nil {
		return nil, err
	}
	var allowedKeySize bool
	for _, size := range h.allowedKeySized {
		if len(key)*8 == size {
			allowedKeySize = true
			break
		}
	}
	if !allowedKeySize {
		return nil, errors.New("crypto/cipher: invalid key size")
	}
	c := &aesCipher{key: make([]byte, len(key))}
	copy(c.key, key)
	err = bcrypt.GenerateSymmetricKey(h.h, &c.kh, nil, 0, &c.key[0], uint32(len(c.key)), 0)
	if err != nil {
		return nil, err
	}
	runtime.SetFinalizer(c, (*aesCipher).finalize)
	return c, nil
}

func (c *aesCipher) finalize() {
	bcrypt.DestroyKey(c.kh)
}

func (c *aesCipher) BlockSize() int { return aesBlockSize }

func (c *aesCipher) Encrypt(dst, src []byte) {
	if subtle.InexactOverlap(dst, src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(src) < aesBlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < aesBlockSize {
		panic("crypto/aes: output not full block")
	}
	var ret uint32
	err := bcrypt.Encrypt(c.kh, &src[0], uint32(len(src)), 0, nil, 0, &dst[0], uint32(len(dst)), &ret, 0)
	if err != nil {
		panic(err)
	}
	if int(ret) != len(src) {
		panic("crypto/aes: plaintext not fully encrypted")
	}
	runtime.KeepAlive(c)
}

func (c *aesCipher) Decrypt(dst, src []byte) {
	if subtle.InexactOverlap(dst, src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(src) < aesBlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < aesBlockSize {
		panic("crypto/aes: output not full block")
	}

	var ret uint32
	err := bcrypt.Decrypt(c.kh, &src[0], uint32(len(src)), 0, nil, 0, &dst[0], uint32(len(dst)), &ret, 0)
	if err != nil {
		panic(err)
	}
	if int(ret) != len(src) {
		panic("crypto/aes: plaintext not fully decrypted")
	}
	runtime.KeepAlive(c)
}
