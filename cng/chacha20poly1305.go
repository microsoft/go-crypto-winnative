// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"crypto/cipher"
	"errors"
	"runtime"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
	"github.com/microsoft/go-crypto-winnative/internal/subtle"
)

const (
	chacha20Poly1305KeySize   = 32
	chacha20Poly1305NonceSize = 12
	chacha20Poly1305Overhead  = 16
)

func SupportsChaCha20Poly1305() bool {
	_, err := loadCipher(bcrypt.CHACHA20_POLY1305_ALGORITHM, "")
	return err == nil
}

type chacha20poly1305 struct {
	kh bcrypt.KEY_HANDLE
}

func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if len(key) != chacha20Poly1305KeySize {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	kh, err := newCipherHandle(bcrypt.CHACHA20_POLY1305_ALGORITHM, "", key)
	if err != nil {
		return nil, err
	}
	c := &chacha20poly1305{kh: kh}
	runtime.SetFinalizer(c, (*chacha20poly1305).finalize)
	return c, nil
}

func (c *chacha20poly1305) finalize() {
	if c.kh != 0 {
		bcrypt.DestroyKey(c.kh)
	}
}

func (c *chacha20poly1305) NonceSize() int {
	return chacha20Poly1305NonceSize
}

func (c *chacha20poly1305) Overhead() int {
	return chacha20Poly1305Overhead
}

func (c *chacha20poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != chacha20Poly1305NonceSize {
		panic("chacha20poly1305: bad nonce length passed to Seal")
	}

	if uint64(len(plaintext)) > (1<<38)-64 {
		panic("chacha20poly1305: plaintext too large")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+chacha20Poly1305Overhead)
	if subtle.InexactOverlap(out, plaintext) {
		panic("chacha20poly1305: invalid buffer overlap of output and input")
	}
	if subtle.AnyOverlap(out, additionalData) {
		panic("chacha20poly1305: invalid buffer overlap of output and additional data")
	}
	info := bcrypt.NewAUTHENTICATED_CIPHER_MODE_INFO(nonce, additionalData, out[len(out)-chacha20Poly1305Overhead:])
	var encSize uint32
	if err := bcrypt.Encrypt(c.kh, plaintext, unsafe.Pointer(info), nil, out, &encSize, 0); err != nil {
		panic("chacha20poly1305: encryption failed: " + err.Error())
	}
	if int(encSize) != len(plaintext) {
		panic("chacha20poly1305: plaintext not fully encrypted")
	}
	runtime.KeepAlive(c)
	return ret
}

func (c *chacha20poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != chacha20Poly1305NonceSize {
		panic("chacha20poly1305: bad nonce length passed to Open")
	}
	if len(ciphertext) < 16 {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > (1<<38)-48 {
		panic("chacha20poly1305: ciphertext too large")
	}
	tag := ciphertext[len(ciphertext)-chacha20Poly1305Overhead:]
	ciphertext = ciphertext[:len(ciphertext)-chacha20Poly1305Overhead]
	// Make room in dst to append ciphertext without tag.
	ret, out := sliceForAppend(dst, len(ciphertext))
	if subtle.InexactOverlap(out, ciphertext) {
		panic("chacha20poly1305: invalid buffer overlap of output and input")
	}
	if subtle.AnyOverlap(out, additionalData) {
		panic("chacha20poly1305: invalid buffer overlap of output and additional data")
	}
	info := bcrypt.NewAUTHENTICATED_CIPHER_MODE_INFO(nonce, additionalData, tag)
	var decSize uint32
	err := bcrypt.Decrypt(c.kh, ciphertext, unsafe.Pointer(info), nil, out, &decSize, 0)
	if err != nil || int(decSize) != len(ciphertext) {
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}
	runtime.KeepAlive(c)
	return ret, nil
}
