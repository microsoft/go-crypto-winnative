// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"runtime"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
	"github.com/microsoft/go-crypto-winnative/internal/subtle"
)

// A RC4Cipher is an instance of RC4 using a particular key.
type RC4Cipher struct {
	kh bcrypt.KEY_HANDLE
}

// NewRC4Cipher creates and returns a new Cipher.
func NewRC4Cipher(key []byte) (*RC4Cipher, error) {
	kh, err := newCipherHandle(bcrypt.RC4_ALGORITHM, "", key)
	if err != nil {
		return nil, err
	}
	c := &RC4Cipher{kh: kh}
	runtime.SetFinalizer(c, (*RC4Cipher).finalize)
	return c, nil
}

func (c *RC4Cipher) finalize() {
	if c.kh != 0 {
		bcrypt.DestroyKey(c.kh)
	}
}

// Reset zeros the key data and makes the Cipher unusable.
func (c *RC4Cipher) Reset() {
	bcrypt.DestroyKey(c.kh)
	c.kh = 0
}

// XORKeyStream sets dst to the result of XORing src with the key stream.
// Dst and src must overlap entirely or not at all.
func (c *RC4Cipher) XORKeyStream(dst, src []byte) {
	if c.kh == 0 || len(src) == 0 {
		return
	}
	// rc4.Cipher.XORKeyStream throws an out of bond panic if
	// dst is smaller than src. Replicate the same behavior here.
	_ = dst[len(src)-1]

	if subtle.InexactOverlap(dst[:len(src)], src) {
		panic("crypto/rc4: invalid buffer overlap")
	}
	var outLen uint32
	if err := bcrypt.Encrypt(c.kh, src, nil, nil, dst, &outLen, 0); err != nil {
		panic("crypto/rc4: encryption failed: " + err.Error())
	}
	if int(outLen) != len(src) {
		panic("crypto/rc4: src not fully XORed")
	}
	runtime.KeepAlive(c)
}
