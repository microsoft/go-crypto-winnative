// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"runtime"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

func SupportsHKDF() bool {
	_, err := loadHKDF()
	return err == nil
}

func loadHKDF() (bcrypt.ALG_HANDLE, error) {
	h, err := loadOrStoreAlg(bcrypt.HKDF_ALGORITHM, 0, "", func(h bcrypt.ALG_HANDLE) (interface{}, error) {
		return h, nil
	})
	if err != nil {
		return 0, err
	}
	return h.(bcrypt.ALG_HANDLE), nil
}

type hkdf struct {
	hkey bcrypt.KEY_HANDLE
	info []byte

	hashLen int
	buf     []byte
}

func (c *hkdf) finalize() {
	bcrypt.DestroyKey(c.hkey)
}

func (c *hkdf) Read(p []byte) (int, error) {
	var params *bcrypt.BufferDesc
	if len(c.info) > 0 {
		params = &bcrypt.BufferDesc{
			Count: 1,
			Buffers: &bcrypt.Buffer{
				Length: uint32(len(c.info)),
				Type:   bcrypt.KDF_HKDF_INFO,
				Data:   uintptr(unsafe.Pointer(&c.info[0])),
			},
		}
	}
	// KeyDerivation doesn't support incremental output, each call
	// derives the key from scratch and returns the requested bytes.
	// To implement io.Reader, we need to ask for len(c.buf) + len(p)
	// bytes and copy the last derived len(p) bytes to p.
	// We use c.buf to know how many bytes we've already derived and
	// to avoid allocating the whole output buffer on each call.
	prevLen := len(c.buf)
	needLen := len(p)
	remains := 255*c.hashLen - prevLen
	// Check whether enough data can be generated.
	if remains < needLen {
		return 0, errors.New("hkdf: entropy limit reached")
	}
	c.buf = append(c.buf, make([]byte, needLen)...)
	var size uint32
	if err := bcrypt.KeyDerivation(c.hkey, params, c.buf, &size, 0); err != nil {
		return 0, err
	}
	runtime.KeepAlive(params)
	n := copy(p, c.buf[prevLen:size])
	return n, nil
}

func newHKDF(h func() hash.Hash, secret, salt []byte, info []byte) (*hkdf, error) {
	ch := h()
	hashID := hashToID(ch)
	if hashID == "" {
		return nil, errors.New("cng: unsupported hash function")
	}
	alg, err := loadHKDF()
	if err != nil {
		return nil, err
	}
	var kh bcrypt.KEY_HANDLE
	if err := bcrypt.GenerateSymmetricKey(alg, &kh, nil, secret, 0); err != nil {
		return nil, err
	}
	if err := setString(bcrypt.HANDLE(kh), bcrypt.HKDF_HASH_ALGORITHM, hashID); err != nil {
		bcrypt.DestroyKey(kh)
		return nil, err
	}
	if salt != nil {
		// Used for Extract.
		err = bcrypt.SetProperty(bcrypt.HANDLE(kh), utf16PtrFromString(bcrypt.HKDF_SALT_AND_FINALIZE), salt, 0)
	} else {
		// Used for Expand.
		err = bcrypt.SetProperty(bcrypt.HANDLE(kh), utf16PtrFromString(bcrypt.HKDF_PRK_AND_FINALIZE), nil, 0)
	}
	if err != nil {
		bcrypt.DestroyKey(kh)
		return nil, err
	}
	k := &hkdf{kh, info, ch.Size(), nil}
	runtime.SetFinalizer(k, (*hkdf).finalize)
	return k, nil
}

func ExtractHKDF(h func() hash.Hash, secret, salt []byte) ([]byte, error) {
	if salt == nil {
		// Replicate x/crypto/hkdf behavior.
		salt = make([]byte, h().Size())
	}
	kh, err := newHKDF(h, secret, salt, nil)
	if err != nil {
		return nil, err
	}
	hdr, blob, err := exportKeyData(kh.hkey)
	if err != nil {
		return nil, err
	}
	runtime.KeepAlive(kh)
	if hdr.Version != bcrypt.KEY_DATA_BLOB_VERSION1 {
		return nil, errors.New("cng: unknown key data blob version")
	}
	// KEY_DATA_BLOB_VERSION1 format is:
	// cbHash uint32 // Big-endian
	// hashName [cbHash]byte
	// key []byte // Rest of the blob
	if len(blob) < 4 {
		return nil, errors.New("cng: exported key is corrupted")
	}
	hashLength := binary.BigEndian.Uint32(blob[:])
	return blob[4+hashLength:], nil
}

func ExpandHKDF(h func() hash.Hash, pseudorandomKey, info []byte) (io.Reader, error) {
	kh, err := newHKDF(h, pseudorandomKey, nil, info)
	if err != nil {
		return nil, err
	}
	return kh, nil
}
