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
	n       int // count of bytes requested from Read
	// buf contains the derived data.
	// len(buf) can be larger than n, as Read may derive
	// more data than requested and cache it in buf.
	buf []byte
}

func (c *hkdf) finalize() {
	bcrypt.DestroyKey(c.hkey)
}

func hkdfDerive(hkey bcrypt.KEY_HANDLE, info, out []byte) (int, error) {
	var params *bcrypt.BufferDesc
	if len(info) > 0 {
		params = &bcrypt.BufferDesc{
			Count: 1,
			Buffers: &bcrypt.Buffer{
				Length: uint32(len(info)),
				Type:   bcrypt.KDF_HKDF_INFO,
				Data:   uintptr(unsafe.Pointer(&info[0])),
			},
		}
		defer runtime.KeepAlive(params)
	}
	var n uint32
	err := bcrypt.KeyDerivation(hkey, params, out, &n, 0)
	return int(n), err
}

func (c *hkdf) Read(p []byte) (int, error) {
	// KeyDerivation doesn't support incremental output, each call
	// derives the key from scratch and returns the requested bytes.
	// To implement io.Reader, we need to ask for len(c.buf) + len(p)
	// bytes and copy the last derived len(p) bytes to p.
	maxDerived := 255 * c.hashLen
	totalDerived := c.n + len(p)
	// Check whether enough data can be derived.
	if totalDerived > maxDerived {
		return 0, errors.New("hkdf: entropy limit reached")
	}
	// Check whether c.buf already contains enough derived data,
	// otherwise derive more data.
	if bytesNeeded := totalDerived - len(c.buf); bytesNeeded > 0 {
		// It is common to derive multiple equally sized keys from the same HKDF instance.
		// Optimize this case by allocating a buffer large enough to hold
		// at least 3 of such keys each time there is not enough data.
		blocks := bytesNeeded / c.hashLen
		if bytesNeeded%c.hashLen != 0 {
			// Round up to the next multiple of hashLen.
			blocks += 1
		}
		const minBlocks = 3
		if blocks < minBlocks {
			blocks = minBlocks
		}
		alloc := blocks * c.hashLen
		if len(c.buf)+alloc > maxDerived {
			// The buffer can't grow beyond maxDerived.
			alloc = maxDerived - len(c.buf)
		}
		c.buf = append(c.buf, make([]byte, alloc)...)
		n, err := hkdfDerive(c.hkey, c.info, c.buf)
		if err != nil {
			c.buf = c.buf[:c.n]
			return 0, err
		}
		// Adjust totalDerived to the actual number of bytes derived.
		totalDerived = n
	}
	n := copy(p, c.buf[c.n:totalDerived])
	c.n += n
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
	k := &hkdf{kh, info, ch.Size(), nil, 0}
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
