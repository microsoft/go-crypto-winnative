// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"errors"
	"hash"
	"runtime"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

func SupportsHKDF() bool {
	_, err := loadHKDF()
	return err == nil
}

func loadHKDF() (bcrypt.ALG_HANDLE, error) {
	return loadOrStoreAlg(bcrypt.HKDF_ALGORITHM, bcrypt.ALG_NONE_FLAG, "", func(h bcrypt.ALG_HANDLE) (bcrypt.ALG_HANDLE, error) {
		return h, nil
	})
}

func newHKDF(h func() hash.Hash, secret, salt []byte) (bcrypt.KEY_HANDLE, error) {
	ch := h()
	hashID := hashToID(ch)
	if hashID == "" {
		return 0, errors.New("cng: unsupported hash function")
	}
	alg, err := loadHKDF()
	if err != nil {
		return 0, err
	}
	var kh bcrypt.KEY_HANDLE
	if err := bcrypt.GenerateSymmetricKey(alg, &kh, nil, secret, 0); err != nil {
		return 0, err
	}
	if err := setString(bcrypt.HANDLE(kh), bcrypt.HKDF_HASH_ALGORITHM, hashID); err != nil {
		bcrypt.DestroyKey(kh)
		return 0, err
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
		return 0, err
	}
	return kh, nil
}

func ExtractHKDF(h func() hash.Hash, secret, salt []byte) ([]byte, error) {
	if salt == nil {
		// Replicate x/crypto/hkdf behavior.
		salt = make([]byte, h().Size())
	}
	kh, err := newHKDF(h, secret, salt)
	if err != nil {
		return nil, err
	}
	defer bcrypt.DestroyKey(kh)
	hdr, blob, err := exportKeyData(kh)
	if err != nil {
		return nil, err
	}
	if hdr.Version != bcrypt.KEY_DATA_BLOB_VERSION1 {
		return nil, errors.New("cng: unknown key data blob version")
	}
	// KEY_DATA_BLOB_VERSION1 format is:
	// cbHashName uint32 // Big-endian
	// pHashName [cbHash]byte
	// key []byte // Rest of the blob
	if len(blob) < 4 {
		return nil, errors.New("cng: exported key is corrupted")
	}
	cbHashName := bigEndianUint32(blob)
	blob = blob[4:]
	if len(blob) < int(cbHashName) {
		return nil, errors.New("cng: exported key is corrupted")
	}
	// Skip pHashName.
	return blob[cbHashName:], nil
}

// ExpandHKDF derives a key from the given hash, key, and optional context info.
func ExpandHKDF(h func() hash.Hash, pseudorandomKey, info []byte, keyLength int) ([]byte, error) {
	kh, err := newHKDF(h, pseudorandomKey, nil)
	if err != nil {
		return nil, err
	}
	defer bcrypt.DestroyKey(kh)
	out := make([]byte, keyLength)
	if len(out) == 0 {
		// Nothing to do, and CNG doesn't like zero-length output buffers.
		// Call newHKDF, though, to validate parameters.
		return out, nil
	}
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
	err = bcrypt.KeyDerivation(kh, params, out, &n, 0)
	if err != nil {
		return nil, err
	}
	if int(n) != keyLength {
		return nil, errors.New("cng: key derivation returned unexpected length")
	}
	return out, err
}

func bigEndianUint32(b []byte) uint32 {
	_ = b[3] // bounds check hint to compiler; see golang.org/issue/14808
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}
