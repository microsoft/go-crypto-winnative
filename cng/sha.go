// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"hash"
	"runtime"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

func writeSha(ctx bcrypt.HASH_HANDLE, p []byte) (err error) {
	var n int
	for n < len(p) && err == nil {
		nn := lenU32(p[n:])
		err = bcrypt.HashData(ctx, p[n:n+nn], 0)
		n += nn
	}
	return err
}

func shaOneShot(id string, p, sum []byte) error {
	h, err := loadSha(id, 0)
	if err != nil {
		return err
	}
	var buf []byte
	// fbuf is a stack-allocated memory buffer big enough to hold all supported SHA types,
	// tested on a Windows 11 10.0.22000 x64 machine.
	// If the SHA object requires more memory, buf will be nil
	// and bcrypt.CreateHash will internally heap-allocate the necessary memory.
	// This is a performance optimization which boost one-shot SHAs ~10%.
	var fbuf [512]byte
	if h.objectLength <= uint32(len(fbuf)) {
		buf = fbuf[:h.objectLength]
	}
	var ctx bcrypt.HASH_HANDLE
	err = bcrypt.CreateHash(h.h, &ctx, buf, nil, 0)
	if err != nil {
		return err
	}
	defer bcrypt.DestroyHash(ctx)
	err = writeSha(ctx, p)
	if err != nil {
		return err
	}
	err = bcrypt.FinishHash(ctx, sum, 0)
	if err != nil {
		return err
	}
	runtime.KeepAlive(fbuf)
	return nil
}

func SHA1(p []byte) (sum [20]byte) {
	if err := shaOneShot(bcrypt.SHA1_ALGORITHM, p, sum[:]); err != nil {
		panic("bcrypt: SHA1 failed")
	}
	return
}

func SHA256(p []byte) (sum [32]byte) {
	if err := shaOneShot(bcrypt.SHA256_ALGORITHM, p, sum[:]); err != nil {
		panic("bcrypt: SHA256 failed")
	}
	return
}

func SHA384(p []byte) (sum [48]byte) {
	if err := shaOneShot(bcrypt.SHA384_ALGORITHM, p, sum[:]); err != nil {
		panic("bcrypt: SHA384 failed")
	}
	return
}

func SHA512(p []byte) (sum [64]byte) {
	if err := shaOneShot(bcrypt.SHA512_ALGORITHM, p, sum[:]); err != nil {
		panic("bcrypt: SHA512 failed")
	}
	return
}

// NewSHA1 returns a new SHA1 hash.
func NewSHA1() hash.Hash {
	return newSHAX(bcrypt.SHA1_ALGORITHM, nil)
}

// NewSHA256 returns a new SHA256 hash.
func NewSHA256() hash.Hash {
	return newSHAX(bcrypt.SHA256_ALGORITHM, nil)
}

// NewSHA384 returns a new SHA384 hash.
func NewSHA384() hash.Hash {
	return newSHAX(bcrypt.SHA384_ALGORITHM, nil)
}

// NewSHA512 returns a new SHA512 hash.
func NewSHA512() hash.Hash {
	return newSHAX(bcrypt.SHA512_ALGORITHM, nil)
}

type shaAlgorithm struct {
	h            bcrypt.ALG_HANDLE
	size         uint32
	blockSize    uint32
	objectLength uint32
}

func loadSha(id string, flags bcrypt.AlgorithmProviderFlags) (shaAlgorithm, error) {
	v, err := loadOrStoreAlg(id, flags, "", func(h bcrypt.ALG_HANDLE) (interface{}, error) {
		size, err := getUint32(bcrypt.HANDLE(h), bcrypt.HASH_LENGTH)
		if err != nil {
			return nil, err
		}
		blockSize, err := getUint32(bcrypt.HANDLE(h), bcrypt.HASH_BLOCK_LENGTH)
		if err != nil {
			return nil, err
		}
		objectLength, err := getUint32(bcrypt.HANDLE(h), bcrypt.OBJECT_LENGTH)
		if err != nil {
			return nil, err
		}
		return shaAlgorithm{h, size, blockSize, objectLength}, nil
	})
	if err != nil {
		return shaAlgorithm{}, err
	}
	return v.(shaAlgorithm), nil
}

type shaXHash struct {
	h         bcrypt.ALG_HANDLE
	ctx       bcrypt.HASH_HANDLE
	size      int
	blockSize int
	buf       []byte
	key       []byte
}

func newSHAX(id string, key []byte) *shaXHash {
	var flag bcrypt.AlgorithmProviderFlags
	if len(key) > 0 {
		flag = bcrypt.ALG_HANDLE_HMAC_FLAG
	}
	h, err := loadSha(id, flag)
	if err != nil {
		panic(err)
	}
	sha := new(shaXHash)
	sha.h = h.h
	sha.size = int(h.size)
	sha.blockSize = int(h.blockSize)
	sha.buf = make([]byte, sha.size)
	if len(key) > 0 {
		sha.key = make([]byte, len(key))
		copy(sha.key, key)
	}
	sha.Reset()
	runtime.SetFinalizer(sha, (*shaXHash).finalize)
	return sha
}

func (h *shaXHash) finalize() {
	if h.ctx != 0 {
		bcrypt.DestroyHash(h.ctx)
	}
}

func (h *shaXHash) Reset() {
	if h.ctx != 0 {
		bcrypt.DestroyHash(h.ctx)
		h.ctx = 0
	}
	err := bcrypt.CreateHash(h.h, &h.ctx, nil, h.key, 0)
	if err != nil {
		panic(err)
	}
	runtime.KeepAlive(h)
}

func (h *shaXHash) Write(p []byte) (n int, err error) {
	err = writeSha(h.ctx, p)
	if err != nil {
		// hash.Hash interface mandates Write should never return an error.
		panic(err)
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h *shaXHash) Size() int {
	return h.size
}

func (h *shaXHash) BlockSize() int {
	return h.blockSize
}

func (h *shaXHash) Sum(in []byte) []byte {
	h.sum(h.buf)
	return append(in, h.buf...)
}

func (h *shaXHash) sum(out []byte) {
	var ctx2 bcrypt.HASH_HANDLE
	err := bcrypt.DuplicateHash(h.ctx, &ctx2, nil, 0)
	if err != nil {
		panic(err)
	}
	defer bcrypt.DestroyHash(ctx2)
	err = bcrypt.FinishHash(ctx2, out, 0)
	if err != nil {
		panic(err)
	}
	runtime.KeepAlive(h)
}
