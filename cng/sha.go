// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"hash"
	"runtime"
	"sync"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

// NewSHA1 returns a new SHA1 hash.
func NewSHA1() hash.Hash {
	return newSHAX(bcrypt.SHA1_ALGORITHM)
}

// NewSHA256 returns a new SHA256 hash.
func NewSHA256() hash.Hash {
	return newSHAX(bcrypt.SHA256_ALGORITHM)
}

// NewSHA384 returns a new SHA384 hash.
func NewSHA384() hash.Hash {
	return newSHAX(bcrypt.SHA384_ALGORITHM)
}

// NewSHA512 returns a new SHA512 hash.
func NewSHA512() hash.Hash {
	return newSHAX(bcrypt.SHA512_ALGORITHM)
}

var shaCache sync.Map

type shaAlgorithm struct {
	h         bcrypt.ALG_HANDLE
	size      uint32
	blockSize uint32
}

func loadSha(id string, flags uint32) (h shaAlgorithm, err error) {
	if v, ok := shaCache.Load(algCacheEntry{id, flags}); ok {
		return v.(shaAlgorithm), nil
	}
	err = bcrypt.OpenAlgorithmProvider(&h.h, utf16PtrFromString(id), nil, flags)
	if err != nil {
		return
	}
	h.size, err = getUint32(bcrypt.HANDLE(h.h), bcrypt.HASH_LENGTH)
	if err != nil {
		return
	}
	h.blockSize, err = getUint32(bcrypt.HANDLE(h.h), bcrypt.HASH_BLOCK_LENGTH)
	if err != nil {
		return
	}
	shaCache.Store(algCacheEntry{id, flags}, h)
	return
}

type shaXHash struct {
	h         bcrypt.ALG_HANDLE
	ctx       bcrypt.HASH_HANDLE
	size      int
	blockSize int
	buf       []byte
}

func newSHAX(id string) *shaXHash {
	h, err := loadSha(id, 0)
	if err != nil {
		panic(err)
	}
	sha := new(shaXHash)
	sha.h = h.h
	sha.size = int(h.size)
	sha.blockSize = int(h.blockSize)
	sha.buf = make([]byte, sha.size)
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
	err := bcrypt.CreateHash(h.h, &h.ctx, nil, nil, 0)
	if err != nil {
		panic(err)
	}
	runtime.KeepAlive(h)
}

func (h *shaXHash) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	err := bcrypt.HashData(h.ctx, p, 0)
	if err != nil {
		return 0, err
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
