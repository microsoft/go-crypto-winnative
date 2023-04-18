// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"hash"
	"runtime"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

func shaOneShot(id string, p, sum []byte) error {
	h, err := loadSha(id, 0)
	if err != nil {
		return err
	}
	return bcrypt.Hash(h.handle, nil, p, sum)
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
	return newSHAX(bcrypt.SHA1_ALGORITHM, bcrypt.ALG_NONE_FLAG, nil)
}

// NewSHA256 returns a new SHA256 hash.
func NewSHA256() hash.Hash {
	return newSHAX(bcrypt.SHA256_ALGORITHM, bcrypt.ALG_NONE_FLAG, nil)
}

// NewSHA384 returns a new SHA384 hash.
func NewSHA384() hash.Hash {
	return newSHAX(bcrypt.SHA384_ALGORITHM, bcrypt.ALG_NONE_FLAG, nil)
}

// NewSHA512 returns a new SHA512 hash.
func NewSHA512() hash.Hash {
	return newSHAX(bcrypt.SHA512_ALGORITHM, bcrypt.ALG_NONE_FLAG, nil)
}

type shaAlgorithm struct {
	handle    bcrypt.ALG_HANDLE
	size      uint32
	blockSize uint32
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
		return shaAlgorithm{h, size, blockSize}, nil
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

func newSHAX(id string, flag bcrypt.AlgorithmProviderFlags, key []byte) *shaXHash {
	h, err := loadSha(id, flag)
	if err != nil {
		panic(err)
	}
	sha := new(shaXHash)
	sha.h = h.handle
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

func (h *shaXHash) Clone() (hash.Hash, error) {
	h2 := &shaXHash{
		h:         h.h,
		size:      h.size,
		blockSize: h.blockSize,
		buf:       make([]byte, len(h.buf)),
		key:       make([]byte, len(h.key)),
	}
	copy(h2.key, h.key)
	err := bcrypt.DuplicateHash(h.ctx, &h2.ctx, nil, 0)
	if err != nil {
		return nil, err
	}
	runtime.SetFinalizer(h2, (*shaXHash).finalize)
	runtime.KeepAlive(h)
	return h2, nil
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
	for n < len(p) && err == nil {
		nn := len32(p[n:])
		err = bcrypt.HashData(h.ctx, p[n:n+nn], 0)
		n += nn
	}
	if err != nil {
		// hash.Hash interface mandates Write should never return an error.
		panic(err)
	}
	runtime.KeepAlive(h)
	return len(p), nil
}

func (h *shaXHash) WriteString(s string) (int, error) {
	// TODO: use unsafe.StringData once we drop support
	// for go1.19 and earlier.
	hdr := (*struct {
		Data *byte
		Len  int
	})(unsafe.Pointer(&s))
	return h.Write(unsafe.Slice(hdr.Data, len(s)))
}

func (h *shaXHash) WriteByte(c byte) error {
	if err := bcrypt.HashDataRaw(h.ctx, &c, 1, 0); err != nil {
		// hash.Hash interface mandates Write should never return an error.
		panic(err)
	}
	runtime.KeepAlive(h)
	return nil
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
