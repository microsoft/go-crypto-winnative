// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"crypto"
	"hash"
	"runtime"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

// SupportsHash returns true if a hash.Hash implementation is supported for h.
func SupportsHash(h crypto.Hash) bool {
	switch h {
	case crypto.MD4, crypto.MD5, crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return true
	case crypto.SHA3_256:
		_, err := loadHash(bcrypt.SHA3_256_ALGORITHM, bcrypt.ALG_NONE_FLAG)
		return err == nil
	case crypto.SHA3_384:
		_, err := loadHash(bcrypt.SHA3_384_ALGORITHM, bcrypt.ALG_NONE_FLAG)
		return err == nil
	case crypto.SHA3_512:
		_, err := loadHash(bcrypt.SHA3_512_ALGORITHM, bcrypt.ALG_NONE_FLAG)
		return err == nil
	}
	return false
}

func hashOneShot(id string, p, sum []byte) error {
	h, err := loadHash(id, 0)
	if err != nil {
		return err
	}
	return bcrypt.Hash(h.handle, nil, p, sum)
}

func MD4(p []byte) (sum [16]byte) {
	if err := hashOneShot(bcrypt.MD4_ALGORITHM, p, sum[:]); err != nil {
		panic("bcrypt: MD4 failed")
	}
	return
}

func MD5(p []byte) (sum [16]byte) {
	if err := hashOneShot(bcrypt.MD5_ALGORITHM, p, sum[:]); err != nil {
		panic("bcrypt: MD5 failed")
	}
	return
}

func SHA1(p []byte) (sum [20]byte) {
	if err := hashOneShot(bcrypt.SHA1_ALGORITHM, p, sum[:]); err != nil {
		panic("bcrypt: SHA1 failed")
	}
	return
}

func SHA256(p []byte) (sum [32]byte) {
	if err := hashOneShot(bcrypt.SHA256_ALGORITHM, p, sum[:]); err != nil {
		panic("bcrypt: SHA256 failed")
	}
	return
}

func SHA384(p []byte) (sum [48]byte) {
	if err := hashOneShot(bcrypt.SHA384_ALGORITHM, p, sum[:]); err != nil {
		panic("bcrypt: SHA384 failed")
	}
	return
}

func SHA512(p []byte) (sum [64]byte) {
	if err := hashOneShot(bcrypt.SHA512_ALGORITHM, p, sum[:]); err != nil {
		panic("bcrypt: SHA512 failed")
	}
	return
}

func SHA3_256(p []byte) (sum [32]byte) {
	if err := hashOneShot(bcrypt.SHA3_256_ALGORITHM, p, sum[:]); err != nil {
		panic("bcrypt: SHA3_256 failed")
	}
	return
}

func SHA3_384(p []byte) (sum [48]byte) {
	if err := hashOneShot(bcrypt.SHA3_384_ALGORITHM, p, sum[:]); err != nil {
		panic("bcrypt: SHA3_384 failed")
	}
	return
}

func SHA3_512(p []byte) (sum [64]byte) {
	if err := hashOneShot(bcrypt.SHA3_512_ALGORITHM, p, sum[:]); err != nil {
		panic("bcrypt: SHA3_512 failed")
	}
	return
}

// NewMD4 returns a new MD4 hash.
func NewMD4() hash.Hash {
	return newHashX(bcrypt.MD4_ALGORITHM, bcrypt.ALG_NONE_FLAG, nil)
}

// NewMD5 returns a new MD5 hash.
func NewMD5() hash.Hash {
	return newHashX(bcrypt.MD5_ALGORITHM, bcrypt.ALG_NONE_FLAG, nil)
}

// NewSHA1 returns a new SHA1 hash.
func NewSHA1() hash.Hash {
	return newHashX(bcrypt.SHA1_ALGORITHM, bcrypt.ALG_NONE_FLAG, nil)
}

// NewSHA256 returns a new SHA256 hash.
func NewSHA256() hash.Hash {
	return newHashX(bcrypt.SHA256_ALGORITHM, bcrypt.ALG_NONE_FLAG, nil)
}

// NewSHA384 returns a new SHA384 hash.
func NewSHA384() hash.Hash {
	return newHashX(bcrypt.SHA384_ALGORITHM, bcrypt.ALG_NONE_FLAG, nil)
}

// NewSHA512 returns a new SHA512 hash.
func NewSHA512() hash.Hash {
	return newHashX(bcrypt.SHA512_ALGORITHM, bcrypt.ALG_NONE_FLAG, nil)
}

// NewSHA3_256 returns a new SHA256 hash.
func NewSHA3_256() hash.Hash {
	return newHashX(bcrypt.SHA3_256_ALGORITHM, bcrypt.ALG_NONE_FLAG, nil)
}

// NewSHA3_384 returns a new SHA384 hash.
func NewSHA3_384() hash.Hash {
	return newHashX(bcrypt.SHA3_384_ALGORITHM, bcrypt.ALG_NONE_FLAG, nil)
}

// NewSHA3_512 returns a new SHA512 hash.
func NewSHA3_512() hash.Hash {
	return newHashX(bcrypt.SHA3_512_ALGORITHM, bcrypt.ALG_NONE_FLAG, nil)
}

type hashAlgorithm struct {
	handle    bcrypt.ALG_HANDLE
	size      uint32
	blockSize uint32
}

func loadHash(id string, flags bcrypt.AlgorithmProviderFlags) (hashAlgorithm, error) {
	v, err := loadOrStoreAlg(id, flags, "", func(h bcrypt.ALG_HANDLE) (interface{}, error) {
		size, err := getUint32(bcrypt.HANDLE(h), bcrypt.HASH_LENGTH)
		if err != nil {
			return nil, err
		}
		blockSize, err := getUint32(bcrypt.HANDLE(h), bcrypt.HASH_BLOCK_LENGTH)
		if err != nil {
			return nil, err
		}
		return hashAlgorithm{h, size, blockSize}, nil
	})
	if err != nil {
		return hashAlgorithm{}, err
	}
	return v.(hashAlgorithm), nil
}

type hashX struct {
	h         bcrypt.ALG_HANDLE
	ctx       bcrypt.HASH_HANDLE
	size      int
	blockSize int
	buf       []byte
	key       []byte
}

func newHashX(id string, flag bcrypt.AlgorithmProviderFlags, key []byte) *hashX {
	h, err := loadHash(id, flag)
	if err != nil {
		panic(err)
	}
	hx := new(hashX)
	hx.h = h.handle
	hx.size = int(h.size)
	hx.blockSize = int(h.blockSize)
	hx.buf = make([]byte, hx.size)
	if len(key) > 0 {
		hx.key = make([]byte, len(key))
		copy(hx.key, key)
	}
	hx.Reset()
	runtime.SetFinalizer(hx, (*hashX).finalize)
	return hx
}

func (h *hashX) finalize() {
	if h.ctx != 0 {
		bcrypt.DestroyHash(h.ctx)
	}
}

func (h *hashX) Clone() (hash.Hash, error) {
	h2 := &hashX{
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
	runtime.SetFinalizer(h2, (*hashX).finalize)
	runtime.KeepAlive(h)
	return h2, nil
}

func (h *hashX) Reset() {
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

func (h *hashX) Write(p []byte) (n int, err error) {
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

func (h *hashX) WriteString(s string) (int, error) {
	// TODO: use unsafe.StringData once we drop support
	// for go1.19 and earlier.
	hdr := (*struct {
		Data *byte
		Len  int
	})(unsafe.Pointer(&s))
	return h.Write(unsafe.Slice(hdr.Data, len(s)))
}

func (h *hashX) WriteByte(c byte) error {
	if err := bcrypt.HashDataRaw(h.ctx, &c, 1, 0); err != nil {
		// hash.Hash interface mandates Write should never return an error.
		panic(err)
	}
	runtime.KeepAlive(h)
	return nil
}

func (h *hashX) Size() int {
	return h.size
}

func (h *hashX) BlockSize() int {
	return h.blockSize
}

func (h *hashX) Sum(in []byte) []byte {
	h.sum(h.buf)
	return append(in, h.buf...)
}

func (h *hashX) sum(out []byte) {
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
