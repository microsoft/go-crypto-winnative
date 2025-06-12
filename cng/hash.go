// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"bytes"
	"crypto"
	"errors"
	"hash"
	"runtime"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

// maxHashSize is the size of SHA512 and SHA3_512, the largest hashes we support.
const maxHashSize = 64

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

type hashAlgorithm struct {
	handle    bcrypt.ALG_HANDLE
	id        string
	size      uint32
	blockSize uint32
}

func loadHash(id string, flags bcrypt.AlgorithmProviderFlags) (*hashAlgorithm, error) {
	return loadOrStoreAlg(id, flags, "", func(h bcrypt.ALG_HANDLE) (*hashAlgorithm, error) {
		size, err := getUint32(bcrypt.HANDLE(h), bcrypt.HASH_LENGTH)
		if err != nil {
			return nil, err
		}
		blockSize, err := getUint32(bcrypt.HANDLE(h), bcrypt.HASH_BLOCK_LENGTH)
		if err != nil {
			return nil, err
		}
		return &hashAlgorithm{h, id, size, blockSize}, nil
	})
}

// hashToID converts a hash.Hash implementation from this package
// to a CNG hash ID
func hashToID(h hash.Hash) string {
	hx, ok := h.(*hashX)
	if !ok {
		return ""
	}
	return hx.alg.id
}

var _ hash.Hash = (*hashX)(nil)
var _ HashCloner = (*hashX)(nil)

// hashX implements [hash.Hash].
type hashX struct {
	alg *hashAlgorithm
	ctx bcrypt.HASH_HANDLE

	key []byte
}

// newHashX returns a new hash.Hash using the specified algorithm.
func newHashX(id string, flag bcrypt.AlgorithmProviderFlags, key []byte) *hashX {
	alg, err := loadHash(id, flag)
	if err != nil {
		panic(err)
	}
	h := &hashX{alg: alg, key: bytes.Clone(key)}
	// Don't call bcrypt.CreateHash yet, it would be wasteful
	// if the caller only wants to know the hash type. This
	// is a common pattern in this package, as some functions
	// accept a `func() hash.Hash` parameter and call it just
	// to know the hash type.
	return h
}

func (h *hashX) finalize() {
	bcrypt.DestroyHash(h.ctx)
}

func (h *hashX) init() {
	defer runtime.KeepAlive(h)
	if h.ctx != 0 {
		return
	}
	err := bcrypt.CreateHash(h.alg.handle, &h.ctx, nil, h.key, bcrypt.HASH_REUSABLE_FLAG)
	if err != nil {
		panic(err)
	}
	runtime.SetFinalizer(h, (*hashX).finalize)
}

func (h *hashX) Clone() (HashCloner, error) {
	defer runtime.KeepAlive(h)
	h2 := &hashX{alg: h.alg, key: bytes.Clone(h.key)}
	if h.ctx != 0 {
		hashClone(h.ctx, &h2.ctx)
		runtime.SetFinalizer(h2, (*hashX).finalize)
	}
	return h2, nil
}

func (h *hashX) Reset() {
	defer runtime.KeepAlive(h)
	if h.ctx != 0 {
		hashReset(h.ctx, h.Size())
	}
}

func (h *hashX) Write(p []byte) (n int, err error) {
	defer runtime.KeepAlive(h)
	h.init()
	hashData(h.ctx, p)
	return len(p), nil
}

func (h *hashX) WriteString(s string) (int, error) {
	defer runtime.KeepAlive(h)
	return h.Write(unsafe.Slice(unsafe.StringData(s), len(s)))
}

func (h *hashX) WriteByte(c byte) error {
	defer runtime.KeepAlive(h)
	h.init()
	hashByte(h.ctx, c)
	return nil
}

func (h *hashX) Sum(in []byte) []byte {
	defer runtime.KeepAlive(h)
	h.init()
	return hashSum(h.ctx, h.Size(), in)
}

func (h *hashX) Size() int {
	return int(h.alg.size)
}

func (h *hashX) BlockSize() int {
	return int(h.alg.blockSize)
}

func (hx *hashX) MarshalBinary() ([]byte, error) {
	return nil, errors.New("cng: hash state is not marshallable")
}

func (hx *hashX) AppendBinary(b []byte) ([]byte, error) {
	return nil, errors.New("cng: hash state is not marshallable")
}

func (hx *hashX) UnmarshalBinary(data []byte) error {
	return errors.New("cng: hash state is not marshallable")
}

// hashData writes p to ctx. It panics on error.
func hashData(ctx bcrypt.HASH_HANDLE, p []byte) {
	var n int
	var err error
	for n < len(p) && err == nil {
		nn := len32(p[n:])
		err = bcrypt.HashData(ctx, p[n:n+nn], 0)
		n += nn
	}
	if err != nil {
		panic(err)
	}
}

// hashByte writes c to ctx. It panics on error.
func hashByte(ctx bcrypt.HASH_HANDLE, c byte) {
	err := bcrypt.HashDataRaw(ctx, &c, 1, 0)
	if err != nil {
		panic(err)
	}
}

// hashSum writes the hash of ctx to in and returns the result.
// size is the size of the hash output.
// It panics on error.
func hashSum(ctx bcrypt.HASH_HANDLE, size int, in []byte) []byte {
	var ctx2 bcrypt.HASH_HANDLE
	err := bcrypt.DuplicateHash(ctx, &ctx2, nil, 0)
	if err != nil {
		panic(err)
	}
	defer bcrypt.DestroyHash(ctx2)
	buf := make([]byte, size, maxHashSize) // explicit cap to allow stack allocation
	err = bcrypt.FinishHash(ctx2, buf, 0)
	if err != nil {
		panic(err)
	}
	return append(in, buf...)
}

// hashReset resets the hash state of ctx.
// size is the size of the hash output.
// It panics on error.
func hashReset(ctx bcrypt.HASH_HANDLE, size int) {
	// bcrypt.FinishHash expects the output buffer to match the hash size.
	// We don't care about the output, so we just pass a stack-allocated buffer
	// that is large enough to hold the largest hash size we support.
	var discard [maxHashSize]byte
	if err := bcrypt.FinishHash(ctx, discard[:size], 0); err != nil {
		panic(err)
	}
}

// hashClone clones ctx into ctx2. It panics on error.
func hashClone(ctx bcrypt.HASH_HANDLE, ctx2 *bcrypt.HASH_HANDLE) {
	err := bcrypt.DuplicateHash(ctx, ctx2, nil, 0)
	if err != nil {
		panic(err)
	}
}
