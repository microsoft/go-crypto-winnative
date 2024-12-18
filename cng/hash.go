// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"bytes"
	"crypto"
	"hash"
	"runtime"
	"slices"
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

type hashX struct {
	alg  *hashAlgorithm
	_ctx bcrypt.HASH_HANDLE // access it using withCtx

	buf []byte
	key []byte
}

// newHashX returns a new hash.Hash using the specified algorithm.
func newHashX(id string, flag bcrypt.AlgorithmProviderFlags, key []byte) *hashX {
	alg, err := loadHash(id, flag)
	if err != nil {
		panic(err)
	}
	h := &hashX{alg: alg, key: bytes.Clone(key)}
	// Don't allocate hx.buf nor call bcrypt.CreateHash yet,
	// which would be wasteful if the caller only wants to know
	// the hash type. This is a common pattern in this package,
	// as some functions accept a `func() hash.Hash` parameter
	// and call it just to know the hash type.
	runtime.SetFinalizer(h, (*hashX).finalize)
	return h
}

func (h *hashX) finalize() {
	if h._ctx != 0 {
		bcrypt.DestroyHash(h._ctx)
	}
}

func (h *hashX) withCtx(fn func(ctx bcrypt.HASH_HANDLE) error) error {
	defer runtime.KeepAlive(h)
	if h._ctx == 0 {
		err := bcrypt.CreateHash(h.alg.handle, &h._ctx, nil, h.key, 0)
		if err != nil {
			panic(err)
		}
	}
	return fn(h._ctx)
}

func (h *hashX) Clone() (hash.Hash, error) {
	h2 := &hashX{alg: h.alg, key: bytes.Clone(h.key)}
	err := h.withCtx(func(ctx bcrypt.HASH_HANDLE) error {
		return bcrypt.DuplicateHash(ctx, &h2._ctx, nil, 0)
	})
	if err != nil {
		return nil, err
	}
	runtime.SetFinalizer(h2, (*hashX).finalize)
	return h2, nil
}

func (h *hashX) Reset() {
	if h._ctx != 0 {
		bcrypt.DestroyHash(h._ctx)
		h._ctx = 0
	}
}

func (h *hashX) Write(p []byte) (n int, err error) {
	err = h.withCtx(func(ctx bcrypt.HASH_HANDLE) error {
		for n < len(p) && err == nil {
			nn := len32(p[n:])
			err = bcrypt.HashData(h._ctx, p[n:n+nn], 0)
			n += nn
		}
		return err
	})
	if err != nil {
		// hash.Hash interface mandates Write should never return an error.
		panic(err)
	}
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
	err := h.withCtx(func(ctx bcrypt.HASH_HANDLE) error {
		return bcrypt.HashDataRaw(h._ctx, &c, 1, 0)
	})
	if err != nil {
		// hash.Hash interface mandates Write should never return an error.
		panic(err)
	}
	return nil
}

func (h *hashX) Size() int {
	return int(h.alg.size)
}

func (h *hashX) BlockSize() int {
	return int(h.alg.blockSize)
}

func (h *hashX) Sum(in []byte) []byte {
	var ctx2 bcrypt.HASH_HANDLE
	err := h.withCtx(func(ctx bcrypt.HASH_HANDLE) error {
		return bcrypt.DuplicateHash(ctx, &ctx2, nil, 0)
	})
	if err != nil {
		panic(err)
	}
	defer bcrypt.DestroyHash(ctx2)
	if h.buf == nil {
		h.buf = make([]byte, h.alg.size)
	}
	err = bcrypt.FinishHash(ctx2, h.buf, 0)
	if err != nil {
		panic(err)
	}
	return append(in, h.buf...)
}

// SupportsSHAKE128 returns true if the SHAKE128 extendable output function is
// supported.
func SupportsSHAKE128() bool {
	_, err := loadHash(bcrypt.CSHAKE128_ALGORITHM, bcrypt.ALG_NONE_FLAG)
	return err == nil
}

// SupportsSHAKE256 returns true if the SHAKE256 extendable output function is
// supported.
func SupportsSHAKE256() bool {
	_, err := loadHash(bcrypt.CSHAKE256_ALGORITHM, bcrypt.ALG_NONE_FLAG)
	return err == nil
}

// SumSHAKE128 applies the SHAKE128 extendable output function to data and
// returns an output of the given length in bytes.
func SumSHAKE128(data []byte, length int) []byte {
	out := make([]byte, length)
	if err := hashOneShot(bcrypt.CSHAKE128_ALGORITHM, data, out); err != nil {
		panic("bcrypt: CSHAKE128_ALGORITHM failed")
	}
	return out
}

// SumSHAKE256 applies the SHAKE256 extendable output function to data and
// returns an output of the given length in bytes.
func SumSHAKE256(data []byte, length int) []byte {
	out := make([]byte, length)
	if err := hashOneShot(bcrypt.CSHAKE256_ALGORITHM, data, out); err != nil {
		panic("bcrypt: CSHAKE128_ALGORITHM failed")
	}
	return out
}

// SHAKE is an instance of a SHAKE extendable output function.
type SHAKE struct {
	alg  *hashAlgorithm
	ctx  bcrypt.HASH_HANDLE
	n, s []byte
}

func newShake(id string, N, S []byte) *SHAKE {
	alg, err := loadHash(id, bcrypt.ALG_NONE_FLAG)
	if err != nil {
		panic(err)
	}
	h := &SHAKE{alg: alg, n: slices.Clone(N), s: slices.Clone(S)}
	err = bcrypt.CreateHash(h.alg.handle, &h.ctx, nil, nil, 0)
	if err != nil {
		panic(err)
	}
	if len(N) != 0 {
		if err := bcrypt.SetProperty(bcrypt.HANDLE(h.ctx), utf16PtrFromString(bcrypt.FUNCTION_NAME_STRING), N, 0); err != nil {
			panic(err)
		}
	}
	if len(S) != 0 {
		if err := bcrypt.SetProperty(bcrypt.HANDLE(h.ctx), utf16PtrFromString(bcrypt.CUSTOMIZATION_STRING), S, 0); err != nil {
			panic(err)
		}
	}
	runtime.SetFinalizer(h, (*SHAKE).finalize)
	return h
}

// NewSHAKE128 creates a new SHAKE128 XOF.
func NewSHAKE128() *SHAKE {
	return newShake(bcrypt.CSHAKE128_ALGORITHM, nil, nil)
}

// NewSHAKE256 creates a new SHAKE256 XOF.
func NewSHAKE256() *SHAKE {
	return newShake(bcrypt.CSHAKE256_ALGORITHM, nil, nil)
}

// NewCSHAKE128 creates a new cSHAKE128 XOF.
//
// N is used to define functions based on cSHAKE, it can be empty when plain
// cSHAKE is desired. S is a customization byte string used for domain
// separation. When N and S are both empty, this is equivalent to NewSHAKE128.
func NewCSHAKE128(N, S []byte) *SHAKE {
	return newShake(bcrypt.CSHAKE128_ALGORITHM, N, S)
}

// NewCSHAKE256 creates a new cSHAKE256 XOF.
//
// N is used to define functions based on cSHAKE, it can be empty when plain
// cSHAKE is desired. S is a customization byte string used for domain
// separation. When N and S are both empty, this is equivalent to NewSHAKE256.
func NewCSHAKE256(N, S []byte) *SHAKE {
	return newShake(bcrypt.CSHAKE256_ALGORITHM, N, S)
}

func (h *SHAKE) finalize() {
	bcrypt.DestroyHash(h.ctx)
}

// Write absorbs more data into the XOF's state.
//
// It panics if any output has already been read.
func (s *SHAKE) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	defer runtime.KeepAlive(s)
	for n < len(p) && err == nil {
		nn := len32(p[n:])
		err = bcrypt.HashData(s.ctx, p[n:n+nn], 0)
		n += nn
	}
	if err != nil {
		panic(err)
	}
	return len(p), nil
}

// Read squeezes more output from the XOF.
//
// Any call to Write after a call to Read will panic.
func (s *SHAKE) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	defer runtime.KeepAlive(s)
	for n < len(p) && err == nil {
		nn := len32(p[n:])
		err = bcrypt.FinishHash(s.ctx, p[n:n+nn], bcrypt.HASH_DONT_RESET_FLAG)
		n += nn
	}
	if err != nil {
		panic(err)
	}
	return len(p), nil
}

// Reset resets the XOF to its initial state.
func (s *SHAKE) Reset() {
	defer runtime.KeepAlive(s)
	bcrypt.DestroyHash(s.ctx)
	err := bcrypt.CreateHash(s.alg.handle, &s.ctx, nil, nil, 0)
	if err != nil {
		panic(err)
	}
	if len(s.n) != 0 {
		if err := bcrypt.SetProperty(bcrypt.HANDLE(s.ctx), utf16PtrFromString(bcrypt.FUNCTION_NAME_STRING), s.n, 0); err != nil {
			panic(err)
		}
	}
	if len(s.s) != 0 {
		if err := bcrypt.SetProperty(bcrypt.HANDLE(s.ctx), utf16PtrFromString(bcrypt.CUSTOMIZATION_STRING), s.s, 0); err != nil {
			panic(err)
		}
	}
}

// BlockSize returns the rate of the XOF.
func (s *SHAKE) BlockSize() int {
	return int(s.alg.blockSize)
}
