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

// SumSHA3_256 returns the SHA3-256 checksum of the data.
func SumSHA3_256(p []byte) (sum [32]byte) {
	if err := hashOneShot(bcrypt.SHA3_256_ALGORITHM, p, sum[:]); err != nil {
		panic("bcrypt: SHA3_256 failed")
	}
	return
}

// SumSHA3_384 returns the SHA3-384 checksum of the data.
func SumSHA3_384(p []byte) (sum [48]byte) {
	if err := hashOneShot(bcrypt.SHA3_384_ALGORITHM, p, sum[:]); err != nil {
		panic("bcrypt: SHA3_384 failed")
	}
	return
}

// SumSHA3_512 returns the SHA3-512 checksum of the data.
func SumSHA3_512(p []byte) (sum [64]byte) {
	if err := hashOneShot(bcrypt.SHA3_512_ALGORITHM, p, sum[:]); err != nil {
		panic("bcrypt: SHA3_512 failed")
	}
	return
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
		panic("bcrypt: CSHAKE256_ALGORITHM failed")
	}
	return out
}

// SupportsSHAKE returns true if the SHAKE and CSHAKE extendable output functions
// with the given securityBits are supported.
func SupportsSHAKE(securityBits int) bool {
	var id string
	switch securityBits {
	case 128:
		id = bcrypt.CSHAKE128_ALGORITHM
	case 256:
		id = bcrypt.CSHAKE256_ALGORITHM
	default:
		return false
	}
	_, err := loadHash(id, bcrypt.ALG_NONE_FLAG)
	return err == nil
}

var _ hash.Hash = DigestSHA3{}
var _ HashCloner = DigestSHA3{}

// DigestSHA3 is the [sha3.SHA3] implementation using the CNG API.
type DigestSHA3 struct{ *hashX }

// NewSHA3_256 returns a new SHA256 hash.
func NewSHA3_256() DigestSHA3 {
	return DigestSHA3{newHashX(bcrypt.SHA3_256_ALGORITHM, bcrypt.ALG_NONE_FLAG, nil)}
}

// NewSHA3_384 returns a new SHA384 hash.
func NewSHA3_384() DigestSHA3 {
	return DigestSHA3{newHashX(bcrypt.SHA3_384_ALGORITHM, bcrypt.ALG_NONE_FLAG, nil)}
}

// NewSHA3_512 returns a new SHA512 hash.
func NewSHA3_512() DigestSHA3 {
	return DigestSHA3{newHashX(bcrypt.SHA3_512_ALGORITHM, bcrypt.ALG_NONE_FLAG, nil)}
}

// SHAKE is an instance of a SHAKE extendable output function.
type SHAKE struct {
	ctx       bcrypt.HASH_HANDLE
	blockSize uint32
}

func newShake(id string, N, S []byte) *SHAKE {
	alg, err := loadHash(id, bcrypt.ALG_NONE_FLAG)
	if err != nil {
		panic(err)
	}
	h := &SHAKE{blockSize: alg.blockSize}
	err = bcrypt.CreateHash(alg.handle, &h.ctx, nil, nil, bcrypt.HASH_REUSABLE_FLAG)
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
	hashData(s.ctx, p)
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
	// SHAKE has a variable size, CNG doesn't change the size of the hash
	// when resetting, so we can pass a small value here.
	hashReset(s.ctx, 1)
}

// BlockSize returns the rate of the XOF.
func (s *SHAKE) BlockSize() int {
	return int(s.blockSize)
}

func (s *SHAKE) MarshalBinary() ([]byte, error) {
	return nil, errMarshallUnsupported{}
}

func (s *SHAKE) AppendBinary(b []byte) ([]byte, error) {
	return nil, errMarshallUnsupported{}
}

func (s *SHAKE) UnmarshalBinary(data []byte) error {
	return errMarshallUnsupported{}
}
