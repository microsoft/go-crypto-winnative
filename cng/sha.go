// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"errors"
	"hash"
	"runtime"

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
	handle       bcrypt.ALG_HANDLE
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
	size      uint32
	blockSize uint32
	magic     [7]byte
	obj       []byte
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
	sha.size = h.size
	sha.blockSize = h.blockSize
	sha.magic = hashMagic(h.size)
	sha.obj = make([]byte, h.objectLength)
	sha.buf = make([]byte, sha.size)
	if len(key) > 0 {
		sha.key = make([]byte, len(key))
		copy(sha.key, key)
	}
	sha.Reset()
	runtime.SetFinalizer(sha, (*shaXHash).finalize)
	return sha
}

func hashMagic(size uint32) [7]byte {
	var m [7]byte
	m[0], m[1], m[2] = 'c', 'n', 'g'
	// Encode size as little endian.
	m[3], m[4], m[5], m[6] = byte(size>>24), byte(size>>16), byte(size>>8), byte(size)
	return m
}

// MarshalBinary returns the hash internal state.
// The state is not compatible with the Go standard library hash state scheme.
// The state might not be compatible across Windows version.
func (h *shaXHash) MarshalBinary() ([]byte, error) {
	state := make([]byte, len(h.magic)+len(h.obj))
	copy(state, h.magic[:])
	copy(state[len(h.magic):], h.obj)
	return state, nil
}

// UnmarshalBinary sets the internal hash state.
// The state must be generated using shaXHash.MarshalBinary().
func (h *shaXHash) UnmarshalBinary(data []byte) error {
	if len(data) < len(h.magic) || string(data[:len(h.magic)]) != string(h.magic[:]) {
		return errors.New("invalid hash state identifier")
	}
	data = data[len(h.magic):]
	if len(data) != len(h.obj) {
		return errors.New("invalid hash state")
	}
	copy(h.obj, data)
	return nil
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
	err := bcrypt.CreateHash(h.h, &h.ctx, h.obj, h.key, 0)
	if err != nil {
		panic(err)
	}
	runtime.KeepAlive(h)
}

func (h *shaXHash) Write(p []byte) (n int, err error) {
	for n < len(p) && err == nil {
		nn := lenU32(p[n:])
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

func (h *shaXHash) Size() int {
	return int(h.size)
}

func (h *shaXHash) BlockSize() int {
	return int(h.blockSize)
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
