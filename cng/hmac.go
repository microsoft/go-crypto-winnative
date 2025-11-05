// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"bytes"
	"hash"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

// NewHMAC returns a new HMAC using BCrypt.
// The function h must return a hash implemented by
// CNG (for example, h could be cng.NewSHA256).
// If h is not recognized, NewHMAC returns nil.
func NewHMAC(h func() hash.Hash, key []byte) hash.Hash {
	ch := h()
	id := hashToID(ch)
	if id == "" {
		return nil
	}
	if len(key) > ch.BlockSize() {
		// Keys longer than BlockSize are first hashed using
		// the same hash function, according to RFC 2104, Section 3.
		// BCrypt already does that, but if we hash the key on our side
		// we avoid allocating unnecessary memory and
		// allow keys longer than math.MaxUint32 bytes.
		ch.Write(key)
		key = ch.Sum(nil)
	} else {
		key = bytes.Clone(key)
	}
	return hmacWrapper{hashX: &Hash{alg: mustLoadHash(id, bcrypt.ALG_HANDLE_HMAC_FLAG), key: key}}
}

type hmacWrapper struct {
	hashX *Hash
}

func (h hmacWrapper) Write(p []byte) (n int, err error) {
	return h.hashX.Write(p)
}

func (h hmacWrapper) Sum(b []byte) []byte {
	return h.hashX.Sum(b)
}

func (h hmacWrapper) Reset() {
	h.hashX.Reset()
}

func (h hmacWrapper) Size() int {
	return h.hashX.Size()
}

func (h hmacWrapper) BlockSize() int {
	return h.hashX.BlockSize()
}

func (h hmacWrapper) Clone() (HashCloner, error) {
	clone, err := h.hashX.Clone()
	if err != nil {
		return nil, err
	}
	return hmacWrapper{hashX: clone.(*Hash)}, nil
}
