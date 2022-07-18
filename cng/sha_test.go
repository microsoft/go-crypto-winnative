// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng_test

import (
	"bytes"
	"encoding"
	"hash"
	"testing"

	"github.com/microsoft/go-crypto-winnative/cng"
	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

func TestSha(t *testing.T) {
	msg := []byte("testing")
	var tests = []struct {
		name string
		fn   func() hash.Hash
	}{
		{"sha1", cng.NewSHA1},
		{"sha256", cng.NewSHA256},
		{"sha384", cng.NewSHA384},
		{"sha512", cng.NewSHA512},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := tt.fn()
			initSum := h.Sum(nil)
			n, err := h.Write(msg)
			if err != nil {
				t.Fatal(err)
			}
			if n != len(msg) {
				t.Errorf("got: %d, want: %d", n, len(msg))
			}
			sum := h.Sum(nil)
			if size := h.Size(); len(sum) != size {
				t.Errorf("got: %d, want: %d", len(sum), size)
			}
			if bytes.Equal(sum, initSum) {
				t.Error("Write didn't change internal hash state")
			}

			state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
			if err != nil {
				t.Errorf("could not marshal: %v", err)
			}
			h2 := tt.fn()
			if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
				t.Errorf("could not unmarshal: %v", err)
			}
			if actual, actual2 := h.Sum(nil), h2.Sum(nil); !bytes.Equal(actual, actual2) {
				t.Errorf("0x%x != marshaled 0x%x", actual, actual2)
			}

			h.Reset()
			sum = h.Sum(nil)
			if !bytes.Equal(sum, initSum) {
				t.Errorf("got:%x want:%x", sum, initSum)
			}
		})
	}
}

func TestSHA_OneShot(t *testing.T) {
	msg := []byte("testing")
	var tests = []struct {
		id      string
		want    func() hash.Hash
		oneShot func([]byte) []byte
	}{
		{bcrypt.SHA1_ALGORITHM, cng.NewSHA1, func(p []byte) []byte {
			b := cng.SHA1(p)
			return b[:]
		}},
		{bcrypt.SHA256_ALGORITHM, cng.NewSHA256, func(p []byte) []byte {
			b := cng.SHA256(p)
			return b[:]
		}},
		{bcrypt.SHA384_ALGORITHM, cng.NewSHA384, func(p []byte) []byte {
			b := cng.SHA384(p)
			return b[:]
		}},
		{bcrypt.SHA512_ALGORITHM, cng.NewSHA512, func(p []byte) []byte {
			b := cng.SHA512(p)
			return b[:]
		}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := tt.oneShot(msg)
			h := tt.want()
			h.Write(msg)
			want := h.Sum(nil)
			if !bytes.Equal(got[:], want) {
				t.Errorf("got:%x want:%x", got, want)
			}
		})
	}
}

func BenchmarkHash8Bytes(b *testing.B) {
	b.StopTimer()
	h := cng.NewSHA256()
	sum := make([]byte, h.Size())
	size := 8
	buf := make([]byte, size)
	b.StartTimer()
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(buf[:size])
		h.Sum(sum[:0])
	}
}

func BenchmarkSHA256(b *testing.B) {
	b.StopTimer()
	size := 8
	buf := make([]byte, size)
	b.StartTimer()
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cng.SHA256(buf)
	}
}
