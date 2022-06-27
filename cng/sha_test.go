// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"bytes"
	"hash"
	"testing"
)

func TestSha(t *testing.T) {
	msg := []byte("testing")
	var tests = []struct {
		name string
		fn   func() hash.Hash
	}{
		{"sha1", NewSHA1},
		{"sha256", NewSHA256},
		{"sha384", NewSHA384},
		{"sha512", NewSHA512},
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
		name    string
		want    func() hash.Hash
		oneShot func([]byte) []byte
	}{
		{"sha1", NewSHA1, func(p []byte) []byte {
			b := SHA1(p)
			return b[:]
		}},
		{"sha256", NewSHA256, func(p []byte) []byte {
			b := SHA256(p)
			return b[:]
		}},
		{"sha384", NewSHA384, func(p []byte) []byte {
			b := SHA384(p)
			return b[:]
		}},
		{"sha512", NewSHA512, func(p []byte) []byte {
			b := SHA512(p)
			return b[:]
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	h := NewSHA256()
	sum := make([]byte, h.Size())
	size := 8
	buf := make([]byte, size)
	b.StartTimer()
	b.SetBytes(int64(size))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(buf[:size])
		h.Write(buf)
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
		SHA256(buf)
	}
}
