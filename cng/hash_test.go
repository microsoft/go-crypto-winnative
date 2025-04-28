// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng_test

import (
	"bytes"
	"crypto"
	"hash"
	"io"
	"testing"

	"github.com/microsoft/go-crypto-winnative/cng"
	"github.com/microsoft/go-crypto-winnative/internal/cryptotest"
)

func cryptoToHash(h crypto.Hash) func() hash.Hash {
	switch h {
	case crypto.MD4:
		return cng.NewMD4
	case crypto.MD5:
		return cng.NewMD5
	case crypto.SHA1:
		return cng.NewSHA1
	case crypto.SHA256:
		return cng.NewSHA256
	case crypto.SHA384:
		return cng.NewSHA384
	case crypto.SHA512:
		return cng.NewSHA512
	case crypto.SHA3_256:
		return func() hash.Hash { return cng.NewSHA3_256() }
	case crypto.SHA3_384:
		return func() hash.Hash { return cng.NewSHA3_384() }
	case crypto.SHA3_512:
		return func() hash.Hash { return cng.NewSHA3_512() }
	}
	return nil
}

var hashes = []crypto.Hash{
	crypto.MD4,
	crypto.MD5,
	crypto.SHA1,
	crypto.SHA224,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
	crypto.SHA3_224,
	crypto.SHA3_256,
	crypto.SHA3_384,
	crypto.SHA3_512,
}

func TestHash(t *testing.T) {
	msg := []byte("testing")
	for _, tt := range hashes {
		t.Run(tt.String(), func(t *testing.T) {
			if !cng.SupportsHash(tt) {
				t.Skip("skipping: not supported")
			}
			h := cryptoToHash(tt)()
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

			h2 := h.(interface{ Clone() hash.Hash }).Clone()
			h.Write(msg)
			h2.Write(msg)
			if actual, actual2 := h.Sum(nil), h2.Sum(nil); !bytes.Equal(actual, actual2) {
				t.Errorf("%s(%q) = 0x%x != cloned 0x%x", tt.String(), msg, actual, actual2)
			}
			h.Reset()
			sum = h.Sum(nil)
			if !bytes.Equal(sum, initSum) {
				t.Errorf("got:%x want:%x", sum, initSum)
			}

			bw := h.(io.ByteWriter)
			for i := 0; i < len(msg); i++ {
				bw.WriteByte(msg[i])
			}
			h.Reset()
			sum = h.Sum(nil)
			if !bytes.Equal(sum, initSum) {
				t.Errorf("got:%x want:%x", sum, initSum)
			}

			h.(io.StringWriter).WriteString(string(msg))
			h.Reset()
			sum = h.Sum(nil)
			if !bytes.Equal(sum, initSum) {
				t.Errorf("got:%x want:%x", sum, initSum)
			}
		})
	}
}

func TestHash_Interface(t *testing.T) {
	for _, tt := range hashes {
		t.Run(tt.String(), func(t *testing.T) {
			if !cng.SupportsHash(tt) {
				t.Skip("skipping: not supported")
			}
			cryptotest.TestHash(t, cryptoToHash(tt))
		})
	}
}

func TestHash_OneShot(t *testing.T) {
	msg := []byte("testing")
	var tests = []struct {
		h       crypto.Hash
		oneShot func([]byte) []byte
	}{
		{crypto.MD4, func(p []byte) []byte {
			b := cng.MD4(p)
			return b[:]
		}},
		{crypto.MD5, func(p []byte) []byte {
			b := cng.MD5(p)
			return b[:]
		}},
		{crypto.SHA1, func(p []byte) []byte {
			b := cng.SHA1(p)
			return b[:]
		}},
		{crypto.SHA256, func(p []byte) []byte {
			b := cng.SHA256(p)
			return b[:]
		}},
		{crypto.SHA384, func(p []byte) []byte {
			b := cng.SHA384(p)
			return b[:]
		}},
		{crypto.SHA512, func(p []byte) []byte {
			b := cng.SHA512(p)
			return b[:]
		}},
		{crypto.SHA3_256, func(p []byte) []byte {
			b := cng.SumSHA3_256(p)
			return b[:]
		}},
		{crypto.SHA3_384, func(p []byte) []byte {
			b := cng.SumSHA3_384(p)
			return b[:]
		}},
		{crypto.SHA3_512, func(p []byte) []byte {
			b := cng.SumSHA3_512(p)
			return b[:]
		}},
	}
	for _, tt := range tests {
		t.Run(tt.h.String(), func(t *testing.T) {
			if !cng.SupportsHash(tt.h) {
				t.Skip("skipping: not supported")
			}
			got := tt.oneShot(msg)
			h := cryptoToHash(tt.h)()
			h.Write(msg)
			want := h.Sum(nil)
			if !bytes.Equal(got[:], want) {
				t.Errorf("got:%x want:%x", got, want)
			}
		})
	}
}

func TestHashAllocations(t *testing.T) {
	msg := []byte("testing")
	n := int(testing.AllocsPerRun(10, func() {
		sink ^= cng.SHA1(msg)[0]
		sink ^= cng.SHA256(msg)[0]
		sink ^= cng.SHA384(msg)[0]
		sink ^= cng.SHA512(msg)[0]
	}))
	want := 0
	if n > want {
		t.Errorf("allocs = %d, want %d", n, want)
	}
}

func TestHashStructAllocations(t *testing.T) {
	msg := []byte("testing")

	sha1Hash := cng.NewSHA1()
	sha256Hash := cng.NewSHA256()
	sha384Hash := cng.NewSHA384()
	sha512Hash := cng.NewSHA512()

	sum := make([]byte, sha512Hash.Size())
	n := int(testing.AllocsPerRun(10, func() {
		sha1Hash.Write(msg)
		sha256Hash.Write(msg)
		sha384Hash.Write(msg)
		sha512Hash.Write(msg)

		sha1Hash.Sum(sum[:0])
		sha256Hash.Sum(sum[:0])
		sha384Hash.Sum(sum[:0])
		sha512Hash.Sum(sum[:0])

		sha1Hash.Reset()
		sha256Hash.Reset()
		sha384Hash.Reset()
		sha512Hash.Reset()
	}))
	want := 0
	if n > want {
		t.Errorf("allocs = %d, want %d", n, want)
	}
}

func BenchmarkSHA256_8Bytes(b *testing.B) {
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
		h.Write(buf)
		h.Sum(sum[:0])
	}
}

func BenchmarkSHA256_OneShot(b *testing.B) {
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
