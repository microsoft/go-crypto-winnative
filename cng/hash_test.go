// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"hash"
	"io"
	"math/rand"
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
		return cng.NewSHA3_256
	case crypto.SHA3_384:
		return cng.NewSHA3_384
	case crypto.SHA3_512:
		return cng.NewSHA3_512
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

			h2, err := h.(interface{ Clone() (hash.Hash, error) }).Clone()
			if err != nil {
				t.Fatal(err)
			}
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
			b := cng.SHA3_256(p)
			return b[:]
		}},
		{crypto.SHA3_384, func(p []byte) []byte {
			b := cng.SHA3_384(p)
			return b[:]
		}},
		{crypto.SHA3_512, func(p []byte) []byte {
			b := cng.SHA3_512(p)
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

// testShakes contains functions that return *sha3.SHAKE instances for
// with output-length equal to the KAT length.
var testShakes = map[string]struct {
	constructor  func(N []byte, S []byte) *cng.SHAKE
	defAlgoName  string
	defCustomStr string
}{
	// NewCSHAKE without customization produces same result as SHAKE
	"SHAKE128":  {cng.NewCSHAKE128, "", ""},
	"SHAKE256":  {cng.NewCSHAKE256, "", ""},
	"cSHAKE128": {cng.NewCSHAKE128, "CSHAKE128", "CustomString"},
	"cSHAKE256": {cng.NewCSHAKE256, "CSHAKE256", "CustomString"},
}

// TestCSHAKESqueezing checks that squeezing the full output a single time produces
// the same output as repeatedly squeezing the instance.
func TestCSHAKESqueezing(t *testing.T) {
	const testString = "brekeccakkeccak koax koax"
	for algo, v := range testShakes {
		d0 := v.constructor([]byte(v.defAlgoName), []byte(v.defCustomStr))
		d0.Write([]byte(testString))
		ref := make([]byte, 32)
		d0.Read(ref)

		d1 := v.constructor([]byte(v.defAlgoName), []byte(v.defCustomStr))
		d1.Write([]byte(testString))
		var multiple []byte
		for range ref {
			d1.Read(make([]byte, 0))
			one := make([]byte, 1)
			d1.Read(one)
			multiple = append(multiple, one...)
		}
		if !bytes.Equal(ref, multiple) {
			t.Errorf("%s: squeezing %d bytes one at a time failed", algo, len(ref))
		}
	}
}

// sequentialBytes produces a buffer of size consecutive bytes 0x00, 0x01, ..., used for testing.
func sequentialBytes(size int) []byte {
	alignmentOffset := rand.Intn(8)
	result := make([]byte, size+alignmentOffset)[alignmentOffset:]
	for i := range result {
		result[i] = byte(i)
	}
	return result
}

func TestCSHAKEReset(t *testing.T) {
	out1 := make([]byte, 32)
	out2 := make([]byte, 32)

	for _, v := range testShakes {
		// Calculate hash for the first time
		c := v.constructor(nil, []byte{0x99, 0x98})
		c.Write(sequentialBytes(0x100))
		c.Read(out1)

		// Calculate hash again
		c.Reset()
		c.Write(sequentialBytes(0x100))
		c.Read(out2)

		if !bytes.Equal(out1, out2) {
			t.Error("\nExpected:\n", out1, "\ngot:\n", out2)
		}
	}
}

func TestCSHAKEAccumulated(t *testing.T) {
	t.Run("CSHAKE128", func(t *testing.T) {
		testCSHAKEAccumulated(t, cng.NewCSHAKE128, (1600-256)/8,
			"bb14f8657c6ec5403d0b0e2ef3d3393497e9d3b1a9a9e8e6c81dbaa5fd809252")
	})
	t.Run("CSHAKE256", func(t *testing.T) {
		testCSHAKEAccumulated(t, cng.NewCSHAKE256, (1600-512)/8,
			"0baaf9250c6e25f0c14ea5c7f9bfde54c8a922c8276437db28f3895bdf6eeeef")
	})
}

func testCSHAKEAccumulated(t *testing.T, newCSHAKE func(N, S []byte) *cng.SHAKE, rate int64, exp string) {
	rnd := newCSHAKE(nil, nil)
	acc := newCSHAKE(nil, nil)
	for n := 0; n < 200; n++ {
		N := make([]byte, n)
		rnd.Read(N)
		for s := 0; s < 200; s++ {
			S := make([]byte, s)
			rnd.Read(S)

			c := newCSHAKE(N, S)
			io.CopyN(c, rnd, 100 /* < rate */)
			io.CopyN(acc, c, 200)

			c.Reset()
			io.CopyN(c, rnd, rate)
			io.CopyN(acc, c, 200)

			c.Reset()
			io.CopyN(c, rnd, 200 /* > rate */)
			io.CopyN(acc, c, 200)
		}
	}
	out := make([]byte, 32)
	acc.Read(out)
	if got := hex.EncodeToString(out); got != exp {
		t.Errorf("got %s, want %s", got, exp)
	}
}

func TestCSHAKELargeS(t *testing.T) {
	const s = (1<<32)/8 + 1000 // s * 8 > 2^32
	S := make([]byte, s)
	rnd := cng.NewSHAKE128()
	rnd.Read(S)
	c := cng.NewCSHAKE128(nil, S)
	io.CopyN(c, rnd, 1000)
	out := make([]byte, 32)
	c.Read(out)

	exp := "2cb9f237767e98f2614b8779cf096a52da9b3a849280bbddec820771ae529cf0"
	if got := hex.EncodeToString(out); got != exp {
		t.Errorf("got %s, want %s", got, exp)
	}
}

func TestCSHAKESum(t *testing.T) {
	const testString = "hello world"
	t.Run("CSHAKE128", func(t *testing.T) {
		h := cng.NewCSHAKE128(nil, nil)
		h.Write([]byte(testString[:5]))
		h.Write([]byte(testString[5:]))
		want := make([]byte, 32)
		h.Read(want)
		got := cng.SumSHAKE128([]byte(testString), 32)
		if !bytes.Equal(got, want) {
			t.Errorf("got:%x want:%x", got, want)
		}
	})
	t.Run("CSHAKE256", func(t *testing.T) {
		h := cng.NewCSHAKE256(nil, nil)
		h.Write([]byte(testString[:5]))
		h.Write([]byte(testString[5:]))
		want := make([]byte, 32)
		h.Read(want)
		got := cng.SumSHAKE256([]byte(testString), 32)
		if !bytes.Equal(got, want) {
			t.Errorf("got:%x want:%x", got, want)
		}
	})
}

// benchmarkHash tests the speed to hash num buffers of buflen each.
func benchmarkHash(b *testing.B, h hash.Hash, size, num int) {
	b.StopTimer()
	h.Reset()
	data := sequentialBytes(size)
	b.SetBytes(int64(size * num))
	b.StartTimer()

	var state []byte
	for i := 0; i < b.N; i++ {
		for j := 0; j < num; j++ {
			h.Write(data)
		}
		state = h.Sum(state[:0])
	}
	b.StopTimer()
	h.Reset()
}

// benchmarkCSHAKE is specialized to the Shake instances, which don't
// require a copy on reading output.
func benchmarkCSHAKE(b *testing.B, h *cng.SHAKE, size, num int) {
	b.StopTimer()
	h.Reset()
	data := sequentialBytes(size)
	d := make([]byte, 32)

	b.SetBytes(int64(size * num))
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		h.Reset()
		for j := 0; j < num; j++ {
			h.Write(data)
		}
		h.Read(d)
	}
}

func BenchmarkSHA3_512_MTU(b *testing.B) { benchmarkHash(b, cng.NewSHA3_512(), 1350, 1) }
func BenchmarkSHA3_384_MTU(b *testing.B) { benchmarkHash(b, cng.NewSHA3_384(), 1350, 1) }
func BenchmarkSHA3_256_MTU(b *testing.B) { benchmarkHash(b, cng.NewSHA3_256(), 1350, 1) }

func BenchmarkCSHAKE128_MTU(b *testing.B)  { benchmarkCSHAKE(b, cng.NewSHAKE128(), 1350, 1) }
func BenchmarkCSHAKE256_MTU(b *testing.B)  { benchmarkCSHAKE(b, cng.NewSHAKE256(), 1350, 1) }
func BenchmarkCSHAKE256_16x(b *testing.B)  { benchmarkCSHAKE(b, cng.NewSHAKE256(), 16, 1024) }
func BenchmarkCSHAKE256_1MiB(b *testing.B) { benchmarkCSHAKE(b, cng.NewSHAKE256(), 1024, 1024) }

func BenchmarkCSHA3_512_1MiB(b *testing.B) { benchmarkHash(b, cng.NewSHA3_512(), 1024, 1024) }
