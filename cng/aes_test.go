// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math"
	"runtime"
	"strings"
	"testing"

	"github.com/microsoft/go-crypto-winnative/cng"
	"github.com/microsoft/go-crypto-winnative/internal/cryptotest"
)

var key = []byte("D249BF6DEC97B1EBD69BC4D6B3A3C49D")

const (
	gcmTagSize           = 16
	gcmStandardNonceSize = 12
)

func TestNewGCMNonce(t *testing.T) {
	ci, err := cng.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	c := ci.(interface {
		NewGCM(nonceSize, tagSize int) (cipher.AEAD, error)
	})
	_, err = c.NewGCM(gcmStandardNonceSize-1, gcmTagSize-1)
	if err != nil {
		t.Errorf("expected no error for non-standard tag and nonce sizes, got: %#v", err)
	}
	_, err = c.NewGCM(gcmStandardNonceSize-1, gcmTagSize)
	if err != nil {
		t.Errorf("expected no error for non-standard nonce size with standard tag size, got: %#v", err)
	}
	_, err = c.NewGCM(gcmStandardNonceSize, gcmTagSize-1)
	if err != nil {
		t.Errorf("expected no error for standard tag size, got: %#v", err)
	}
	_, err = c.NewGCM(gcmStandardNonceSize, gcmTagSize)
	if err != nil {
		t.Errorf("expected no error for standard tag / nonce size, got: %#v", err)
	}
}

func TestAESGCMParameters(t *testing.T) {
	for _, keySize := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("AES-%d", keySize*8), func(t *testing.T) {
			key := bytes.Repeat([]byte{0x42}, keySize)
			block, err := cng.NewAESCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			c := block.(interface {
				NewGCM(nonceSize, tagSize int) (cipher.AEAD, error)
			})
			stdBlock, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			for _, nonceSize := range []int{1, 8, 11, 12, 13, 16, 100} {
				stdGCM, err := cipher.NewGCMWithNonceSize(stdBlock, nonceSize)
				if err != nil {
					t.Fatal(err)
				}
				for tagSize := 12; tagSize <= gcmTagSize; tagSize++ {
					t.Run(fmt.Sprintf("Nonce-%d/Tag-%d", nonceSize, tagSize), func(t *testing.T) {
						gcm, err := c.NewGCM(nonceSize, tagSize)
						if err != nil {
							t.Fatal(err)
						}
						if gcm.NonceSize() != nonceSize || gcm.Overhead() != tagSize {
							t.Fatalf("NonceSize, Overhead = %d, %d, want %d, %d", gcm.NonceSize(), gcm.Overhead(), nonceSize, tagSize)
						}
						nonce := bytes.Repeat([]byte{0x24}, nonceSize)
						for size := 0; size < tagSize; size++ {
							got, err := gcm.Open(nil, nonce, make([]byte, size), nil)
							if got != nil || err == nil {
								t.Fatalf("Open with ciphertext size %d = (%x, %v), want (nil, error)", size, got, err)
							}
						}
						for _, size := range []int{0, 1, 16, 17, 1024} {
							for _, additionalData := range [][]byte{nil, []byte("additional data")} {
								plaintext := bytes.Repeat([]byte{0x5a}, size)
								want := stdGCM.Seal(nil, nonce, plaintext, additionalData)
								// GCM truncates the tag without changing the ciphertext.
								want = want[:len(want)-gcmTagSize+tagSize]
								got := gcm.Seal(nil, nonce, plaintext, additionalData)
								if !bytes.Equal(got, want) {
									t.Fatalf("Seal with plaintext size %d and AAD size %d = %x, want %x", size, len(additionalData), got, want)
								}
								got, err = gcm.Open(nil, nonce, want, additionalData)
								if err != nil || !bytes.Equal(got, plaintext) {
									t.Fatalf("Open = (%x, %v), want (%x, nil)", got, err, plaintext)
								}

								buf := make([]byte, len(plaintext), len(plaintext)+tagSize)
								copy(buf, plaintext)
								got = gcm.Seal(buf[:0], nonce, buf, additionalData)
								if !bytes.Equal(got, want) {
									t.Fatalf("in-place Seal = %x, want %x", got, want)
								}
								got, err = gcm.Open(got[:0], nonce, got, additionalData)
								if err != nil || !bytes.Equal(got, plaintext) {
									t.Fatalf("in-place Open = (%x, %v), want (%x, nil)", got, err, plaintext)
								}

								bad := bytes.Clone(want)
								bad[len(bad)-1] ^= 1
								prefix := []byte("prefix")
								out := bytes.Repeat([]byte{0xaa}, len(prefix)+len(plaintext))
								copy(out, prefix)
								got, err = gcm.Open(out[:len(prefix)], nonce, bad, additionalData)
								if got != nil || err == nil {
									t.Fatalf("Open with invalid tag = (%x, %v), want (nil, error)", got, err)
								}
								if !bytes.Equal(out[:len(prefix)], prefix) {
									t.Fatalf("Open modified output prefix: %x", out[:len(prefix)])
								}
								if !bytes.Equal(out[len(prefix):], make([]byte, len(plaintext))) {
									t.Fatalf("Open did not clear unauthenticated plaintext: %x", out[len(prefix):])
								}
							}
						}
						t.Run("SealAdditionalDataOverlap", func(t *testing.T) {
							out := make([]byte, 16+gcm.Overhead())
							assertPanic(t, func() {
								gcm.Seal(out[:0], nonce, make([]byte, 16), out[:1])
							})
						})
						t.Run("OpenAdditionalDataOverlap", func(t *testing.T) {
							out := make([]byte, 16)
							ciphertext := gcm.Seal(nil, nonce, make([]byte, 16), out[:1])
							assertPanic(t, func() {
								gcm.Open(out[:0], nonce, ciphertext, out[:1])
							})
						})
					})
				}
			}
		})
	}
}

func TestAESGCMInvalidParameters(t *testing.T) {
	block, err := cng.NewAESCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	c := block.(interface {
		NewGCM(nonceSize, tagSize int) (cipher.AEAD, error)
	})
	for _, tt := range []struct {
		nonceSize int
		tagSize   int
	}{
		{-1, gcmTagSize},
		{0, gcmTagSize},
		{gcmStandardNonceSize, -1},
		{gcmStandardNonceSize, 0},
		{gcmStandardNonceSize, 11},
		{gcmStandardNonceSize, 17},
		{1, 11},
		{1, 17},
	} {
		t.Run(fmt.Sprintf("Nonce-%d/Tag-%d", tt.nonceSize, tt.tagSize), func(t *testing.T) {
			gcm, err := c.NewGCM(tt.nonceSize, tt.tagSize)
			if err == nil || gcm != nil {
				t.Fatalf("NewGCM = (%v, %v), want (nil, error)", gcm, err)
			}
		})
	}
}

func TestAESGCMRandomNonceParameters(t *testing.T) {
	block, err := cng.NewAESCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	c := block.(interface {
		NewGCM(nonceSize, tagSize int) (cipher.AEAD, error)
	})
	for _, tt := range []struct {
		nonceSize int
		tagSize   int
	}{
		{1, gcmTagSize},
		{gcmStandardNonceSize, 12},
		{16, 15},
	} {
		t.Run(fmt.Sprintf("Nonce-%d/Tag-%d", tt.nonceSize, tt.tagSize), func(t *testing.T) {
			gcm, err := c.NewGCM(tt.nonceSize, tt.tagSize)
			if err != nil {
				t.Fatal(err)
			}
			g := gcm.(interface {
				SealWithRandomNonce(out, nonce, plaintext, additionalData []byte)
			})
			assertPanic(t, func() {
				g.SealWithRandomNonce(make([]byte, gcmTagSize), make([]byte, gcmStandardNonceSize), nil, nil)
			})
		})
	}
}

func TestAESGCMOversizedNonce(t *testing.T) {
	nonce := cryptotest.OversizedBuffer(t)
	block, err := cng.NewAESCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := block.(interface {
		NewGCM(nonceSize, tagSize int) (cipher.AEAD, error)
	}).NewGCM(len(nonce), gcmTagSize)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := gcm.Open(nil, nonce, make([]byte, gcm.Overhead()), nil); err == nil || out != nil {
		t.Fatalf("Open with oversized nonce = (%x, %v), want (nil, error)", out, err)
	}
	assertPanic(t, func() {
		gcm.Seal(nil, nonce, nil, nil)
	})
}

func TestSealAndOpen(t *testing.T) {
	ci, err := cng.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCMWithTagSize(ci, gcmTagSize)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte{0x91, 0xc7, 0xa7, 0x54, 0x52, 0xef, 0x10, 0xdb, 0x91, 0xa8, 0x6c, 0xf9}
	plainText := []byte{0x01, 0x02, 0x03}
	additionalData := []byte{0x05, 0x05, 0x07}
	sealed := gcm.Seal(nil, nonce, plainText, additionalData)
	decrypted, err := gcm.Open(nil, nonce, sealed, additionalData)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(decrypted, plainText) {
		t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, plainText)
	}
	// Test with no additional data.
	sealed = gcm.Seal(nil, nonce, plainText, []byte{})
	decrypted, err = gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(decrypted, plainText) {
		t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, plainText)
	}
}

func TestSealWithRandomNonce(t *testing.T) {
	block, err := cng.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := block.(interface {
		NewGCM(nonceSize, tagSize int) (cipher.AEAD, error)
	}).NewGCM(gcmStandardNonceSize, gcmTagSize)
	if err != nil {
		t.Fatal(err)
	}
	g := gcm.(interface {
		SealWithRandomNonce(out, nonce, plaintext, additionalData []byte)
	})
	for _, size := range []int{0, 1, 32, 1024} {
		plaintext := bytes.Repeat([]byte{0x5a}, size)
		nonce := make([]byte, gcm.NonceSize())
		out := make([]byte, len(plaintext)+gcm.Overhead())
		g.SealWithRandomNonce(out, nonce, plaintext, nil)
		got, err := gcm.Open(nil, nonce, out, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round trip = %x, want %x", got, plaintext)
		}
		if allocs := testing.AllocsPerRun(10, func() {
			g.SealWithRandomNonce(out, nonce, plaintext, nil)
		}); allocs != 0 {
			t.Fatalf("size %d: allocations = %v, want 0", size, allocs)
		}
	}
}

func TestSealAndOpenTLS(t *testing.T) {
	tests := []struct {
		name string
		tls  string
		mask func(n *[12]byte)
	}{
		{"1.2", "1.2", nil},
		{"1.3", "1.3", nil},
		{"1.3_masked", "1.3", func(n *[12]byte) {
			// Arbitrary mask in the high bits.
			n[9] ^= 0x42
			// Mask the very first bit. This makes sure that if Seal doesn't
			// handle the mask, the counter appears to go backwards and panics
			// when it shouldn't.
			n[11] ^= 0x1
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ci, err := cng.NewAESCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			var gcm cipher.AEAD
			switch tt.tls {
			case "1.2":
				gcm, err = cng.NewGCMTLS(ci)
			case "1.3":
				gcm, err = cng.NewGCMTLS13(ci)
			}
			if err != nil {
				t.Fatal(err)
			}
			nonce := [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			nonce1 := [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
			nonce9 := [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}
			nonce10 := [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}
			nonceMax := [12]byte{0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255}
			if tt.mask != nil {
				for _, m := range []*[12]byte{&nonce, &nonce1, &nonce9, &nonce10, &nonceMax} {
					tt.mask(m)
				}
			}
			plainText := []byte{0x01, 0x02, 0x03}
			var additionalData []byte
			switch tt.tls {
			case "1.2":
				additionalData = make([]byte, 13)
			case "1.3":
				additionalData = []byte{23, 3, 3, 0, 0}
			}
			additionalData[len(additionalData)-2] = byte(len(plainText) >> 8)
			additionalData[len(additionalData)-1] = byte(len(plainText))
			sealed := gcm.Seal(nil, nonce[:], plainText, additionalData)
			assertPanic(t, func() {
				gcm.Seal(nil, nonce[:], plainText, additionalData)
			})
			sealed1 := gcm.Seal(nil, nonce1[:], plainText, additionalData)
			gcm.Seal(nil, nonce10[:], plainText, additionalData)
			assertPanic(t, func() {
				gcm.Seal(nil, nonce9[:], plainText, additionalData)
			})
			assertPanic(t, func() {
				gcm.Seal(nil, nonceMax[:], plainText, additionalData)
			})
			if bytes.Equal(sealed, sealed1) {
				t.Errorf("different nonces should produce different outputs\ngot: %#v\nexp: %#v", sealed, sealed1)
			}
			decrypted, err := gcm.Open(nil, nonce[:], sealed, additionalData)
			if err != nil {
				t.Error(err)
			}
			decrypted1, err := gcm.Open(nil, nonce1[:], sealed1, additionalData)
			if err != nil {
				t.Error(err)
			}
			if !bytes.Equal(decrypted, plainText) {
				t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, plainText)
			}
			if !bytes.Equal(decrypted, decrypted1) {
				t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, decrypted1)
			}
		})
	}
}

func TestSealAndOpenAuthenticationError(t *testing.T) {
	ci, err := cng.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCMWithTagSize(ci, gcmTagSize)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte{0x91, 0xc7, 0xa7, 0x54, 0x52, 0xef, 0x10, 0xdb, 0x91, 0xa8, 0x6c, 0xf9}
	plainText := []byte{0x01, 0x02, 0x03}
	additionalData := []byte{0x05, 0x05, 0x07}
	sealed := gcm.Seal(nil, nonce, plainText, additionalData)
	_, err = gcm.Open(nil, nonce, sealed, nil)
	if !strings.Contains(err.Error(), "cipher: message authentication failed") {
		t.Errorf("expected authentication error, got: %#v", err)
	}
}

func assertPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	f()
}

func TestSealPanic(t *testing.T) {
	ci, err := cng.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCMWithTagSize(ci, gcmTagSize)
	if err != nil {
		t.Fatal(err)
	}
	for _, nonceSize := range []int{1, gcmStandardNonceSize, 16, 100} {
		gcm, err := cipher.NewGCMWithNonceSize(ci, nonceSize)
		if err != nil {
			t.Fatal(err)
		}
		for _, size := range []int{nonceSize - 1, nonceSize + 1} {
			assertPanic(t, func() {
				gcm.Seal(nil, make([]byte, size), []byte{0x01, 0x02, 0x03}, nil)
			})
			assertPanic(t, func() {
				gcm.Open(nil, make([]byte, size), make([]byte, gcm.Overhead()), nil)
			})
		}
	}
	if runtime.GOARCH != "386" {
		assertPanic(t, func() {
			gcm.Seal(nil, make([]byte, gcmStandardNonceSize), make([]byte, math.MaxInt), nil)
		})
	}
}

func TestAESInvalidKeySize(t *testing.T) {
	_, err := cng.NewAESCipher([]byte{1})
	if err == nil {
		t.Error("error expected")
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	ci, err := cng.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	plainText := make([]byte, ci.BlockSize())
	plainText[1] = 1
	plainText[15] = 15
	cipherText := make([]byte, ci.BlockSize())
	decrypted := make([]byte, ci.BlockSize())
	ci.Encrypt(cipherText, plainText)
	ci.Decrypt(decrypted, cipherText)
	if !bytes.Equal(decrypted, plainText) {
		t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, plainText)
	}
}

func TestCBCBlobEncryptBasicBlockEncryption(t *testing.T) {
	key := []byte{0x24, 0xcd, 0x8b, 0x13, 0x37, 0xc5, 0xc1, 0xb1, 0x0, 0xbb, 0x27, 0x40, 0x4f, 0xab, 0x5f, 0x7b, 0x2d, 0x0, 0x20, 0xf5, 0x1, 0x84, 0x4, 0xbf, 0xe3, 0xbd, 0xa1, 0xc4, 0xbf, 0x61, 0x2f, 0xc5}
	iv := []byte{0x91, 0xc7, 0xa7, 0x54, 0x52, 0xef, 0x10, 0xdb, 0x91, 0xa8, 0x6c, 0xf9, 0x79, 0xd5, 0xac, 0x74}

	block, err := cng.NewAESCipher(key)
	if err != nil {
		t.Errorf("expected no error for aes.NewCipher, got: %s", err)
	}

	blockSize := block.BlockSize()
	if blockSize != 16 {
		t.Errorf("unexpected block size, expected 16 got: %d", blockSize)
	}

	encrypter := cipher.NewCBCEncrypter(block, iv)

	encrypted := make([]byte, 32)

	// First block. 16 bytes.
	srcBlock1 := bytes.Repeat([]byte{0x01}, 16)
	encrypter.CryptBlocks(encrypted, srcBlock1)
	if !bytes.Equal([]byte{
		0x14, 0xb7, 0x3e, 0x2f, 0xd9, 0xe7, 0x69, 0x7e, 0xb7, 0xd2, 0xc3, 0x5b, 0x31, 0x9c, 0xf0, 0x59,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, encrypted) {
		t.Error("unexpected CryptBlocks result for first block")
	}

	// Second block. 16 bytes.
	srcBlock2 := bytes.Repeat([]byte{0x02}, 16)
	encrypter.CryptBlocks(encrypted[16:], srcBlock2)
	if !bytes.Equal([]byte{
		0x14, 0xb7, 0x3e, 0x2f, 0xd9, 0xe7, 0x69, 0x7e, 0xb7, 0xd2, 0xc3, 0x5b, 0x31, 0x9c, 0xf0, 0x59,
		0xbb, 0xd4, 0x95, 0x25, 0x21, 0x56, 0x87, 0x3b, 0xe6, 0x22, 0xe8, 0xd0, 0x19, 0xa8, 0xed, 0xcd,
	}, encrypted) {
		t.Error("unexpected CryptBlocks result for second block")
	}

	decrypter := cipher.NewCBCDecrypter(block, iv)
	plainText := append(srcBlock1, srcBlock2...)
	decrypted := make([]byte, len(plainText))
	decrypter.CryptBlocks(decrypted, encrypted[:16])
	decrypter.CryptBlocks(decrypted[16:], encrypted[16:])
	if !bytes.Equal(decrypted, plainText) {
		t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, plainText)
	}
}

func TestCBCDecryptSimple(t *testing.T) {
	key := []byte{
		0x24, 0xcd, 0x8b, 0x13, 0x37, 0xc5, 0xc1, 0xb1,
		0x0, 0xbb, 0x27, 0x40, 0x4f, 0xab, 0x5f, 0x7b,
		0x2d, 0x0, 0x20, 0xf5, 0x1, 0x84, 0x4, 0xbf,
		0xe3, 0xbd, 0xa1, 0xc4, 0xbf, 0x61, 0x2f, 0xc5,
	}

	block, err := cng.NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	iv := []byte{
		0x91, 0xc7, 0xa7, 0x54, 0x52, 0xef, 0x10, 0xdb,
		0x91, 0xa8, 0x6c, 0xf9, 0x79, 0xd5, 0xac, 0x74,
	}

	encrypter := cipher.NewCBCEncrypter(block, iv)
	decrypter := cipher.NewCBCDecrypter(block, iv)

	plainText := []byte{
		0x54, 0x68, 0x65, 0x72, 0x65, 0x20, 0x69, 0x73,
		0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
		0x65, 0x20, 0x4c, 0x6f, 0x72, 0x64, 0x20, 0x6f,
		0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x52, 0x69,
		0x6e, 0x67, 0x2c, 0x20, 0x6f, 0x6e, 0x6c, 0x79,
		0x20, 0x6f, 0x6e, 0x65, 0x20, 0x77, 0x68, 0x6f,
		0x20, 0x63, 0x61, 0x6e, 0x20, 0x62, 0x65, 0x6e,
		0x64, 0x20, 0x69, 0x74, 0x20, 0x74, 0x6f, 0x20,
		0x68, 0x69, 0x73, 0x20, 0x77, 0x69, 0x6c, 0x6c,
		0x2e, 0x20, 0x41, 0x6e, 0x64, 0x20, 0x68, 0x65,
		0x20, 0x64, 0x6f, 0x65, 0x73, 0x20, 0x6e, 0x6f,
		0x74, 0x20, 0x73, 0x68, 0x61, 0x72, 0x65, 0x20,
		0x70, 0x6f, 0x77, 0x65, 0x72, 0x2e, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	cipherText := make([]byte, len(plainText))

	encrypter.CryptBlocks(cipherText, plainText[:64])
	encrypter.CryptBlocks(cipherText[64:], plainText[64:])

	expectedCipherText := []byte{
		23, 51, 192, 210, 170, 124, 30, 218,
		176, 54, 70, 132, 141, 124, 3, 152,
		47, 3, 37, 81, 187, 101, 197, 94,
		11, 38, 128, 60, 112, 20, 235, 130,
		111, 236, 176, 99, 121, 6, 221, 181,
		190, 228, 150, 177, 218, 3, 196, 0,
		5, 141, 169, 151, 3, 161, 64, 244,
		231, 237, 252, 143, 111, 37, 68, 70,
		11, 137, 220, 243, 195, 90, 182, 83,
		96, 80, 122, 14, 93, 178, 62, 159,
		25, 162, 200, 155, 21, 150, 6, 101,
		21, 234, 12, 74, 190, 213, 159, 220,
		111, 184, 94, 169, 188, 93, 38, 150,
		3, 208, 185, 201, 212, 246, 238, 181,
	}

	if !bytes.Equal(expectedCipherText, cipherText) {
		t.Fail()
	}

	decrypted := make([]byte, len(plainText))

	decrypter.CryptBlocks(decrypted, cipherText[:64])
	decrypter.CryptBlocks(decrypted[64:], cipherText[64:])

	if len(decrypted) != len(plainText) {
		t.Fail()
	}

	if !bytes.Equal(plainText, decrypted) {
		t.Errorf("decryption incorrect\nexp %v, got %v\n", plainText, decrypted)
	}
}

// Test AES against the general cipher.Block interface tester.
func TestAESBlock(t *testing.T) {
	for _, keylen := range []int{128, 192, 256} {
		t.Run(fmt.Sprintf("AES-%d", keylen), func(t *testing.T) {
			cryptotest.TestBlock(t, keylen/8, cng.NewAESCipher)
		})
	}
}

func TestAESBlockMode(t *testing.T) {
	for _, keylen := range []int{128, 192, 256} {
		t.Run(fmt.Sprintf("AES-%d", keylen), func(t *testing.T) {
			rng := newRandReader(t)

			key := make([]byte, keylen/8)
			rng.Read(key)

			block, err := cng.NewAESCipher(key)
			if err != nil {
				t.Fatal(err)
			}

			cryptotest.TestBlockMode(t, block, cipher.NewCBCEncrypter, cipher.NewCBCDecrypter)
		})
	}
}

// Test GCM against the general cipher.AEAD interface tester.
func TestAESGCMAEAD(t *testing.T) {
	for _, keySize := range []int{128, 192, 256} {
		// Use AES as underlying block cipher at different key sizes for GCM.
		t.Run(fmt.Sprintf("AES-%d", keySize), func(t *testing.T) {
			rng := newRandReader(t)

			key := make([]byte, keySize/8)
			rng.Read(key)

			block, err := cng.NewAESCipher(key)
			if err != nil {
				panic(err)
			}

			// Test GCM with the current AES block with the standard nonce and tag
			// sizes.
			cryptotest.TestAEAD(t, func() (cipher.AEAD, error) { return cipher.NewGCM(block) })

			// Test non-standard tag sizes.
			for tagSize := 12; tagSize < gcmTagSize; tagSize++ {
				t.Run(fmt.Sprintf("TagSize-%d", tagSize), func(t *testing.T) {
					cryptotest.TestAEAD(t, func() (cipher.AEAD, error) { return cipher.NewGCMWithTagSize(block, tagSize) })
				})
			}

			// Test non-standard nonce sizes.
			for _, nonceSize := range []int{1, 8, 11, 13, 16, 100} {
				t.Run(fmt.Sprintf("NonceSize-%d", nonceSize), func(t *testing.T) {

					cryptotest.TestAEAD(t, func() (cipher.AEAD, error) { return cipher.NewGCMWithNonceSize(block, nonceSize) })
				})
			}
		})
	}
}
