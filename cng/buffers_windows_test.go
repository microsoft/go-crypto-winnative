// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package cng

import (
	"crypto/cipher"
	"testing"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
	"github.com/microsoft/go-crypto-winnative/internal/cryptotest"
)

func TestOversizedAEADData(t *testing.T) {
	large := cryptotest.OversizedBuffer(t)
	block, err := NewAESCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		aead cipher.AEAD
	}{{"GCM", gcm}}
	if SupportsChaCha20Poly1305() {
		chacha, err := NewChaCha20Poly1305(make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		tests = append(tests, struct {
			name string
			aead cipher.AEAD
		}{"ChaCha20Poly1305", chacha})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce := make([]byte, tt.aead.NonceSize())
			plaintext := []byte("message")
			ciphertext := tt.aead.Seal(nil, nonce, plaintext, nil)
			if out, err := tt.aead.Open(nil, nonce, ciphertext, large); err == nil || out != nil {
				t.Fatalf("Open with oversized AAD = (%x, %v), want (nil, error)", out, err)
			}
			oversizedCiphertext := large[:len(large)+tt.aead.Overhead()]
			if out, err := tt.aead.Open(nil, nonce, oversizedCiphertext, nil); err == nil || out != nil {
				t.Fatalf("Open with oversized ciphertext = (%x, %v), want (nil, error)", out, err)
			}
			t.Run("Seal AAD", func(t *testing.T) {
				defer func() {
					if recover() == nil {
						t.Error("expected a panic for oversized AAD")
					}
				}()
				tt.aead.Seal(nil, nonce, plaintext, large)
			})
			t.Run("Seal plaintext", func(t *testing.T) {
				defer func() {
					if recover() == nil {
						t.Error("expected a panic for oversized plaintext")
					}
				}()
				tt.aead.Seal(nil, nonce, large, nil)
			})
		})
	}
	t.Run("GCM random nonce AAD", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("expected a panic for oversized AAD")
			}
		}()
		gcm.(interface {
			SealWithRandomNonce(out, nonce, plaintext, additionalData []byte)
		}).SealWithRandomNonce(make([]byte, gcm.Overhead()), make([]byte, gcm.NonceSize()), nil, large)
	})
}

func TestOversizedKDFParameters(t *testing.T) {
	large := cryptotest.OversizedBuffer(t)
	want := bcrypt.CheckBufferSizes(len(large))
	tests := []struct {
		name string
		call func() error
	}{
		{"HKDF info", func() error {
			_, err := ExpandHKDF(NewSHA256, nil, large, 32)
			return err
		}},
		{"HKDF empty output", func() error {
			_, err := ExpandHKDF(NewSHA256, nil, large, 0)
			return err
		}},
		{"HKDF output", func() error {
			_, err := ExpandHKDF(NewSHA256, nil, nil, len(large))
			return err
		}},
		{"PBKDF2 salt", func() error {
			_, err := PBKDF2(nil, large, 1, 32, NewSHA256)
			return err
		}},
		{"PBKDF2 output", func() error {
			_, err := PBKDF2(nil, nil, 1, len(large), NewSHA256)
			return err
		}},
		{"TLS label", func() error { return TLS1PRF(nil, nil, large, nil, NewSHA256) }},
		{"TLS seed", func() error { return TLS1PRF(nil, nil, nil, large, NewSHA256) }},
		{"TLS output", func() error { return TLS1PRF(large, nil, nil, nil, NewSHA256) }},
		{"OAEP label", func() error {
			_, err := rsaOAEP(nil, nil, nil, large, true)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); err != want {
				t.Fatalf("got %v, want %v", err, want)
			}
		})
	}
}
