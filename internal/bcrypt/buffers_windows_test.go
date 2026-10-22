// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bcrypt

import (
	"testing"

	"github.com/microsoft/go-crypto-winnative/internal/cryptotest"
)

func TestOversizedNativeBuffers(t *testing.T) {
	large := cryptotest.OversizedBuffer(t)
	var size uint32
	var key KEY_HANDLE
	tests := []struct {
		name string
		call func() error
	}{
		{"hash input", func() error { return Hash(nil, nil, large, nil) }},
		{"hash output", func() error { return Hash(nil, nil, nil, large) }},
		{"hash data", func() error { return HashData(nil, large, 0) }},
		{"finish hash", func() error { return FinishHash(nil, large, 0) }},
		{"sign", func() error { return SignHash(nil, nil, large, nil, &size, 0) }},
		{"verify", func() error { return VerifySignature(nil, nil, large, nil, 0) }},
		{"derive", func() error { return KeyDerivation(nil, nil, large, &size, 0) }},
		{"property", func() error { return SetProperty(nil, nil, large, 0) }},
		{"encrypt input", func() error { return Encrypt(nil, large, nil, nil, nil, &size, 0) }},
		{"encrypt output", func() error { return Encrypt(nil, nil, nil, nil, large, &size, 0) }},
		{"decrypt input", func() error { return Decrypt(nil, large, nil, nil, nil, &size, 0) }},
		{"decrypt output", func() error { return Decrypt(nil, nil, nil, nil, large, &size, 0) }},
		{"symmetric key", func() error { return GenerateSymmetricKey(nil, &key, nil, large, 0) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); err != errBufferTooLarge {
				t.Fatalf("got %v, want %v", err, errBufferTooLarge)
			}
		})
	}
}
