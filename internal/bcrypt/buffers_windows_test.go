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
		{"random", func() error { return GenRandom(nil, large, 0) }},
		{"encrypt input", func() error { return Encrypt(nil, large, nil, nil, nil, &size, 0) }},
		{"encrypt IV", func() error { return Encrypt(nil, nil, nil, large, nil, &size, 0) }},
		{"encrypt output", func() error { return Encrypt(nil, nil, nil, nil, large, &size, 0) }},
		{"decrypt input", func() error { return Decrypt(nil, large, nil, nil, nil, &size, 0) }},
		{"decrypt IV", func() error { return Decrypt(nil, nil, nil, large, nil, &size, 0) }},
		{"decrypt output", func() error { return Decrypt(nil, nil, nil, nil, large, &size, 0) }},
		{"symmetric key", func() error { return GenerateSymmetricKey(nil, &key, nil, large, 0) }},
		{"symmetric key object", func() error { return GenerateSymmetricKey(nil, &key, large, nil, 0) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); err != errBufferTooLarge {
				t.Fatalf("got %v, want %v", err, errBufferTooLarge)
			}
			if n := testing.AllocsPerRun(100, func() { _ = tt.call() }); n != 0 {
				t.Fatalf("oversized-buffer check allocated %v times, want 0", n)
			}
		})
	}
}

func TestGeneratedBufferCountBoundary(t *testing.T) {
	large := cryptotest.OversizedBuffer(t)
	t.Cleanup(FailGenRandomForTesting())
	// The replacement rejects the nil handle without reading the buffer.
	// A representable count must still reach that native error path.
	if err := GenRandom(nil, large[:len(large)-1], 0); err == nil {
		t.Fatal("expected the replacement native call to fail")
	} else if _, ok := err.(NTStatus); !ok {
		t.Fatalf("maximum native count returned %v, want a native NTSTATUS error", err)
	}
	if err := GenRandom(nil, large, 0); err != errBufferTooLarge {
		t.Fatalf("overflow returned %v, want %v", err, errBufferTooLarge)
	}
}
