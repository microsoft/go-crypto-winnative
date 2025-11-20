// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng_test

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"testing"

	"github.com/microsoft/go-crypto-winnative/cng"
)

type encapsulationKey interface {
	Bytes() []byte
	Encapsulate() ([]byte, []byte)
}

type decapsulationKey[E encapsulationKey] interface {
	Bytes() []byte
	Decapsulate([]byte) ([]byte, error)
	EncapsulationKey() E
}

func TestMLKEMRoundTrip(t *testing.T) {
	if !cng.SupportsMLKEM() {
		t.Skip("ML-KEM not supported on this platform")
	}
	t.Parallel()
	t.Run("768", func(t *testing.T) {
		testRoundTrip(t, cng.GenerateKeyMLKEM768, cng.NewEncapsulationKeyMLKEM768, cng.NewDecapsulationKeyMLKEM768)
	})
	t.Run("1024", func(t *testing.T) {
		testRoundTrip(t, cng.GenerateKeyMLKEM1024, cng.NewEncapsulationKeyMLKEM1024, cng.NewDecapsulationKeyMLKEM1024)
	})
}

func testRoundTrip[E encapsulationKey, D decapsulationKey[E]](
	t *testing.T, generateKey func() (D, error),
	newEncapsulationKey func([]byte) (E, error),
	newDecapsulationKey func([]byte) (D, error)) {
	t.Parallel()
	dk, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	Ke, c := ek.Encapsulate()
	Kd, err := dk.Decapsulate(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Ke, Kd) {
		t.Fail()
	}

	ek1, err := newEncapsulationKey(ek.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ek.Bytes(), ek1.Bytes()) {
		t.Fail()
	}
	dk1, err := newDecapsulationKey(dk.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dk.Bytes(), dk1.Bytes()) {
		t.Fail()
	}
	Ke1, c1 := ek1.Encapsulate()
	Kd1, err := dk1.Decapsulate(c1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Ke1, Kd1) {
		t.Fail()
	}

	dk2, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dk.EncapsulationKey().Bytes(), dk2.EncapsulationKey().Bytes()) {
		t.Fail()
	}
	if bytes.Equal(dk.Bytes(), dk2.Bytes()) {
		t.Fail()
	}

	Ke2, c2 := dk.EncapsulationKey().Encapsulate()
	if bytes.Equal(c, c2) {
		t.Fail()
	}
	if bytes.Equal(Ke, Ke2) {
		t.Fail()
	}
}

func TestMLKEMBadLengths(t *testing.T) {
	if !cng.SupportsMLKEM() {
		t.Skip("ML-KEM not supported on this platform")
	}
	t.Parallel()
	t.Run("768", func(t *testing.T) {
		testBadLengths(t, cng.GenerateKeyMLKEM768, cng.NewEncapsulationKeyMLKEM768, cng.NewDecapsulationKeyMLKEM768)
	})
	t.Run("1024", func(t *testing.T) {
		testBadLengths(t, cng.GenerateKeyMLKEM1024, cng.NewEncapsulationKeyMLKEM1024, cng.NewDecapsulationKeyMLKEM1024)
	})
}

func testBadLengths[E encapsulationKey, D decapsulationKey[E]](
	t *testing.T, generateKey func() (D, error),
	newEncapsulationKey func([]byte) (E, error),
	newDecapsulationKey func([]byte) (D, error)) {
	t.Parallel()
	dk, err := generateKey()
	dkBytes := dk.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	ekBytes := dk.EncapsulationKey().Bytes()
	_, c := ek.Encapsulate()

	for i := 0; i < len(dkBytes)-1; i++ {
		if _, err := newDecapsulationKey(dkBytes[:i]); err == nil {
			t.Errorf("expected error for dk length %d", i)
		}
	}
	dkLong := dkBytes
	for i := 0; i < 100; i++ {
		dkLong = append(dkLong, 0)
		if _, err := newDecapsulationKey(dkLong); err == nil {
			t.Errorf("expected error for dk length %d", len(dkLong))
		}
	}

	for i := 0; i < len(ekBytes)-1; i++ {
		if _, err := newEncapsulationKey(ekBytes[:i]); err == nil {
			t.Errorf("expected error for ek length %d", i)
		}
	}
	ekLong := ekBytes
	for i := 0; i < 100; i++ {
		ekLong = append(ekLong, 0)
		if _, err := newEncapsulationKey(ekLong); err == nil {
			t.Errorf("expected error for ek length %d", len(ekLong))
		}
	}

	for i := 0; i < len(c)-1; i++ {
		if _, err := dk.Decapsulate(c[:i]); err == nil {
			t.Errorf("expected error for c length %d", i)
		}
	}
	cLong := c
	for i := 0; i < 100; i++ {
		cLong = append(cLong, 0)
		if _, err := dk.Decapsulate(cLong); err == nil {
			t.Errorf("expected error for c length %d", len(cLong))
		}
	}
}

func BenchmarkMLKEMKeyGen(b *testing.B) {
	if !cng.SupportsMLKEM() {
		b.Skip("ML-KEM not supported on this platform")
	}
	var d, z [32]byte
	rand.Read(d[:])
	rand.Read(z[:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dk, err := cng.GenerateKeyMLKEM768()
		if err != nil {
			b.Fatal(err)
		}
		sink ^= dk.EncapsulationKey().Bytes()[0]
	}
}

func BenchmarkMLKEMEncaps(b *testing.B) {
	if !cng.SupportsMLKEM() {
		b.Skip("ML-KEM not supported on this platform")
	}
	seed := make([]byte, cng.SeedSizeMLKEM)
	rand.Read(seed)
	var m [32]byte
	rand.Read(m[:])
	dk, err := cng.NewDecapsulationKeyMLKEM768(seed)
	if err != nil {
		b.Fatal(err)
	}
	ekBytes := dk.EncapsulationKey().Bytes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ek, err := cng.NewEncapsulationKeyMLKEM768(ekBytes)
		if err != nil {
			b.Fatal(err)
		}
		K, c := ek.Encapsulate()
		sink ^= c[0] ^ K[0]
	}
}

func BenchmarkMLKEMDecaps(b *testing.B) {
	if !cng.SupportsMLKEM() {
		b.Skip("ML-KEM not supported on this platform")
	}
	dk, err := cng.GenerateKeyMLKEM768()
	if err != nil {
		b.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	_, c := ek.Encapsulate()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		K, _ := dk.Decapsulate(c)
		sink ^= K[0]
	}
}

func BenchmarkMLKEMRoundTrip(b *testing.B) {
	if !cng.SupportsMLKEM() {
		b.Skip("ML-KEM not supported on this platform")
	}
	dk, err := cng.GenerateKeyMLKEM768()
	if err != nil {
		b.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	ekBytes := ek.Bytes()
	_, c := ek.Encapsulate()
	if err != nil {
		b.Fatal(err)
	}
	b.Run("Alice", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			dkS, err := cng.GenerateKeyMLKEM768()
			if err != nil {
				b.Fatal(err)
			}
			ekS := dkS.EncapsulationKey().Bytes()
			sink ^= ekS[0]

			Ks, err := dk.Decapsulate(c)
			if err != nil {
				b.Fatal(err)
			}
			sink ^= Ks[0]
		}
	})
	b.Run("Bob", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ek, err := cng.NewEncapsulationKeyMLKEM768(ekBytes)
			if err != nil {
				b.Fatal(err)
			}
			Ks, cS := ek.Encapsulate()
			if err != nil {
				b.Fatal(err)
			}
			sink ^= cS[0] ^ Ks[0]
		}
	})
}

// Test that the constants match the ML-KEM specification (NIST FIPS 203).
func TestMLKEMConstantSizes(t *testing.T) {
	t.Parallel()
	if cng.SharedKeySizeMLKEM != mlkem.SharedKeySize {
		t.Errorf("SharedKeySize mismatch: got %d, want %d", cng.SharedKeySizeMLKEM, mlkem.SharedKeySize)
	}

	if cng.SeedSizeMLKEM != mlkem.SeedSize {
		t.Errorf("SeedSize mismatch: got %d, want %d", cng.SeedSizeMLKEM, mlkem.SeedSize)
	}

	if cng.CiphertextSizeMLKEM768 != mlkem.CiphertextSize768 {
		t.Errorf("CiphertextSize768 mismatch: got %d, want %d", cng.CiphertextSizeMLKEM768, mlkem.CiphertextSize768)
	}

	if cng.EncapsulationKeySizeMLKEM768 != mlkem.EncapsulationKeySize768 {
		t.Errorf("EncapsulationKeySize768 mismatch: got %d, want %d", cng.EncapsulationKeySizeMLKEM768, mlkem.EncapsulationKeySize768)
	}

	if cng.CiphertextSizeMLKEM1024 != mlkem.CiphertextSize1024 {
		t.Errorf("CiphertextSize1024 mismatch: got %d, want %d", cng.CiphertextSizeMLKEM1024, mlkem.CiphertextSize1024)
	}

	if cng.EncapsulationKeySizeMLKEM1024 != mlkem.EncapsulationKeySize1024 {
		t.Errorf("EncapsulationKeySize1024 mismatch: got %d, want %d", cng.EncapsulationKeySizeMLKEM1024, mlkem.EncapsulationKeySize1024)
	}
}

// TestMLKEMInteropWithStdlib tests that CNG and stdlib implementations can interoperate.
func TestMLKEMInteropWithStdlib(t *testing.T) {
	if !cng.SupportsMLKEM() {
		t.Skip("ML-KEM not supported on this platform")
	}
	t.Parallel()

	t.Run("768_CNG_to_Stdlib", func(t *testing.T) {
		t.Parallel()
		// Generate key with CNG
		cngDK, err := cng.GenerateKeyMLKEM768()
		if err != nil {
			t.Fatal(err)
		}
		cngEK := cngDK.EncapsulationKey()

		// Import CNG encapsulation key into stdlib
		stdlibEK, err := mlkem.NewEncapsulationKey768(cngEK.Bytes())
		if err != nil {
			t.Fatal(err)
		}

		// Encapsulate with stdlib
		stdlibSharedKey, ciphertext := stdlibEK.Encapsulate()

		// Decapsulate with CNG
		cngSharedKey, err := cngDK.Decapsulate(ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		// Verify shared keys match
		if !bytes.Equal(stdlibSharedKey, cngSharedKey) {
			t.Error("shared keys don't match (CNG DK, stdlib EK)")
		}
	})

	t.Run("768_Stdlib_to_CNG", func(t *testing.T) {
		t.Parallel()
		// Generate key with stdlib
		stdlibDK, err := mlkem.GenerateKey768()
		if err != nil {
			t.Fatal(err)
		}
		stdlibEK := stdlibDK.EncapsulationKey()

		// Import stdlib encapsulation key into CNG
		cngEK, err := cng.NewEncapsulationKeyMLKEM768(stdlibEK.Bytes())
		if err != nil {
			t.Fatal(err)
		}

		// Encapsulate with CNG
		cngSharedKey, ciphertext := cngEK.Encapsulate()

		// Decapsulate with stdlib
		stdlibSharedKey, err := stdlibDK.Decapsulate(ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		// Verify shared keys match
		if !bytes.Equal(stdlibSharedKey, cngSharedKey) {
			t.Error("shared keys don't match (stdlib DK, CNG EK)")
		}
	})

	t.Run("768_Bidirectional", func(t *testing.T) {
		t.Parallel()
		// Generate keys with both implementations
		cngDK, err := cng.GenerateKeyMLKEM768()
		if err != nil {
			t.Fatal(err)
		}
		stdlibDK, err := mlkem.GenerateKey768()
		if err != nil {
			t.Fatal(err)
		}

		if len(cngDK.Bytes()) != len(stdlibDK.Bytes()) {
			t.Fatalf("decapsulation key sizes don't match: CNG=%d, stdlib=%d", len(cngDK.Bytes()), len(stdlibDK.Bytes()))
		}

		// Test CNG encapsulation key -> stdlib
		cngEKBytes := cngDK.EncapsulationKey().Bytes()
		stdlibEK, err := mlkem.NewEncapsulationKey768(cngEKBytes)
		if err != nil {
			t.Fatalf("failed to import CNG encapsulation key into stdlib: %v", err)
		}
		if !bytes.Equal(cngEKBytes, stdlibEK.Bytes()) {
			t.Error("encapsulation key bytes don't match after round-trip (CNG -> stdlib)")
		}

		// Test stdlib encapsulation key -> CNG
		stdlibEKBytes := stdlibDK.EncapsulationKey().Bytes()
		cngEK, err := cng.NewEncapsulationKeyMLKEM768(stdlibEKBytes)
		if err != nil {
			t.Fatalf("failed to import stdlib encapsulation key into CNG: %v", err)
		}
		if !bytes.Equal(stdlibEKBytes, cngEK.Bytes()) {
			t.Error("encapsulation key bytes don't match after round-trip (stdlib -> CNG)")
		}

		// Test cross-encryption/decryption
		sharedKey1, ct1 := stdlibEK.Encapsulate()
		sharedKey2, err := cngDK.Decapsulate(ct1)
		if err != nil {
			t.Fatalf("CNG failed to decapsulate stdlib ciphertext: %v", err)
		}
		if !bytes.Equal(sharedKey1, sharedKey2) {
			t.Error("shared keys don't match (stdlib encaps, CNG decaps)")
		}

		sharedKey3, ct2 := cngEK.Encapsulate()
		sharedKey4, err := stdlibDK.Decapsulate(ct2)
		if err != nil {
			t.Fatalf("stdlib failed to decapsulate CNG ciphertext: %v", err)
		}
		if !bytes.Equal(sharedKey3, sharedKey4) {
			t.Error("shared keys don't match (CNG encaps, stdlib decaps)")
		}
	})

	t.Run("1024_CNG_to_Stdlib", func(t *testing.T) {
		t.Parallel()
		// Generate key with CNG
		cngDK, err := cng.GenerateKeyMLKEM1024()
		if err != nil {
			t.Fatal(err)
		}
		cngEK := cngDK.EncapsulationKey()

		// Import CNG encapsulation key into stdlib
		stdlibEK, err := mlkem.NewEncapsulationKey1024(cngEK.Bytes())
		if err != nil {
			t.Fatal(err)
		}

		// Encapsulate with stdlib
		stdlibSharedKey, ciphertext := stdlibEK.Encapsulate()

		// Decapsulate with CNG
		cngSharedKey, err := cngDK.Decapsulate(ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		// Verify shared keys match
		if !bytes.Equal(stdlibSharedKey, cngSharedKey) {
			t.Error("shared keys don't match (CNG DK, stdlib EK)")
		}
	})

	t.Run("1024_Stdlib_to_CNG", func(t *testing.T) {
		t.Parallel()
		// Generate key with stdlib
		stdlibDK, err := mlkem.GenerateKey1024()
		if err != nil {
			t.Fatal(err)
		}
		stdlibEK := stdlibDK.EncapsulationKey()

		// Import stdlib encapsulation key into CNG
		cngEK, err := cng.NewEncapsulationKeyMLKEM1024(stdlibEK.Bytes())
		if err != nil {
			t.Fatal(err)
		}

		// Encapsulate with CNG
		cngSharedKey, ciphertext := cngEK.Encapsulate()

		// Decapsulate with stdlib
		stdlibSharedKey, err := stdlibDK.Decapsulate(ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		// Verify shared keys match
		if !bytes.Equal(stdlibSharedKey, cngSharedKey) {
			t.Error("shared keys don't match (stdlib DK, CNG EK)")
		}
	})

	t.Run("1024_Bidirectional", func(t *testing.T) {
		t.Parallel()
		// Generate keys with both implementations
		cngDK, err := cng.GenerateKeyMLKEM1024()
		if err != nil {
			t.Fatal(err)
		}
		stdlibDK, err := mlkem.GenerateKey1024()
		if err != nil {
			t.Fatal(err)
		}
		if len(cngDK.Bytes()) != len(stdlibDK.Bytes()) {
			t.Fatalf("decapsulation key sizes don't match: CNG=%d, stdlib=%d", len(cngDK.Bytes()), len(stdlibDK.Bytes()))
		}

		// Test CNG encapsulation key -> stdlib
		cngEKBytes := cngDK.EncapsulationKey().Bytes()
		stdlibEK, err := mlkem.NewEncapsulationKey1024(cngEKBytes)
		if err != nil {
			t.Fatalf("failed to import CNG encapsulation key into stdlib: %v", err)
		}
		if !bytes.Equal(cngEKBytes, stdlibEK.Bytes()) {
			t.Error("encapsulation key bytes don't match after round-trip (CNG -> stdlib)")
		}

		// Test stdlib encapsulation key -> CNG
		stdlibEKBytes := stdlibDK.EncapsulationKey().Bytes()
		cngEK, err := cng.NewEncapsulationKeyMLKEM1024(stdlibEKBytes)
		if err != nil {
			t.Fatalf("failed to import stdlib encapsulation key into CNG: %v", err)
		}
		if !bytes.Equal(stdlibEKBytes, cngEK.Bytes()) {
			t.Error("encapsulation key bytes don't match after round-trip (stdlib -> CNG)")
		}

		// Test cross-encryption/decryption
		sharedKey1, ct1 := stdlibEK.Encapsulate()
		sharedKey2, err := cngDK.Decapsulate(ct1)
		if err != nil {
			t.Fatalf("CNG failed to decapsulate stdlib ciphertext: %v", err)
		}
		if !bytes.Equal(sharedKey1, sharedKey2) {
			t.Error("shared keys don't match (stdlib encaps, CNG decaps)")
		}

		sharedKey3, ct2 := cngEK.Encapsulate()
		sharedKey4, err := stdlibDK.Decapsulate(ct2)
		if err != nil {
			t.Fatalf("stdlib failed to decapsulate CNG ciphertext: %v", err)
		}
		if !bytes.Equal(sharedKey3, sharedKey4) {
			t.Error("shared keys don't match (CNG encaps, stdlib decaps)")
		}
	})
}
