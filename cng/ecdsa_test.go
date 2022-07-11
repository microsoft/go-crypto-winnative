// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"

	"github.com/microsoft/go-crypto-winnative/cng"
	"github.com/microsoft/go-crypto-winnative/cng/bbig"
)

func testAllCurves(t *testing.T, f func(*testing.T, elliptic.Curve)) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	}
	for _, test := range tests {
		curve := test.curve
		t.Run(test.name, func(t *testing.T) {
			f(t, curve)
		})
	}
}

func TestECDSAKeyGeneration(t *testing.T) {
	testAllCurves(t, testECDSAKeyGeneration)
}

func testECDSAKeyGeneration(t *testing.T, c elliptic.Curve) {
	priv, err := generateKeycurve(c)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Error("public key invalid: not on curve")
	}
}

func TestECDSASignAndVerify(t *testing.T) {
	testAllCurves(t, testECDSASignAndVerify)
}

func testECDSASignAndVerify(t *testing.T, c elliptic.Curve) {
	key, err := generateKeycurve(c)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := cng.NewPrivateKeyECDSA(key.Params().Name, bbig.Enc(key.X), bbig.Enc(key.Y), bbig.Enc(key.D))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := cng.NewPublicKeyECDSA(key.Params().Name, bbig.Enc(key.X), bbig.Enc(key.Y))
	if err != nil {
		t.Fatal(err)
	}
	hashed := []byte("testing")
	r, s, err := cng.SignECDSA(priv, hashed)
	if err != nil {
		t.Fatalf("SignECDSA error: %s", err)
	}
	if !cng.VerifyECDSA(pub, hashed, r, s) {
		t.Errorf("Verify failed")
	}
	hashed[0] ^= 0xff
	if cng.VerifyECDSA(pub, hashed, r, s) {
		t.Errorf("Verify succeeded despite intentionally invalid hash!")
	}
}

func generateKeycurve(c elliptic.Curve) (*ecdsa.PrivateKey, error) {
	x, y, d, err := cng.GenerateKeyECDSA(c.Params().Name)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: bbig.Dec(x), Y: bbig.Dec(y)}, D: bbig.Dec(d)}, nil
}

func BenchmarkSignECDSA(b *testing.B) {
	name := "P-256"
	x, y, d, err := cng.GenerateKeyECDSA(name)
	if err != nil {
		b.Fatal(err)
	}
	priv, err := cng.NewPrivateKeyECDSA(name, x, y, d)
	if err != nil {
		b.Fatal(err)
	}
	hashed := []byte("testing")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := cng.SignECDSA(priv, hashed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyECDSA(b *testing.B) {
	name := "P-256"
	x, y, d, err := cng.GenerateKeyECDSA(name)
	if err != nil {
		b.Fatal(err)
	}
	pub, err := cng.NewPublicKeyECDSA(name, x, y)
	if err != nil {
		b.Fatal(err)
	}
	priv, err := cng.NewPrivateKeyECDSA(name, x, y, d)
	if err != nil {
		b.Fatal(err)
	}
	hashed := []byte("testing")
	r, s, err := cng.SignECDSA(priv, hashed)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok := cng.VerifyECDSA(pub, hashed, r, s)
		if !ok {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkGenerateKeyECDSA(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _, err := cng.GenerateKeyECDSA("P-256")
		if err != nil {
			b.Fatal(err)
		}
	}
}
