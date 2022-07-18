// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng_test

import (
	"bytes"
	"crypto"
	"math/big"
	"strconv"
	"testing"

	"github.com/microsoft/go-crypto-winnative/cng"
	"github.com/microsoft/go-crypto-winnative/cng/bbig"
)

func newRSAKey(t *testing.T, size int) (*cng.PrivateKeyRSA, *cng.PublicKeyRSA) {
	t.Helper()
	N, E, D, P, Q, Dp, Dq, Qinv, err := cng.GenerateKeyRSA(size)
	if err != nil {
		t.Fatalf("GenerateKeyRSA(%d): %v", size, err)
	}
	priv, err := cng.NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv)
	if err != nil {
		t.Fatalf("NewPrivateKeyRSA(%d): %v", size, err)
	}
	pub, err := cng.NewPublicKeyRSA(N, E)
	if err != nil {
		t.Fatalf("NewPublicKeyRSA(%d): %v", size, err)
	}
	return priv, pub
}

func TestGenerateKeyRSA_InvalidLength(t *testing.T) {
	_, _, _, _, _, _, _, _, err := cng.GenerateKeyRSA(2)
	if err == nil {
		t.Error("error expected")
	}
}

func TestRSAKeyGeneration(t *testing.T) {
	for _, size := range []int{2048, 3072} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			priv, pub := newRSAKey(t, size)
			msg := []byte("hi!")
			enc, err := cng.EncryptRSAPKCS1(pub, msg)
			if err != nil {
				t.Fatalf("EncryptPKCS1v15: %v", err)
			}
			dec, err := cng.DecryptRSAPKCS1(priv, enc)
			if err != nil {
				t.Fatalf("DecryptPKCS1v15: %v", err)
			}
			if !bytes.Equal(dec, msg) {
				t.Fatalf("got:%x want:%x", dec, msg)
			}
		})
	}
}

func TestEncryptDecryptOAEP(t *testing.T) {
	sha256 := cng.NewSHA256()
	msg := []byte("hi!")
	label := []byte("ho!")
	priv, pub := newRSAKey(t, 2048)
	enc, err := cng.EncryptRSAOAEP(sha256, pub, msg, label)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := cng.DecryptRSAOAEP(sha256, priv, enc, label)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, msg) {
		t.Errorf("got:%x want:%x", dec, msg)
	}
}

func TestEncryptDecryptOAEP_WrongLabel(t *testing.T) {
	sha256 := cng.NewSHA256()
	msg := []byte("hi!")
	priv, pub := newRSAKey(t, 2048)
	enc, err := cng.EncryptRSAOAEP(sha256, pub, msg, []byte("ho!"))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := cng.DecryptRSAOAEP(sha256, priv, enc, []byte("wrong!"))
	if err == nil {
		t.Errorf("error expected")
	}
	if dec != nil {
		t.Errorf("got:%x want: nil", dec)
	}
}

func TestEncryptDecryptNoPadding(t *testing.T) {
	const bits = 2048
	var msg [bits / 8]byte
	msg[0] = 1
	msg[255] = 1
	priv, pub := newRSAKey(t, bits)
	enc, err := cng.EncryptRSANoPadding(pub, msg[:])
	if err != nil {
		t.Fatal(err)
	}
	dec, err := cng.DecryptRSANoPadding(priv, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, msg[:]) {
		t.Errorf("got:%x want:%x", dec, msg)
	}
}

func TestSignVerifyPKCS1v15(t *testing.T) {
	sha256 := cng.NewSHA256()
	priv, pub := newRSAKey(t, 2048)
	sha256.Write([]byte("hi!"))
	hashed := sha256.Sum(nil)
	signed, err := cng.SignRSAPKCS1v15(priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatal(err)
	}
	err = cng.VerifyRSAPKCS1v15(pub, crypto.SHA256, hashed, signed)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyPKCS1v15_Unhashed(t *testing.T) {
	msg := []byte("hi!")
	priv, pub := newRSAKey(t, 2048)
	signed, err := cng.SignRSAPKCS1v15(priv, 0, msg)
	if err != nil {
		t.Fatal(err)
	}
	err = cng.VerifyRSAPKCS1v15(pub, 0, msg, signed)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyPKCS1v15_Invalid(t *testing.T) {
	sha256 := cng.NewSHA256()
	msg := []byte("hi!")
	priv, pub := newRSAKey(t, 2048)
	sha256.Write(msg)
	hashed := sha256.Sum(nil)
	signed, err := cng.SignRSAPKCS1v15(priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatal(err)
	}
	err = cng.VerifyRSAPKCS1v15(pub, crypto.SHA256, msg, signed)
	if err == nil {
		t.Fatal("error expected")
	}
}

func TestSignVerifyRSAPSS(t *testing.T) {
	sha256 := cng.NewSHA256()
	priv, pub := newRSAKey(t, 2048)
	sha256.Write([]byte("testing"))
	hashed := sha256.Sum(nil)
	signed, err := cng.SignRSAPSS(priv, crypto.SHA256, hashed, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = cng.VerifyRSAPSS(pub, crypto.SHA256, hashed, signed, 0)
	if err != nil {
		t.Fatal(err)
	}
}

func fromBase36(base36 string) *big.Int {
	i, ok := new(big.Int).SetString(base36, 36)
	if !ok {
		panic("bad number: " + base36)
	}
	return i
}

func BenchmarkEncryptRSAPKCS1(b *testing.B) {
	b.StopTimer()
	// Public key length should be at least of 2048 bits, else OpenSSL will report an error when running in FIPS mode.
	n := fromBase36("14314132931241006650998084889274020608918049032671858325988396851334124245188214251956198731333464217832226406088020736932173064754214329009979944037640912127943488972644697423190955557435910767690712778463524983667852819010259499695177313115447116110358524558307947613422897787329221478860907963827160223559690523660574329011927531289655711860504630573766609239332569210831325633840174683944553667352219670930408593321661375473885147973879086994006440025257225431977751512374815915392249179976902953721486040787792801849818254465486633791826766873076617116727073077821584676715609985777563958286637185868165868520557")
	test2048PubKey, err := cng.NewPublicKeyRSA(bbig.Enc(n), bbig.Enc(big.NewInt(3)))
	if err != nil {
		b.Fatal(err)
	}
	b.StartTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := cng.EncryptRSAPKCS1(test2048PubKey, []byte("testing")); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateKeyRSA(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _, _, _, _, _, _, err := cng.GenerateKeyRSA(2048)
		if err != nil {
			b.Fatal(err)
		}
	}
}
