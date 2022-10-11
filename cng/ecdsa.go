// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"errors"
	"runtime"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

var errUnknownCurve = errors.New("cng: unknown elliptic curve")

type ecdsaAlgorithm struct {
	handle bcrypt.ALG_HANDLE
}

func loadECDSA(curve string) (h ecdsaAlgorithm, bits uint32, err error) {
	var id string
	switch curve {
	case "P-224":
		id, bits = bcrypt.ECC_CURVE_NISTP224, 224
	case "P-256":
		id, bits = bcrypt.ECC_CURVE_NISTP256, 256
	case "P-384":
		id, bits = bcrypt.ECC_CURVE_NISTP384, 384
	case "P-521":
		id, bits = bcrypt.ECC_CURVE_NISTP521, 521
	default:
		err = errUnknownCurve
	}
	if err != nil {
		return
	}
	v, err := loadOrStoreAlg(bcrypt.ECDSA_ALGORITHM, bcrypt.ALG_NONE_FLAG, id, func(h bcrypt.ALG_HANDLE) (interface{}, error) {
		err := setString(bcrypt.HANDLE(h), bcrypt.ECC_CURVE_NAME, id)
		if err != nil {
			return nil, err
		}
		return ecdsaAlgorithm{h}, nil
	})
	if err != nil {
		return ecdsaAlgorithm{}, 0, err
	}
	return v.(ecdsaAlgorithm), bits, nil
}

func GenerateKeyECDSA(curve string) (X, Y, D BigInt, err error) {
	var h ecdsaAlgorithm
	var bits uint32
	h, bits, err = loadECDSA(curve)
	if err != nil {
		return
	}
	var hkey bcrypt.KEY_HANDLE
	err = bcrypt.GenerateKeyPair(h.handle, &hkey, bits, 0)
	if err != nil {
		return
	}
	defer bcrypt.DestroyKey(hkey)
	// The key cannot be used until BCryptFinalizeKeyPair has been called.
	err = bcrypt.FinalizeKeyPair(hkey, 0)
	if err != nil {
		return
	}
	hdr, data, err := exportECCKey(hkey, true)
	if err != nil {
		return
	}
	consumeBigInt := func(size uint32) BigInt {
		b := data[:size]
		data = data[size:]
		return b
	}
	X = consumeBigInt(hdr.KeySize)
	Y = consumeBigInt(hdr.KeySize)
	D = consumeBigInt(hdr.KeySize)
	return
}

type PublicKeyECDSA struct {
	hkey bcrypt.KEY_HANDLE
}

func NewPublicKeyECDSA(curve string, X, Y BigInt) (*PublicKeyECDSA, error) {
	h, bits, err := loadECDSA(curve)
	if err != nil {
		return nil, err
	}
	hkey, err := importECCKey(h.handle, bcrypt.ECDSA_ALGORITHM, bits, X, Y, nil)
	if err != nil {
		return nil, err
	}
	k := &PublicKeyECDSA{hkey}
	runtime.SetFinalizer(k, (*PublicKeyECDSA).finalize)
	return k, nil
}

func (k *PublicKeyECDSA) finalize() {
	bcrypt.DestroyKey(k.hkey)
}

type PrivateKeyECDSA struct {
	hkey bcrypt.KEY_HANDLE
}

func NewPrivateKeyECDSA(curve string, X, Y, D BigInt) (*PrivateKeyECDSA, error) {
	h, bits, err := loadECDSA(curve)
	if err != nil {
		return nil, err
	}
	hkey, err := importECCKey(h.handle, bcrypt.ECDSA_ALGORITHM, bits, X, Y, D)
	if err != nil {
		return nil, err
	}
	k := &PrivateKeyECDSA{hkey}
	runtime.SetFinalizer(k, (*PrivateKeyECDSA).finalize)
	return k, nil
}

func (k *PrivateKeyECDSA) finalize() {
	bcrypt.DestroyKey(k.hkey)
}

// SignECDSA signs a hash (which should be the result of hashing a larger message),
// using the private key, priv.
//
// We provide this function instead of a boring.SignMarshalECDSA equivalent
// because BCryptSignHash returns the signature encoded using P1363 instead of ASN.1,
// so we would have to transform P1363 to ASN.1 using encoding/asn1, which we can't import here,
// only to be decoded into raw big.Int by the caller.
func SignECDSA(priv *PrivateKeyECDSA, hash []byte) (r, s BigInt, err error) {
	defer runtime.KeepAlive(priv)
	sig, err := keySign(priv.hkey, nil, hash, bcrypt.PAD_UNDEFINED)
	if err != nil {
		return nil, nil, err
	}
	// BCRYPTSignHash generates ECDSA signatures in P1363 format,
	// which is simply (r, s), each of them exactly half of the array.
	if len(sig)%2 != 0 {
		return nil, nil, errors.New("crypto/ecdsa: invalid signature size from bcrypt")
	}
	return sig[:len(sig)/2], sig[len(sig)/2:], nil
}

// VerifyECDSA verifies the signature in r, s of hash using the public key, pub.
func VerifyECDSA(pub *PublicKeyECDSA, hash []byte, r, s BigInt) bool {
	defer runtime.KeepAlive(pub)
	sizeBits, err := getUint32(bcrypt.HANDLE(pub.hkey), bcrypt.KEY_LENGTH)
	if err != nil {
		return false
	}
	size := int(sizeBits+7) / 8
	// r and s might be shorter than size
	// if the original big number contained leading zeros,
	// but they must not be longer than the public key size.
	if len(r) > size || len(s) > size {
		return false
	}
	sig := make([]byte, 0, size*2)
	prependZeros := func(nonZeroBytes int) {
		if zeros := size - nonZeroBytes; zeros > 0 {
			sig = append(sig, make([]byte, zeros)...)
		}
	}
	prependZeros(len(r))
	sig = append(sig, r...)
	prependZeros(len(s))
	sig = append(sig, s...)
	return keyVerify(pub.hkey, nil, hash, sig, bcrypt.PAD_UNDEFINED) == nil
}
