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
var errUnsupportedCurve = errors.New("cng: unsupported elliptic curve")

type ecdsaAlgorithm struct {
	handle bcrypt.ALG_HANDLE
	id     string
	bits   uint32
}

func loadEcdsa(curve string) (h ecdsaAlgorithm, err error) {
	var id string
	var bits uint32
	switch curve {
	case "P-224":
		err = errUnsupportedCurve
	case "P-256":
		id, bits = bcrypt.ECDSA_P256_ALGORITHM, 256
	case "P-384":
		id, bits = bcrypt.ECDSA_P384_ALGORITHM, 384
	case "P-521":
		id, bits = bcrypt.ECDSA_P521_ALGORITHM, 521
	default:
		err = errUnknownCurve
	}
	if err != nil {
		return
	}
	v, err := loadOrStoreAlg(id, bcrypt.ALG_NONE_FLAG, "", func(h bcrypt.ALG_HANDLE) (interface{}, error) {
		return ecdsaAlgorithm{h, id, bits}, nil
	})
	if err != nil {
		return ecdsaAlgorithm{}, err
	}
	return v.(ecdsaAlgorithm), nil
}

func GenerateKeyECDSA(curve string) (X, Y, D BigInt, err error) {
	var h ecdsaAlgorithm
	h, err = loadEcdsa(curve)
	if err != nil {
		return
	}
	var hkey bcrypt.KEY_HANDLE
	err = bcrypt.GenerateKeyPair(h.handle, &hkey, h.bits, 0)
	if err != nil {
		return
	}
	defer bcrypt.DestroyKey(hkey)
	// The key cannot be used until BCryptFinalizeKeyPair has been called.
	err = bcrypt.FinalizeKeyPair(hkey, 0)
	if err != nil {
		return
	}
	hdr, data, err := exportCCKey(hkey, true)
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
	size int
}

func NewPublicKeyECDSA(curve string, X, Y BigInt) (*PublicKeyECDSA, error) {
	h, err := loadEcdsa(curve)
	if err != nil {
		return nil, err
	}
	hkey, err := importECCKey(h.handle, h.id, h.bits, X, Y, nil)
	if err != nil {
		return nil, err
	}
	k := new(PublicKeyECDSA)
	k.hkey = hkey
	k.size = (int(h.bits) + 7) / 8
	runtime.SetFinalizer(k, (*PublicKeyECDSA).finalize)
	return k, nil
}

func (k *PublicKeyECDSA) finalize() {
	bcrypt.DestroyKey(k.hkey)
}

type PrivateKeyECDSA struct {
	hkey bcrypt.KEY_HANDLE
	size int
}

func NewPrivateKeyECDSA(curve string, X, Y, D BigInt) (*PrivateKeyECDSA, error) {
	h, err := loadEcdsa(curve)
	if err != nil {
		return nil, err
	}
	hkey, err := importECCKey(h.handle, h.id, h.bits, X, Y, D)
	if err != nil {
		return nil, err
	}
	k := new(PrivateKeyECDSA)
	k.hkey = hkey
	k.size = (int(h.bits) + 7) / 8
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
	sig, err := keySign(priv.hkey, nil, hash, bcrypt.PAD_UNDEFINED)
	if err != nil {
		return nil, nil, err
	}
	// BCRYPTSignHash generates ECDSA signatures in P1363 format,
	// which is simply (r, s), each of them exactly half of the array.
	if len(sig) != priv.size*2 {
		return nil, nil, errors.New("crypto/ecdsa: invalid signature size from bcrypt")
	}
	return sig[:priv.size], sig[priv.size:], nil
}

// VerifyECDSA verifies the signature in r, s of hash using the public key, pub.
func VerifyECDSA(pub *PublicKeyECDSA, hash []byte, r, s BigInt) bool {
	// r and s might be shorter than size
	// if the original big number contained leading zeros,
	// but they must not be longer than the public key size.
	if len(r) > pub.size || len(s) > pub.size {
		return false
	}
	sig := make([]byte, 0, pub.size*2)
	prependZeros := func(nonZeroBytes int) {
		if zeros := pub.size - nonZeroBytes; zeros > 0 {
			sig = append(sig, make([]byte, zeros)...)
		}
	}
	prependZeros(len(r))
	sig = append(sig, r...)
	prependZeros(len(s))
	sig = append(sig, s...)
	defer runtime.KeepAlive(pub)
	return keyVerify(pub.hkey, nil, hash, sig, bcrypt.PAD_UNDEFINED) == nil
}
