// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"errors"
	"runtime"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

var errUnknownCurve = errors.New("cng: unknown elliptic curve")
var errUnsupportedCurve = errors.New("cng: unsupported elliptic curve")

type ecdsaAlgorithm struct {
	handle bcrypt.ALG_HANDLE
}

func loadEcdsa(id string) (h ecdsaAlgorithm, err error) {
	v, err := loadOrStoreAlg(id, bcrypt.ALG_NONE_FLAG, "", func(h bcrypt.ALG_HANDLE) (interface{}, error) {
		return ecdsaAlgorithm{h}, nil
	})
	if err != nil {
		return ecdsaAlgorithm{}, err
	}
	return v.(ecdsaAlgorithm), nil
}

const sizeOfECCBlobHeader = uint32(unsafe.Sizeof(bcrypt.ECCKEY_BLOB{}))

func GenerateKeyECDSA(curve string) (X, Y, D BigInt, err error) {
	var id string
	var bits uint32
	id, bits, err = curveToID(curve)
	if err != nil {
		return
	}
	var h ecdsaAlgorithm
	h, err = loadEcdsa(id)
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
	var size uint32
	err = bcrypt.ExportKey(hkey, 0, utf16PtrFromString(bcrypt.ECCPRIVATE_BLOB), nil, &size, 0)
	if err != nil {
		return
	}
	blob := make([]byte, size)
	err = bcrypt.ExportKey(hkey, 0, utf16PtrFromString(bcrypt.ECCPRIVATE_BLOB), blob, &size, 0)
	if err != nil {
		return
	}
	hdr := (*(*bcrypt.ECCKEY_BLOB)(unsafe.Pointer(&blob[0])))
	if hdr.KeySize != (bits+7)/8 {
		err = errors.New("crypto/ecdsa: exported key is corrupted")
		return
	}
	data := blob[sizeOfECCBlobHeader:]
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

func curveToID(curve string) (string, uint32, error) {
	switch curve {
	case "P-224":
		return "", 0, errUnsupportedCurve
	case "P-256":
		return bcrypt.ECDSA_P256_ALGORITHM, 256, nil
	case "P-384":
		return bcrypt.ECDSA_P384_ALGORITHM, 384, nil
	case "P-521":
		return bcrypt.ECDSA_P521_ALGORITHM, 521, nil
	}
	return "", 0, errUnknownCurve
}

type PublicKeyECDSA struct {
	pkey bcrypt.KEY_HANDLE
	size int
}

func NewPublicKeyECDSA(curve string, X, Y BigInt) (*PublicKeyECDSA, error) {
	id, bits, err := curveToID(curve)
	if err != nil {
		return nil, err
	}
	h, err := loadEcdsa(id)
	if err != nil {
		return nil, err
	}
	blob, err := encodeECDSAKey(id, bits, X, Y, nil)
	if err != nil {
		return nil, err
	}
	k := new(PublicKeyECDSA)
	err = bcrypt.ImportKeyPair(h.handle, 0, utf16PtrFromString(bcrypt.ECCPUBLIC_BLOB), &k.pkey, blob, 0)
	if err != nil {
		return nil, err
	}
	k.size = (int(bits) + 7) / 8
	runtime.SetFinalizer(k, (*PublicKeyECDSA).finalize)
	return k, nil
}

func (k *PublicKeyECDSA) finalize() {
	bcrypt.DestroyKey(k.pkey)
}

type PrivateKeyECDSA struct {
	pkey bcrypt.KEY_HANDLE
	size int
}

func NewPrivateKeyECDSA(curve string, X, Y, D BigInt) (*PrivateKeyECDSA, error) {
	id, bits, err := curveToID(curve)
	if err != nil {
		return nil, err
	}
	h, err := loadEcdsa(id)
	if err != nil {
		return nil, err
	}
	blob, err := encodeECDSAKey(id, bits, X, Y, D)
	if err != nil {
		return nil, err
	}
	k := new(PrivateKeyECDSA)
	err = bcrypt.ImportKeyPair(h.handle, 0, utf16PtrFromString(bcrypt.ECCPRIVATE_BLOB), &k.pkey, blob, 0)
	if err != nil {
		return nil, err
	}
	k.size = (int(bits) + 7) / 8
	runtime.SetFinalizer(k, (*PrivateKeyECDSA).finalize)
	return k, nil
}

func (k *PrivateKeyECDSA) finalize() {
	bcrypt.DestroyKey(k.pkey)
}

func encodeECDSAKey(id string, bits uint32, X, Y, D BigInt) ([]byte, error) {
	var magic bcrypt.KeyBlobMagicNumber
	switch id {
	case bcrypt.ECDSA_P256_ALGORITHM:
		if D != nil {
			magic = bcrypt.ECDSA_PRIVATE_P256_MAGIC
		} else {
			magic = bcrypt.ECDSA_PUBLIC_P256_MAGIC
		}
	case bcrypt.ECDSA_P384_ALGORITHM:
		if D != nil {
			magic = bcrypt.ECDSA_PRIVATE_P384_MAGIC
		} else {
			magic = bcrypt.ECDSA_PUBLIC_P384_MAGIC
		}
	case bcrypt.ECDSA_P521_ALGORITHM:
		if D != nil {
			magic = bcrypt.ECDSA_PRIVATE_P521_MAGIC
		} else {
			magic = bcrypt.ECDSA_PUBLIC_P521_MAGIC
		}
	}
	hdr := bcrypt.ECCKEY_BLOB{
		Magic:   magic,
		KeySize: (bits + 7) / 8,
	}
	if len(X) > int(hdr.KeySize) || len(Y) > int(hdr.KeySize) || len(D) > int(hdr.KeySize) {
		return nil, errors.New("crypto/ecdsa: invalid parameters")
	}
	var blob []byte
	if D == nil {
		blob = make([]byte, sizeOfECCBlobHeader+hdr.KeySize*2)
	} else {
		blob = make([]byte, sizeOfECCBlobHeader+hdr.KeySize*3)
	}
	copy(blob, (*(*[sizeOfECCBlobHeader]byte)(unsafe.Pointer(&hdr)))[:])
	data := blob[sizeOfECCBlobHeader:]
	encode := func(b BigInt, size uint32) {
		// b might be shorter than size if the original big number contained leading zeros.
		leadingZeros := int(size) - len(b)
		copy(data[leadingZeros:], b)
		data = data[size:]
	}
	encode(X, hdr.KeySize)
	encode(Y, hdr.KeySize)
	if D != nil {
		encode(D, hdr.KeySize)
	}
	return blob, nil
}

// SignECDSA signs a hash (which should be the result of hashing a larger message),
// using the private key, priv.
//
// We provide this function instead of a boring.SignMarshalECDSA equivalent
// because BCryptSignHash returns the signature encoded using P1363 instead of ASN.1,
// so we would have to transform P1363 to ASN.1 using encoding/asn1, which we can't import here,
// only to be decoded into raw big.Int by the caller.
func SignECDSA(priv *PrivateKeyECDSA, hash []byte) (r, s BigInt, err error) {
	sig, err := keySign(priv.pkey, nil, hash, bcrypt.PAD_UNDEFINED)
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
	return keyVerify(pub.pkey, nil, hash, sig, bcrypt.PAD_UNDEFINED) == nil
}
