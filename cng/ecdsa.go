// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"encoding/asn1"
	"errors"
	"math/big"
	"runtime"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

var errUnknownCurve = errors.New("openssl: unknown elliptic curve")
var errUnsupportedCurve = errors.New("openssl: unsupported elliptic curve")

type ecdsaAlgorithm struct {
	h    bcrypt.ALG_HANDLE
	size uint32
}

func loadEcdsa(id string) (h ecdsaAlgorithm, err error) {
	if v, ok := algCache.Load(id); ok {
		return v.(ecdsaAlgorithm), nil
	}
	err = bcrypt.OpenAlgorithmProvider(&h.h, utf16PtrFromString(id), nil, bcrypt.ALG_NONE_FLAG)
	if err != nil {
		return
	}
	algCache.Store(id, h)
	return
}

const sizeOfECCBlobHeader = uint32(unsafe.Sizeof(bcrypt.ECCKEY_BLOB{}))

func GenerateKeyECDSA(curve string) (X, Y, D *big.Int, err error) {
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
	err = bcrypt.GenerateKeyPair(h.h, &hkey, bits, 0)
	if err != nil {
		return
	}
	defer bcrypt.DestroyKey(hkey)
	// The key cannot be used until BcryptFinalizeKeyPair has been called.
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
		panic("crypto/ecdsa: exported key is corrupted")
	}
	data := blob[sizeOfECCBlobHeader:]
	newInt := func(size uint32) *big.Int {
		b := new(big.Int).SetBytes(data[:size])
		data = data[size:]
		return b
	}
	X = newInt(hdr.KeySize)
	Y = newInt(hdr.KeySize)
	D = newInt(hdr.KeySize)
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

func NewPublicKeyECDSA(curve string, X, Y *big.Int) (*PublicKeyECDSA, error) {
	id, bits, err := curveToID(curve)
	if err != nil {
		return nil, err
	}
	h, err := loadEcdsa(id)
	if err != nil {
		return nil, err
	}
	blob := encodeECDSAKey(id, bits, X, Y, nil)
	k := new(PublicKeyECDSA)
	err = bcrypt.ImportKeyPair(h.h, 0, utf16PtrFromString(bcrypt.ECCPUBLIC_BLOB), &k.pkey, blob, 0)
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

func NewPrivateKeyECDSA(curve string, X, Y, D *big.Int) (*PrivateKeyECDSA, error) {
	id, bits, err := curveToID(curve)
	if err != nil {
		return nil, err
	}
	h, err := loadEcdsa(id)
	if err != nil {
		return nil, err
	}
	blob := encodeECDSAKey(id, bits, X, Y, D)
	k := new(PrivateKeyECDSA)
	err = bcrypt.ImportKeyPair(h.h, 0, utf16PtrFromString(bcrypt.ECCPRIVATE_BLOB), &k.pkey, blob, 0)
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

func encodeECDSAKey(id string, bits uint32, X, Y, D *big.Int) []byte {
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
	var blob []byte
	if D == nil {
		blob = make([]byte, sizeOfECCBlobHeader+hdr.KeySize*2)
	} else {
		blob = make([]byte, sizeOfECCBlobHeader+hdr.KeySize*3)
	}
	copy(blob[:sizeOfECCBlobHeader], (*(*[1<<31 - 1]byte)(unsafe.Pointer(&hdr)))[:sizeOfECCBlobHeader])
	data := blob[sizeOfECCBlobHeader:]
	encode := func(b *big.Int, size uint32) {
		b.FillBytes(data[:size])
		data = data[size:]
	}
	encode(X, hdr.KeySize)
	encode(Y, hdr.KeySize)
	if D != nil {
		encode(D, hdr.KeySize)
	}
	return blob
}

type ecdsaSignature struct {
	R, S *big.Int
}

func SignECDSA(priv *PrivateKeyECDSA, hash []byte) (r, s *big.Int, err error) {
	sig, err := keySign(priv.pkey, nil, hash, bcrypt.PAD_UNDEFINED)
	if err != nil {
		return nil, nil, err
	}
	// BCRYPTSignHash generates ECDSA signatures in P1363 format,
	// which is simply (r, s), each of them exactly half of the array.
	if len(sig) != priv.size*2 {
		return nil, nil, errors.New("crypto/ecdsa: invalid signature size")
	}
	r = new(big.Int).SetBytes(sig[:priv.size])
	s = new(big.Int).SetBytes(sig[priv.size:])
	return
}

func SignMarshalECDSA(priv *PrivateKeyECDSA, hash []byte) ([]byte, error) {
	r, s, err := SignECDSA(priv, hash)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ecdsaSignature{r, s})
}

func VerifyECDSA(pub *PublicKeyECDSA, hash []byte, r, s *big.Int) bool {
	sig := make([]byte, pub.size*2)
	r.FillBytes(sig[:pub.size])
	s.FillBytes(sig[pub.size:])
	defer runtime.KeepAlive(pub)
	return keyVerify(pub.pkey, nil, hash, sig, bcrypt.PAD_UNDEFINED) == nil
}
