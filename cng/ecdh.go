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

var errInvalidPublicKey = errors.New("cng: invalid public key")
var errInvalidPrivateKey = errors.New("cng: invalid private key")

type ecdhAlgorithm struct {
	handle bcrypt.ALG_HANDLE
}

func loadEcdh(id string) (h ecdhAlgorithm, err error) {
	v, err := loadOrStoreAlg(id, bcrypt.ALG_NONE_FLAG, "", func(h bcrypt.ALG_HANDLE) (interface{}, error) {
		return ecdhAlgorithm{h}, nil
	})
	if err != nil {
		return ecdhAlgorithm{}, err
	}
	return v.(ecdhAlgorithm), nil
}

type PublicKeyECDH struct {
	hkey  bcrypt.KEY_HANDLE
	size  int
	bytes []byte
}

func (k *PublicKeyECDH) finalize() {
	bcrypt.DestroyKey(k.hkey)
}

type PrivateKeyECDH struct {
	hkey bcrypt.KEY_HANDLE
	size int
}

func (k *PrivateKeyECDH) finalize() {
	bcrypt.DestroyKey(k.hkey)
}

func ECDH(priv *PrivateKeyECDH, pub *PublicKeyECDH) ([]byte, error) {
	// First establish the shared secret.
	var secret bcrypt.SECRET_HANDLE
	err := bcrypt.SecretAgreement(priv.hkey, pub.hkey, &secret, 0)
	if err != nil {
		return nil, err
	}
	defer bcrypt.DestroySecret(secret)

	// Then we need to export the raw shared secret from the secret opaque handler.
	// The only way to do it is using BCryptDeriveKey with BCRYPT_KDF_RAW_SECRET as key derivation function (KDF).
	// Unfortunately, this KDF is supported starting from Windows 10.
	var size uint32
	err = bcrypt.DeriveKey(secret, utf16PtrFromString(bcrypt.KDF_RAW_SECRET), nil, nil, &size, 0)
	if err != nil {
		return nil, err
	}
	agreedSecret := make([]byte, size)
	err = bcrypt.DeriveKey(secret, utf16PtrFromString(bcrypt.KDF_RAW_SECRET), nil, agreedSecret, &size, 0)
	if err != nil {
		return nil, err
	}

	// The raw shared secret is little-endian but Go expects big-endian.
	// Reverse the slice in-place.
	inputMid := size / 2
	for i := uint32(0); i < inputMid; i++ {
		j := size - i - 1
		agreedSecret[i], agreedSecret[j] = agreedSecret[j], agreedSecret[i]
	}
	runtime.KeepAlive(priv)
	runtime.KeepAlive(pub)
	return agreedSecret, nil
}

func GenerateKeyECDH(curve string) (*PrivateKeyECDH, []byte, error) {
	id, bits, err := curveToEcdhID(curve)
	if err != nil {
		return nil, nil, err
	}
	h, err := loadEcdh(id)
	if err != nil {
		return nil, nil, err
	}
	var hkey bcrypt.KEY_HANDLE
	err = bcrypt.GenerateKeyPair(h.handle, &hkey, bits, 0)
	if err != nil {
		return nil, nil, err
	}
	// The key cannot be used until BCryptFinalizeKeyPair has been called.
	err = bcrypt.FinalizeKeyPair(hkey, 0)
	if err != nil {
		return nil, nil, err
	}
	var size uint32
	err = bcrypt.ExportKey(hkey, 0, utf16PtrFromString(bcrypt.ECCPUBLIC_BLOB), nil, &size, 0)
	if err != nil {
		return nil, nil, err
	}
	blob := make([]byte, size)
	err = bcrypt.ExportKey(hkey, 0, utf16PtrFromString(bcrypt.ECCPUBLIC_BLOB), blob, &size, 0)
	if err != nil {
		return nil, nil, err
	}
	hdr := (*(*bcrypt.ECCKEY_BLOB)(unsafe.Pointer(&blob[0])))
	if hdr.KeySize != (bits+7)/8 {
		err = errors.New("cng: exported key is corrupted")
		return nil, nil, err
	}
	k := new(PrivateKeyECDH)
	k.size = int(hdr.KeySize)
	k.hkey = hkey
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	bytes := append([]byte{4}, blob[sizeOfECCBlobHeader:]...)
	return k, bytes, nil
}

func NewPrivateKeyECDH(curve string, key []byte) (*PrivateKeyECDH, error) {
	id, bits, err := curveToEcdhID(curve)
	if err != nil {
		return nil, err
	}
	h, err := loadEcdh(id)
	if err != nil {
		return nil, err
	}
	keySize := int(bits+7) / 8
	if len(key) != keySize {
		return nil, errInvalidPrivateKey
	}
	// zero has enough size to fit P-521 curves
	var zero [66]byte
	blob, err := encodeECCKey(id, bits, zero[:keySize], zero[:keySize], key[:keySize])
	if err != nil {
		return nil, err
	}
	k := new(PrivateKeyECDH)
	err = bcrypt.ImportKeyPair(h.handle, 0, utf16PtrFromString(bcrypt.ECCPRIVATE_BLOB), &k.hkey, blob, 0)
	if err != nil {
		return nil, err
	}
	k.size = (int(bits) + 7) / 8
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, nil
}

func NewPublicKeyECDH(curve string, bytes []byte) (*PublicKeyECDH, error) {
	// Reject the point at infinity and compressed encodings.
	// The first byte is always the key encoding.
	if len(bytes) == 0 || bytes[0] != 4 {
		return nil, errInvalidPublicKey
	}
	// Remove the encoding byte, BCrypt doesn't want it
	// and it only support uncompressed points anyway.
	keyWithoutEncoding := bytes[1:]
	id, bits, err := curveToEcdhID(curve)
	if err != nil {
		return nil, err
	}
	h, err := loadEcdh(id)
	if err != nil {
		return nil, err
	}
	keySize := int(bits+7) / 8
	if len(keyWithoutEncoding) != keySize*2 {
		return nil, errInvalidPublicKey
	}
	blob, err := encodeECCKey(id, bits, keyWithoutEncoding[:keySize], keyWithoutEncoding[keySize:], nil)
	if err != nil {
		return nil, err
	}
	k := new(PublicKeyECDH)
	err = bcrypt.ImportKeyPair(h.handle, 0, utf16PtrFromString(bcrypt.ECCPUBLIC_BLOB), &k.hkey, blob, 0)
	if err != nil {
		return nil, err
	}
	k.size = keySize
	k.bytes = append([]byte(nil), bytes...)
	runtime.SetFinalizer(k, (*PublicKeyECDH).finalize)
	return k, nil
}

func (k *PublicKeyECDH) Bytes() []byte { return k.bytes }

func (k *PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error) {
	defer runtime.KeepAlive(k)
	var size uint32
	err := bcrypt.ExportKey(k.hkey, 0, utf16PtrFromString(bcrypt.ECCPUBLIC_BLOB), nil, &size, 0)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, size)
	err = bcrypt.ExportKey(k.hkey, 0, utf16PtrFromString(bcrypt.ECCPUBLIC_BLOB), blob, &size, 0)
	if err != nil {
		return nil, err
	}
	hdr := (*(*bcrypt.ECCKEY_BLOB)(unsafe.Pointer(&blob[0])))
	if int(hdr.KeySize) != k.size {
		return nil, errors.New("crypto/ecdsa: exported key is corrupted")
	}
	data := blob[sizeOfECCBlobHeader:]
	consumeBigInt := func(size uint32) BigInt {
		b := data[:size]
		data = data[size:]
		return b
	}
	X := consumeBigInt(hdr.KeySize)
	Y := consumeBigInt(hdr.KeySize)
	pub := new(PublicKeyECDH)
	pub.size = int(hdr.KeySize)
	pub.bytes = append([]byte{4}, X...)
	pub.bytes = append(pub.bytes, Y...)
	runtime.SetFinalizer(pub, (*PublicKeyECDH).finalize)
	return pub, nil

}

func curveToEcdhID(curve string) (string, uint32, error) {
	switch curve {
	case "P-224":
		return "", 0, errUnsupportedCurve
	case "P-256":
		return bcrypt.ECDH_P256_ALGORITHM, 256, nil
	case "P-384":
		return bcrypt.ECDH_P384_ALGORITHM, 384, nil
	case "P-521":
		return bcrypt.ECDH_P521_ALGORITHM, 521, nil
	}
	return "", 0, errUnknownCurve
}
