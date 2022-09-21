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

const ecdhUncompressedPrefix = 4

var errInvalidPublicKey = errors.New("cng: invalid public key")
var errInvalidPrivateKey = errors.New("cng: invalid private key")

type ecdhAlgorithm struct {
	handle bcrypt.ALG_HANDLE
}

func loadEcdh(curve string) (h ecdhAlgorithm, bits uint32, err error) {
	var id string
	switch curve {
	case "P-224", "X25519":
		err = errUnsupportedCurve
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
	v, err := loadOrStoreAlg(bcrypt.ECDH_ALGORITHM, bcrypt.ALG_NONE_FLAG, id, func(h bcrypt.ALG_HANDLE) (interface{}, error) {
		err := setString(bcrypt.HANDLE(h), bcrypt.ECC_CURVE_NAME, id)
		if err != nil {
			return nil, err
		}
		return ecdhAlgorithm{h}, nil
	})
	if err != nil {
		return ecdhAlgorithm{}, 0, err
	}
	return v.(ecdhAlgorithm), bits, nil
}

type PublicKeyECDH struct {
	hkey  bcrypt.KEY_HANDLE
	bytes []byte
}

func (k *PublicKeyECDH) finalize() {
	bcrypt.DestroyKey(k.hkey)
}

type PrivateKeyECDH struct {
	hkey bcrypt.KEY_HANDLE
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
	kdf := utf16PtrFromString(bcrypt.KDF_RAW_SECRET)
	var size uint32
	err = bcrypt.DeriveKey(secret, kdf, nil, nil, &size, 0)
	if err != nil {
		return nil, err
	}
	agreedSecret := make([]byte, size)
	err = bcrypt.DeriveKey(secret, kdf, nil, agreedSecret, &size, 0)
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
	h, bits, err := loadEcdh(curve)
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
		bcrypt.DestroyKey(hkey)
		return nil, nil, err
	}

	// GenerateKeyECDH returns the public key as as byte slice.
	// To get it we need to export the raw CNG key blob
	// and prepend the encoding prefix.
	_, blob, err := exportCCKey(hkey, false)
	if err != nil {
		bcrypt.DestroyKey(hkey)
		return nil, nil, err
	}
	k := new(PrivateKeyECDH)
	k.hkey = hkey
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	bytes := append([]byte{ecdhUncompressedPrefix}, blob...)
	return k, bytes, nil
}

func NewPrivateKeyECDH(curve string, key []byte) (*PrivateKeyECDH, error) {
	h, bits, err := loadEcdh(curve)
	if err != nil {
		return nil, err
	}
	keySize := int(bits+7) / 8
	if len(key) != keySize {
		return nil, errInvalidPrivateKey
	}
	// zero has enough size to fit P-521 curves.
	var zero [66]byte
	hkey, err := importECCKey(h.handle, bcrypt.ECDH_ALGORITHM, bits, zero[:keySize], zero[:keySize], key)
	if err != nil {
		return nil, err
	}
	k := new(PrivateKeyECDH)
	k.hkey = hkey
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, nil
}

func NewPublicKeyECDH(curve string, bytes []byte) (*PublicKeyECDH, error) {
	// Reject the point at infinity and compressed encodings.
	// The first byte is always the key encoding.
	if len(bytes) == 0 || bytes[0] != ecdhUncompressedPrefix {
		return nil, errInvalidPublicKey
	}
	h, bits, err := loadEcdh(curve)
	if err != nil {
		return nil, err
	}
	// Remove the encoding byte, BCrypt doesn't want it
	// and it only support uncompressed points anyway.
	keyWithoutEncoding := bytes[1:]
	keySize := int(bits+7) / 8
	if len(keyWithoutEncoding) != keySize*2 {
		return nil, errInvalidPublicKey
	}
	hkey, err := importECCKey(h.handle, bcrypt.ECDH_ALGORITHM, bits, keyWithoutEncoding[:keySize], keyWithoutEncoding[keySize:], nil)
	if err != nil {
		return nil, err
	}
	k := new(PublicKeyECDH)
	k.hkey = hkey
	k.bytes = append([]byte(nil), bytes...)
	runtime.SetFinalizer(k, (*PublicKeyECDH).finalize)
	return k, nil
}

func (k *PublicKeyECDH) Bytes() []byte { return k.bytes }

func (k *PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error) {
	defer runtime.KeepAlive(k)
	hdr, data, err := exportCCKey(k.hkey, false)
	if err != nil {
		return nil, err
	}
	consumeBigInt := func(size uint32) BigInt {
		b := data[:size]
		data = data[size:]
		return b
	}
	X := consumeBigInt(hdr.KeySize)
	Y := consumeBigInt(hdr.KeySize)
	pub := new(PublicKeyECDH)
	pub.bytes = append([]byte{ecdhUncompressedPrefix}, X...)
	pub.bytes = append(pub.bytes, Y...)
	runtime.SetFinalizer(pub, (*PublicKeyECDH).finalize)
	return pub, nil
}
