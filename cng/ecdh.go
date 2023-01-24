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

func loadECDH(curve string) (h ecdhAlgorithm, bits uint32, err error) {
	var id string
	switch curve {
	case "P-256":
		id, bits = bcrypt.ECC_CURVE_NISTP256, 256
	case "P-384":
		id, bits = bcrypt.ECC_CURVE_NISTP384, 384
	case "P-521":
		id, bits = bcrypt.ECC_CURVE_NISTP521, 521
	case "X25519":
		id, bits = bcrypt.ECC_CURVE_25519, 255
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

	// priv is only set when PublicKeyECDH is derived from a private key,
	// in which case priv's finalizer is responsible for freeing hkey.
	// This ensures priv is not finalized while the public key is alive,
	// which could cause use-after-free and double-free behavior.
	priv *PrivateKeyECDH
}

func (k *PublicKeyECDH) finalize() {
	if k.priv == nil {
		bcrypt.DestroyKey(k.hkey)
	}
}

type PrivateKeyECDH struct {
	hkey   bcrypt.KEY_HANDLE
	isNIST bool
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
	h, bits, err := loadECDH(curve)
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

	// GenerateKeyECDH returns the private key as a byte slice.
	// To get it we need to export the raw CNG key bytes.
	hdr, bytes, err := exportECCKey(hkey, true)
	if err != nil {
		bcrypt.DestroyKey(hkey)
		return nil, nil, err
	}
	// Only take the private component of the key,
	// which is the last of the three equally-sized chunks.
	bytes = bytes[hdr.KeySize*2:]

	k := &PrivateKeyECDH{hkey, isNIST(curve)}
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, bytes, nil
}

func NewPublicKeyECDH(curve string, bytes []byte) (*PublicKeyECDH, error) {
	// Reject the point at infinity and compressed encodings.
	// The first byte is always the key encoding.
	nist := isNIST(curve)
	if len(bytes) == 0 || (nist && bytes[0] != ecdhUncompressedPrefix) {
		return nil, errInvalidPublicKey
	}
	h, bits, err := loadECDH(curve)
	if err != nil {
		return nil, err
	}
	// Remove the encoding byte, if any. BCrypt doesn't want it
	// and it only support uncompressed points anyway.
	var keyWithoutEncoding []byte
	var ncomponents int
	if nist {
		ncomponents = 2
		keyWithoutEncoding = bytes[1:]
	} else {
		ncomponents = 1
		keyWithoutEncoding = bytes
	}
	keySize := int(bits+7) / 8
	if len(keyWithoutEncoding) != keySize*ncomponents {
		return nil, errInvalidPublicKey
	}
	hkey, err := importECCKey(h.handle, bcrypt.ECDH_ALGORITHM, bits, keyWithoutEncoding[:keySize], keyWithoutEncoding[keySize:], nil)
	if err != nil {
		return nil, err
	}
	k := &PublicKeyECDH{hkey, append([]byte(nil), bytes...), nil}
	runtime.SetFinalizer(k, (*PublicKeyECDH).finalize)
	return k, nil
}

func (k *PublicKeyECDH) Bytes() []byte { return k.bytes }

func NewPrivateKeyECDH(curve string, key []byte) (*PrivateKeyECDH, error) {
	h, bits, err := loadECDH(curve)
	if err != nil {
		return nil, err
	}
	keySize := int(bits+7) / 8
	if len(key) != keySize {
		return nil, errInvalidPrivateKey
	}
	nist := isNIST(curve)
	if !nist {
		key = convertX25519PrivKey(key)
	}
	// CNG allows to import private ECC keys without defining X/Y,
	// in which case those will be generated from D.
	// To trigger this behavior we pass a zeroed X/Y with keySize length.
	// zero is big enough to fit P-521 curves, the largest we handle, in the stack.
	var zero [(521 + 7) / 8]byte
	hkey, err := importECCKey(h.handle, bcrypt.ECDH_ALGORITHM, bits, zero[:keySize], zero[:keySize], key)
	if err != nil {
		return nil, err
	}
	k := &PrivateKeyECDH{hkey, nist}
	runtime.SetFinalizer(k, (*PrivateKeyECDH).finalize)
	return k, nil
}

func (k *PrivateKeyECDH) PublicKey() (*PublicKeyECDH, error) {
	defer runtime.KeepAlive(k)
	hdr, data, err := exportECCKey(k.hkey, false)
	if err != nil {
		return nil, err
	}
	var bytes []byte
	if k.isNIST {
		// Include X and Y.
		bytes = append([]byte{ecdhUncompressedPrefix}, data...)
	} else {
		// Only include X.
		bytes = data[:hdr.KeySize]
	}
	pub := &PublicKeyECDH{k.hkey, bytes, k}
	runtime.SetFinalizer(pub, (*PublicKeyECDH).finalize)
	return pub, nil
}

func isNIST(curve string) bool {
	return curve != "X25519"
}

func convertX25519PrivKey(key []byte) []byte {
	// CNG consume private X25519 keys using a slightly non-standard representation that don't affect the end result.
	// https://github.com/microsoft/SymCrypt/blob/e875f1f957dcb1308f8e712e9f4a8edc6f4f6207/inc/symcrypt.h#L4670
	// Go internal X25519 implementation also uses this representation, but a raw private key is also accepted.
	// https://github.com/golang/go/blob/e246cf626d1768ab56fa9eeafe4d23266e956ef6/src/crypto/ecdh/x25519.go#L90-L92

	// Copy the private key so we don't modify the original.
	var e [32]byte

	copy(e[:], key[:])

	// Convert to DivHTimesH format by
	// clearing the last three bits of the least significant byte,
	// which is the same as applying h*(s/(h mod GOrd)) where
	// s = key, h = 0x08, GOrd (cbSubgroupOrder) = 0x20.
	// h and GOrd values taken from
	// https://github.com/microsoft/SymCrypt/blob/e875f1f957dcb1308f8e712e9f4a8edc6f4f6207/lib/ec_internal_curves.c#L496.
	e[0] &= 248 // 0b1111_1000

	// Apply the High bit restrictions by clearing the bit 255 and setting the bit 254.
	e[31] &= 127 // 0b0111_1111
	e[31] |= 64  // 0b0100_0000
	return e[:]
}
