// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"crypto"
	"errors"
	"hash"
	"runtime"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

type rsaAlgorithm struct {
	handle            bcrypt.ALG_HANDLE
	allowedKeyLengths bcrypt.KEY_LENGTHS_STRUCT
}

func loadRsa() (rsaAlgorithm, error) {
	v, err := loadOrStoreAlg(bcrypt.RSA_ALGORITHM, bcrypt.ALG_NONE_FLAG, "", func(h bcrypt.ALG_HANDLE) (interface{}, error) {
		lengths, err := getKeyLengths(bcrypt.HANDLE(h))
		if err != nil {
			return nil, err
		}
		return rsaAlgorithm{h, lengths}, nil
	})
	if err != nil {
		return rsaAlgorithm{}, err
	}
	return v.(rsaAlgorithm), nil
}

func GenerateKeyRSA(bits int) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
	bad := func(e error) (N, E, D, P, Q, Dp, Dq, Qinv BigInt, err error) {
		return nil, nil, nil, nil, nil, nil, nil, nil, e
	}
	h, err := loadRsa()
	if err != nil {
		return bad(err)
	}
	if !keyIsAllowed(h.allowedKeyLengths, uint32(bits)) {
		return bad(errors.New("crypto/rsa: invalid key size"))
	}
	var hkey bcrypt.KEY_HANDLE
	err = bcrypt.GenerateKeyPair(h.handle, &hkey, uint32(bits), 0)
	if err != nil {
		return bad(err)
	}
	defer bcrypt.DestroyKey(hkey)
	// The key cannot be used until BcryptFinalizeKeyPair has been called.
	err = bcrypt.FinalizeKeyPair(hkey, 0)
	if err != nil {
		return bad(err)
	}

	hdr, data, err := exportRSAKey(hkey, true)
	if err != nil {
		return bad(err)
	}
	if hdr.Magic != bcrypt.RSAFULLPRIVATE_MAGIC || hdr.BitLength != uint32(bits) {
		return bad(errors.New("crypto/rsa: exported key is corrupted"))
	}
	consumeBigInt := func(size uint32) BigInt {
		b := data[:size]
		data = data[size:]
		return b
	}
	E = consumeBigInt(hdr.PublicExpSize)
	N = consumeBigInt(hdr.ModulusSize)
	P = consumeBigInt(hdr.Prime1Size)
	Q = consumeBigInt(hdr.Prime2Size)
	Dp = consumeBigInt(hdr.Prime1Size)
	Dq = consumeBigInt(hdr.Prime2Size)
	Qinv = consumeBigInt(hdr.Prime1Size)
	D = consumeBigInt(hdr.ModulusSize)
	return
}

type PublicKeyRSA struct {
	hkey bcrypt.KEY_HANDLE
	bits uint32
}

func NewPublicKeyRSA(N, E BigInt) (*PublicKeyRSA, error) {
	h, err := loadRsa()
	if err != nil {
		return nil, err
	}
	if !keyIsAllowed(h.allowedKeyLengths, uint32(len(N)*8)) {
		return nil, errors.New("crypto/rsa: invalid key size")
	}
	hkey, err := importRSAKey(h.handle, N, E, nil, nil, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	k := &PublicKeyRSA{hkey, uint32(N.bitLen())}
	runtime.SetFinalizer(k, (*PublicKeyRSA).finalize)
	return k, nil
}

func (k *PublicKeyRSA) finalize() {
	bcrypt.DestroyKey(k.hkey)
}

type PrivateKeyRSA struct {
	hkey bcrypt.KEY_HANDLE
	bits uint32
}

func (k *PrivateKeyRSA) finalize() {
	bcrypt.DestroyKey(k.hkey)
}

func NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv BigInt) (*PrivateKeyRSA, error) {
	h, err := loadRsa()
	if err != nil {
		return nil, err
	}
	if !keyIsAllowed(h.allowedKeyLengths, uint32(len(N)*8)) {
		return nil, errors.New("crypto/rsa: invalid key size")
	}
	hkey, err := importRSAKey(h.handle, N, E, D, P, Q, Dp, Dq, Qinv)
	if err != nil {
		return nil, err
	}
	k := &PrivateKeyRSA{hkey, uint32(N.bitLen())}
	runtime.SetFinalizer(k, (*PrivateKeyRSA).finalize)
	return k, nil
}

func importRSAKey(h bcrypt.ALG_HANDLE, N, E, D, P, Q, Dp, Dq, Qinv BigInt) (bcrypt.KEY_HANDLE, error) {
	blob, err := encodeRSAKey(N, E, D, P, Q, Dp, Dq, Qinv)
	if err != nil {
		return 0, err
	}
	var kind string
	if D == nil {
		kind = bcrypt.RSAPUBLIC_KEY_BLOB
	} else {
		kind = bcrypt.RSAFULLPRIVATE_BLOB
	}
	var hkey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(h, 0, utf16PtrFromString(kind), &hkey, blob, 0)
	if err != nil {
		return 0, err
	}
	return hkey, nil
}

func encodeRSAKey(N, E, D, P, Q, Dp, Dq, Qinv BigInt) ([]byte, error) {
	hdr := bcrypt.RSAKEY_BLOB{
		BitLength:     uint32(len(N) * 8),
		PublicExpSize: uint32(len(E)),
		ModulusSize:   uint32(len(N)),
	}
	var blob []byte
	if D == nil {
		hdr.Magic = bcrypt.RSAPUBLIC_MAGIC
		blob = make([]byte, sizeOfRSABlobHeader+hdr.PublicExpSize+hdr.ModulusSize)
	} else {
		if P == nil || Q == nil {
			// This case can happen when the key has been generated with more than 2 primes.
			// CNG only supports 2-prime keys.
			return nil, errors.New("crypto/rsa: unsupported private key")
		}
		hdr.Magic = bcrypt.RSAFULLPRIVATE_MAGIC
		hdr.Prime1Size = uint32(len(P))
		hdr.Prime2Size = uint32(len(Q))
		blob = make([]byte, sizeOfRSABlobHeader+hdr.PublicExpSize+hdr.ModulusSize*2+hdr.Prime1Size*3+hdr.Prime2Size*2)
	}
	copy(blob, (*(*[sizeOfRSABlobHeader]byte)(unsafe.Pointer(&hdr)))[:])
	data := blob[sizeOfRSABlobHeader:]
	err := encodeBigInt(data, []sizedBigInt{
		{E, hdr.PublicExpSize}, {N, hdr.ModulusSize},
		{P, hdr.Prime1Size}, {Q, hdr.Prime2Size},
		{Dp, hdr.Prime1Size}, {Dq, hdr.Prime2Size},
		{Qinv, hdr.Prime1Size}, {D, hdr.ModulusSize},
	})
	if err != nil {
		return nil, err
	}
	return blob, nil
}

func DecryptRSAOAEP(h hash.Hash, priv *PrivateKeyRSA, ciphertext, label []byte) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	return rsaOAEP(h, priv.hkey, ciphertext, label, false)
}

func EncryptRSAOAEP(h hash.Hash, pub *PublicKeyRSA, msg, label []byte) ([]byte, error) {
	defer runtime.KeepAlive(pub)
	return rsaOAEP(h, pub.hkey, msg, label, true)
}

func DecryptRSAPKCS1(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	return rsaCrypt(priv.hkey, nil, ciphertext, bcrypt.PAD_PKCS1, false)
}

func EncryptRSAPKCS1(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	defer runtime.KeepAlive(pub)
	return rsaCrypt(pub.hkey, nil, msg, bcrypt.PAD_PKCS1, true)
}

func DecryptRSANoPadding(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	return rsaCrypt(priv.hkey, nil, ciphertext, bcrypt.PAD_NONE, false)

}

func EncryptRSANoPadding(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	defer runtime.KeepAlive(pub)
	return rsaCrypt(pub.hkey, nil, msg, bcrypt.PAD_NONE, true)
}

func SignRSAPSS(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	info, err := newPSS_PADDING_INFO(h, priv.bits, saltLen, true)
	if err != nil {
		return nil, err
	}
	return keySign(priv.hkey, unsafe.Pointer(&info), hashed, bcrypt.PAD_PSS)
}

func VerifyRSAPSS(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	defer runtime.KeepAlive(pub)
	info, err := newPSS_PADDING_INFO(h, pub.bits, saltLen, false)
	if err != nil {
		return err
	}
	return keyVerify(pub.hkey, unsafe.Pointer(&info), hashed, sig, bcrypt.PAD_PSS)
}

func SignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	info, err := newPKCS1_PADDING_INFO(h)
	if err != nil {
		return nil, err
	}
	return keySign(priv.hkey, unsafe.Pointer(&info), hashed, bcrypt.PAD_PKCS1)
}

func VerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte) error {
	defer runtime.KeepAlive(pub)
	info, err := newPKCS1_PADDING_INFO(h)
	if err != nil {
		return err
	}
	return keyVerify(pub.hkey, unsafe.Pointer(&info), hashed, sig, bcrypt.PAD_PKCS1)
}

func rsaCrypt(pkey bcrypt.KEY_HANDLE, info unsafe.Pointer, in []byte, flags bcrypt.PadMode, encrypt bool) ([]byte, error) {
	var size uint32
	var err error
	if encrypt {
		err = bcrypt.Encrypt(pkey, in, info, nil, nil, &size, flags)
	} else {
		err = bcrypt.Decrypt(pkey, in, info, nil, nil, &size, flags)
	}
	if err != nil {
		return nil, err
	}
	out := make([]byte, size)
	if encrypt {
		err = bcrypt.Encrypt(pkey, in, info, nil, out, &size, flags)
	} else {
		err = bcrypt.Decrypt(pkey, in, info, nil, out, &size, flags)
	}
	if err != nil {
		return nil, err
	}
	return out[:size], nil
}

func rsaOAEP(h hash.Hash, pkey bcrypt.KEY_HANDLE, in, label []byte, encrypt bool) ([]byte, error) {
	hashID := hashToID(h)
	if hashID == "" {
		return nil, errors.New("crypto/rsa: unsupported hash function")
	}
	info := bcrypt.OAEP_PADDING_INFO{
		AlgId:     utf16PtrFromString(hashID),
		LabelSize: uint32(len(label)),
	}
	if len(label) > 0 {
		info.Label = &label[0]
	}
	return rsaCrypt(pkey, unsafe.Pointer(&info), in, bcrypt.PAD_OAEP, encrypt)
}

func keySign(pkey bcrypt.KEY_HANDLE, info unsafe.Pointer, hashed []byte, flags bcrypt.PadMode) ([]byte, error) {
	var size uint32
	err := bcrypt.SignHash(pkey, info, hashed, nil, &size, flags)
	if err != nil {
		return nil, err
	}
	out := make([]byte, size)
	err = bcrypt.SignHash(pkey, info, hashed, out, &size, flags)
	if err != nil {
		return nil, err
	}
	return out[:size], nil
}

func keyVerify(pkey bcrypt.KEY_HANDLE, info unsafe.Pointer, hashed, sig []byte, flags bcrypt.PadMode) error {
	return bcrypt.VerifySignature(pkey, info, hashed, sig, flags)
}

func newPSS_PADDING_INFO(h crypto.Hash, sizeBits uint32, saltLen int, sign bool) (info bcrypt.PSS_PADDING_INFO, err error) {
	hashID := cryptoHashToID(h)
	if hashID == "" {
		return info, errors.New("crypto/rsa: unsupported hash function")
	}
	info.AlgId = utf16PtrFromString(hashID)

	// A salt length of -1 and 0 are valid Go sentinel values.
	if saltLen <= -2 {
		return info, errors.New("crypto/rsa: PSSOptions.SaltLength cannot be negative")
	}
	// CNG does not support salt length special cases like Go crypto does,
	// so we do a best-effort to resolve them.
	switch saltLen {
	case -1: // rsa.PSSSaltLengthEqualsHash
		info.Salt = uint32(h.Size())
	case 0: // rsa.PSSSaltLengthAuto
		if sign {
			// Algorithm taken from RFC 3447 Section 9.1.1, which is also implemented by Go at
			// https://github.com/golang/go/blob/54182ff54a687272dd7632c3a963e036ce03cb7c/src/crypto/rsa/pss.go#L288.
			emLen := (sizeBits - 1 + 7) / 8
			hLen := uint32(h.Size())
			info.Salt = emLen - hLen - 2
		} else {
			// Go auto-detects the salt length from the signature structure when verifying.
			// The auto-detection logic is deep in the verification process,
			// we can't replicate it without exhaustive validation.
			err = errors.New("crypto/rsa: rsa.PSSSaltLengthAuto not supported")
		}
	default:
		info.Salt = uint32(saltLen)
	}
	return
}

func newPKCS1_PADDING_INFO(h crypto.Hash) (info bcrypt.PKCS1_PADDING_INFO, err error) {
	if h != 0 {
		hashID := cryptoHashToID(h)
		if hashID == "" {
			err = errors.New("crypto/rsa: unsupported hash function")
		} else {
			info.AlgId = utf16PtrFromString(hashID)
		}
	}
	return
}

func cryptoHashToID(ch crypto.Hash) string {
	switch ch {
	case crypto.MD5:
		return bcrypt.MD5_ALGORITHM
	case crypto.SHA1:
		return bcrypt.SHA1_ALGORITHM
	case crypto.SHA256:
		return bcrypt.SHA256_ALGORITHM
	case crypto.SHA384:
		return bcrypt.SHA384_ALGORITHM
	case crypto.SHA512:
		return bcrypt.SHA512_ALGORITHM
	}
	return ""
}
