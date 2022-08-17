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

const sizeOfRSABlobHeader = uint32(unsafe.Sizeof(bcrypt.RSAKEY_BLOB{}))

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

	var size uint32
	err = bcrypt.ExportKey(hkey, 0, utf16PtrFromString(bcrypt.RSAFULLPRIVATE_BLOB), nil, &size, 0)
	if err != nil {
		return bad(err)
	}

	if size < sizeOfRSABlobHeader {
		return bad(errors.New("crypto/rsa: exported key is corrupted"))
	}

	blob := make([]byte, size)
	err = bcrypt.ExportKey(hkey, 0, utf16PtrFromString(bcrypt.RSAFULLPRIVATE_BLOB), blob, &size, 0)
	if err != nil {
		return bad(err)
	}
	hdr := (*(*bcrypt.RSAKEY_BLOB)(unsafe.Pointer(&blob[0])))
	if hdr.Magic != bcrypt.RSAFULLPRIVATE_MAGIC || hdr.BitLength != uint32(bits) {
		return bad(errors.New("crypto/rsa: exported key is corrupted"))
	}
	data := blob[sizeOfRSABlobHeader:]
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
	pkey bcrypt.KEY_HANDLE
}

func NewPublicKeyRSA(N, E BigInt) (*PublicKeyRSA, error) {
	h, err := loadRsa()
	if err != nil {
		return nil, err
	}
	if !keyIsAllowed(h.allowedKeyLengths, uint32(len(N)*8)) {
		return nil, errors.New("crypto/rsa: invalid key size")
	}
	blob, err := encodeRSAKey(N, E, nil, nil, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	k := new(PublicKeyRSA)
	err = bcrypt.ImportKeyPair(h.handle, 0, utf16PtrFromString(bcrypt.RSAPUBLIC_KEY_BLOB), &k.pkey, blob, 0)
	if err != nil {
		return nil, err
	}
	runtime.SetFinalizer(k, (*PublicKeyRSA).finalize)
	return k, nil
}

func (k *PublicKeyRSA) finalize() {
	bcrypt.DestroyKey(k.pkey)
}

type PrivateKeyRSA struct {
	pkey bcrypt.KEY_HANDLE
}

func (k *PrivateKeyRSA) finalize() {
	bcrypt.DestroyKey(k.pkey)
}

func NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv BigInt) (*PrivateKeyRSA, error) {
	h, err := loadRsa()
	if err != nil {
		return nil, err
	}
	if !keyIsAllowed(h.allowedKeyLengths, uint32(len(N)*8)) {
		return nil, errors.New("crypto/rsa: invalid key size")
	}
	blob, err := encodeRSAKey(N, E, D, P, Q, Dp, Dq, Qinv)
	if err != nil {
		return nil, err
	}
	k := new(PrivateKeyRSA)
	err = bcrypt.ImportKeyPair(h.handle, 0, utf16PtrFromString(bcrypt.RSAFULLPRIVATE_BLOB), &k.pkey, blob, 0)
	if err != nil {
		return nil, err
	}
	runtime.SetFinalizer(k, (*PrivateKeyRSA).finalize)
	return k, nil
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
		hdr.Magic = bcrypt.RSAFULLPRIVATE_MAGIC
		hdr.Prime1Size = uint32(len(P))
		hdr.Prime2Size = uint32(len(Q))
		blob = make([]byte, sizeOfRSABlobHeader+hdr.PublicExpSize+hdr.ModulusSize*2+hdr.Prime1Size*3+hdr.Prime2Size*2)
	}
	copy(blob, (*(*[sizeOfRSABlobHeader]byte)(unsafe.Pointer(&hdr)))[:])
	data := blob[sizeOfRSABlobHeader:]
	var err error
	encode := func(b BigInt, size uint32) {
		if err != nil {
			return
		}
		// b might be shorter than size if the original big number contained leading zeros.
		leadingZeros := int(size) - len(b)
		if leadingZeros < 0 {
			err = errors.New("crypto/rsa: invalid parameters")
			return
		}
		copy(data[leadingZeros:], b)
		data = data[size:]
	}
	encode(E, hdr.PublicExpSize)
	encode(N, hdr.ModulusSize)
	if D != nil {
		encode(P, hdr.Prime1Size)
		encode(Q, hdr.Prime2Size)
		encode(Dp, hdr.Prime1Size)
		encode(Dq, hdr.Prime2Size)
		encode(Qinv, hdr.Prime1Size)
		encode(D, hdr.ModulusSize)
	}
	if err != nil {
		return nil, err
	}
	return blob, nil
}

func DecryptRSAOAEP(h hash.Hash, priv *PrivateKeyRSA, ciphertext, label []byte) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	return rsaOAEP(h, priv.pkey, ciphertext, label, false)
}

func EncryptRSAOAEP(h hash.Hash, pub *PublicKeyRSA, msg, label []byte) ([]byte, error) {
	defer runtime.KeepAlive(pub)
	return rsaOAEP(h, pub.pkey, msg, label, true)
}

func DecryptRSAPKCS1(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	return rsaCrypt(priv.pkey, nil, ciphertext, bcrypt.PAD_PKCS1, false)
}

func EncryptRSAPKCS1(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	defer runtime.KeepAlive(pub)
	return rsaCrypt(pub.pkey, nil, msg, bcrypt.PAD_PKCS1, true)
}

func DecryptRSANoPadding(priv *PrivateKeyRSA, ciphertext []byte) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	return rsaCrypt(priv.pkey, nil, ciphertext, bcrypt.PAD_NONE, false)

}

func EncryptRSANoPadding(pub *PublicKeyRSA, msg []byte) ([]byte, error) {
	defer runtime.KeepAlive(pub)
	return rsaCrypt(pub.pkey, nil, msg, bcrypt.PAD_NONE, true)
}

func SignRSAPSS(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte, saltLen int) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	info, err := newPSS_PADDING_INFO(h, saltLen)
	if err != nil {
		return nil, err
	}
	return keySign(priv.pkey, unsafe.Pointer(&info), hashed, bcrypt.PAD_PSS)
}

func VerifyRSAPSS(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte, saltLen int) error {
	defer runtime.KeepAlive(pub)
	info, err := newPSS_PADDING_INFO(h, saltLen)
	if err != nil {
		return err
	}
	return keyVerify(pub.pkey, unsafe.Pointer(&info), hashed, sig, bcrypt.PAD_PSS)
}

func SignRSAPKCS1v15(priv *PrivateKeyRSA, h crypto.Hash, hashed []byte) ([]byte, error) {
	defer runtime.KeepAlive(priv)
	info, err := newPKCS1_PADDING_INFO(h)
	if err != nil {
		return nil, err
	}
	return keySign(priv.pkey, unsafe.Pointer(&info), hashed, bcrypt.PAD_PKCS1)
}

func VerifyRSAPKCS1v15(pub *PublicKeyRSA, h crypto.Hash, hashed, sig []byte) error {
	defer runtime.KeepAlive(pub)
	info, err := newPKCS1_PADDING_INFO(h)
	if err != nil {
		return err
	}
	return keyVerify(pub.pkey, unsafe.Pointer(&info), hashed, sig, bcrypt.PAD_PKCS1)
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

func newPSS_PADDING_INFO(h crypto.Hash, saltLen int) (info bcrypt.PSS_PADDING_INFO, err error) {
	hashID := cryptoHashToID(h)
	if hashID == "" {
		return info, errors.New("crypto/rsa: unsupported hash function")
	}
	info.AlgId = utf16PtrFromString(hashID)
	switch saltLen {
	case -1: // rsa.PSSSaltLengthEqualsHash
		info.Salt = uint32(h.Size())
	case 0: // rsa.PSSSaltLengthAuto
		err = errors.New("crypto/rsa: rsa.PSSSaltLengthAuto not supported")
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
