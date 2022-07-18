// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"crypto/cipher"
	"errors"
	"runtime"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
	"github.com/microsoft/go-crypto-winnative/internal/subtle"
)

const aesBlockSize = 16

type aesAlgorithm struct {
	handle            bcrypt.ALG_HANDLE
	allowedKeyLengths bcrypt.KEY_LENGTHS_STRUCT
}

func loadAes(mode string) (aesAlgorithm, error) {
	v, err := loadOrStoreAlg(bcrypt.AES_ALGORITHM, bcrypt.ALG_NONE_FLAG, mode, func(h bcrypt.ALG_HANDLE) (interface{}, error) {
		// Windows 8 added support to set the CipherMode value on a key,
		// but Windows 7 requires that it be set on the algorithm before key creation.
		err := setString(bcrypt.HANDLE(h), bcrypt.CHAINING_MODE, mode)
		if err != nil {
			return nil, err
		}
		lengths, err := getKeyLengths(bcrypt.HANDLE(h))
		if err != nil {
			return nil, err
		}
		return aesAlgorithm{h, lengths}, nil
	})
	if err != nil {
		return aesAlgorithm{}, nil
	}
	return v.(aesAlgorithm), nil
}

type aesCipher struct {
	kh  bcrypt.KEY_HANDLE
	key []byte
}

func NewAESCipher(key []byte) (cipher.Block, error) {
	h, err := loadAes(bcrypt.CHAIN_MODE_ECB)
	if err != nil {
		return nil, err
	}
	if !keyIsAllowed(h.allowedKeyLengths, uint32(len(key)*8)) {
		return nil, errors.New("crypto/cipher: invalid key size")
	}
	c := &aesCipher{key: make([]byte, len(key))}
	copy(c.key, key)
	err = bcrypt.GenerateSymmetricKey(h.handle, &c.kh, nil, c.key, 0)
	if err != nil {
		return nil, err
	}
	runtime.SetFinalizer(c, (*aesCipher).finalize)
	return c, nil
}

func (c *aesCipher) finalize() {
	bcrypt.DestroyKey(c.kh)
}

func (c *aesCipher) BlockSize() int { return aesBlockSize }

func (c *aesCipher) Encrypt(dst, src []byte) {
	if subtle.InexactOverlap(dst, src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(src) < aesBlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < aesBlockSize {
		panic("crypto/aes: output not full block")
	}
	var ret uint32
	err := bcrypt.Encrypt(c.kh, src, nil, nil, dst, &ret, 0)
	if err != nil {
		panic(err)
	}
	if int(ret) != len(src) {
		panic("crypto/aes: plaintext not fully encrypted")
	}
	runtime.KeepAlive(c)
}

func (c *aesCipher) Decrypt(dst, src []byte) {
	if subtle.InexactOverlap(dst, src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(src) < aesBlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < aesBlockSize {
		panic("crypto/aes: output not full block")
	}

	var ret uint32
	err := bcrypt.Decrypt(c.kh, src, nil, nil, dst, &ret, 0)
	if err != nil {
		panic(err)
	}
	if int(ret) != len(src) {
		panic("crypto/aes: plaintext not fully decrypted")
	}
	runtime.KeepAlive(c)
}

func (c *aesCipher) NewCBCEncrypter(iv []byte) cipher.BlockMode {
	return newCBC(true, c.key, iv)
}

func (c *aesCipher) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	return newCBC(false, c.key, iv)
}

type noGCM struct {
	cipher.Block
}

func (c *aesCipher) NewGCM(nonceSize, tagSize int) (cipher.AEAD, error) {
	if nonceSize != gcmStandardNonceSize && tagSize != gcmTagSize {
		return nil, errors.New("crypto/aes: GCM tag and nonce sizes can't be non-standard at the same time")
	}
	// Fall back to standard library for GCM with non-standard nonce or tag size.
	if nonceSize != gcmStandardNonceSize {
		return cipher.NewGCMWithNonceSize(&noGCM{c}, nonceSize)
	}
	if tagSize != gcmTagSize {
		return cipher.NewGCMWithTagSize(&noGCM{c}, tagSize)
	}
	return newGCM(c.key, false)
}

// NewGCMTLS returns a GCM cipher specific to TLS
// and should not be used for non-TLS purposes.
func NewGCMTLS(c cipher.Block) (cipher.AEAD, error) {
	return c.(*aesCipher).NewGCMTLS()
}

func (c *aesCipher) NewGCMTLS() (cipher.AEAD, error) {
	return newGCM(c.key, true)
}

type aesCBC struct {
	kh      bcrypt.KEY_HANDLE
	iv      [aesBlockSize]byte
	encrypt bool
}

func newCBC(encrypt bool, key, iv []byte) *aesCBC {
	h, err := loadAes(bcrypt.CHAIN_MODE_CBC)
	if err != nil {
		panic(err)
	}
	x := &aesCBC{encrypt: encrypt}
	x.SetIV(iv)
	err = bcrypt.GenerateSymmetricKey(h.handle, &x.kh, nil, key, 0)
	if err != nil {
		panic(err)
	}
	runtime.SetFinalizer(x, (*aesCBC).finalize)
	return x
}

func (x *aesCBC) finalize() {
	bcrypt.DestroyKey(x.kh)
}

func (x *aesCBC) BlockSize() int { return aesBlockSize }

func (x *aesCBC) CryptBlocks(dst, src []byte) {
	if subtle.InexactOverlap(dst, src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(src)%aesBlockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	if len(src) == 0 {
		return
	}
	var ret uint32
	var err error
	if x.encrypt {
		err = bcrypt.Encrypt(x.kh, src, nil, x.iv[:], dst, &ret, 0)
	} else {
		err = bcrypt.Decrypt(x.kh, src, nil, x.iv[:], dst, &ret, 0)
	}
	if err != nil {
		panic(err)
	}
	if int(ret) != len(src) {
		panic("crypto/aes: plaintext not fully encrypted")
	}
	runtime.KeepAlive(x)
}

func (x *aesCBC) SetIV(iv []byte) {
	if len(iv) != aesBlockSize {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv[:], iv)
}

const (
	gcmTagSize           = 16
	gcmStandardNonceSize = 12
	gcmTlsAddSize        = 13
	gcmTlsFixedNonceSize = 4
)

type aesGCM struct {
	kh           bcrypt.KEY_HANDLE
	tls          bool
	minNextNonce uint64
}

func (g *aesGCM) finalize() {
	bcrypt.DestroyKey(g.kh)
}

func newGCM(key []byte, tls bool) (*aesGCM, error) {
	h, err := loadAes(bcrypt.CHAIN_MODE_GCM)
	if err != nil {
		return nil, err
	}
	g := &aesGCM{tls: tls}
	err = bcrypt.GenerateSymmetricKey(h.handle, &g.kh, nil, key, 0)
	if err != nil {
		return nil, err
	}
	runtime.SetFinalizer(g, (*aesGCM).finalize)
	return g, nil
}

func (g *aesGCM) NonceSize() int {
	return gcmStandardNonceSize
}

func (g *aesGCM) Overhead() int {
	return gcmTagSize
}

func (g *aesGCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != gcmStandardNonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	if uint64(len(plaintext)) > ((1<<32)-2)*aesBlockSize || len(plaintext)+gcmTagSize < len(plaintext) {
		panic("cipher: message too large for GCM")
	}
	if len(dst)+len(plaintext)+gcmTagSize < len(dst) {
		panic("cipher: message too large for buffer")
	}
	if g.tls {
		if len(additionalData) != gcmTlsAddSize {
			panic("cipher: incorrect additional data length given to GCM TLS")
		}
		// BoringCrypto enforces strictly monotonically increasing explicit nonces
		// and to fail after 2^64 - 1 keys as per FIPS 140-2 IG A.5,
		// but BCrypt does not perform this check, so it is implemented here.
		const maxUint64 = 1<<64 - 1
		counter := bigUint64(nonce[gcmTlsFixedNonceSize:])
		if counter == maxUint64 {
			panic("cipher: nonce counter must be less than 2^64 - 1")
		}
		if counter < g.minNextNonce {
			panic("cipher: nonce counter must be strictly monotonically increasing")
		}
		defer func() {
			g.minNextNonce = counter + 1
		}()
	}
	// Make room in dst to append plaintext+overhead.
	ret, out := sliceForAppend(dst, len(plaintext)+gcmTagSize)

	// Check delayed until now to make sure len(dst) is accurate.
	if subtle.InexactOverlap(out, plaintext) {
		panic("cipher: invalid buffer overlap")
	}

	info := bcrypt.NewAUTHENTICATED_CIPHER_MODE_INFO(nonce, additionalData, out[len(out)-gcmTagSize:])
	var encSize uint32
	err := bcrypt.Encrypt(g.kh, plaintext, unsafe.Pointer(info), nil, out, &encSize, 0)
	if err != nil {
		panic(err)
	}
	if int(encSize) != len(plaintext) {
		panic("crypto/aes: plaintext not fully encrypted")
	}
	runtime.KeepAlive(g)
	return ret
}

var errOpen = errors.New("cipher: message authentication failed")

func (g *aesGCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != gcmStandardNonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	if len(ciphertext) < gcmTagSize {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > ((1<<32)-2)*aesBlockSize+gcmTagSize {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-gcmTagSize:]
	ciphertext = ciphertext[:len(ciphertext)-gcmTagSize]

	// Make room in dst to append ciphertext without tag.
	ret, out := sliceForAppend(dst, len(ciphertext))

	// Check delayed until now to make sure len(dst) is accurate.
	if subtle.InexactOverlap(out, ciphertext) {
		panic("cipher: invalid buffer overlap")
	}

	info := bcrypt.NewAUTHENTICATED_CIPHER_MODE_INFO(nonce, additionalData, tag)
	var decSize uint32
	err := bcrypt.Decrypt(g.kh, ciphertext, unsafe.Pointer(info), nil, out, &decSize, 0)
	if err != nil || int(decSize) != len(ciphertext) {
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}
	runtime.KeepAlive(g)
	return ret, nil
}

// sliceForAppend is a mirror of crypto/cipher.sliceForAppend.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

func bigUint64(b []byte) uint64 {
	_ = b[7] // bounds check hint to compiler; see go.dev/issue/14808
	return uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
}
