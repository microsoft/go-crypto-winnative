// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"runtime"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
	"github.com/microsoft/go-crypto-winnative/internal/subtle"
)

const aesBlockSize = 16

type aesCipher struct {
	kh  bcrypt.KEY_HANDLE
	key []byte
}

func NewAESCipher(key []byte) (cipher.Block, error) {
	kh, err := newCipherHandle(bcrypt.AES_ALGORITHM, bcrypt.CHAIN_MODE_ECB, key)
	if err != nil {
		return nil, err
	}
	c := &aesCipher{kh: kh, key: bytes.Clone(key)}
	runtime.SetFinalizer(c, (*aesCipher).finalize)
	return c, nil
}

func (c *aesCipher) finalize() {
	bcrypt.DestroyKey(c.kh)
}

func (c *aesCipher) BlockSize() int { return aesBlockSize }

// validateAndClipInputs checks that dst and src meet the [cipher.Block]
// interface requirements and clips them to a single block.
func (c *aesCipher) validateAndClipInputs(dst, src []byte) (d, s []byte) {
	if len(src) < aesBlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < aesBlockSize {
		panic("crypto/aes: output not full block")
	}
	// cypher.Block methods are documented to operate on
	// one block at a time, so we truncate the input and output
	// to the block size.
	d, s = dst[:aesBlockSize], src[:aesBlockSize]
	if subtle.InexactOverlap(d, s) {
		panic("crypto/aes: invalid buffer overlap")
	}
	return d, s
}

func (c *aesCipher) Encrypt(dst, src []byte) {
	dst, src = c.validateAndClipInputs(dst, src)

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
	dst, src = c.validateAndClipInputs(dst, src)

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
	return newCBC(true, bcrypt.AES_ALGORITHM, c.key, iv)
}

func (c *aesCipher) NewCBCDecrypter(iv []byte) cipher.BlockMode {
	return newCBC(false, bcrypt.AES_ALGORITHM, c.key, iv)
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
	return newGCM(c.key, cipherGCMTLSNone)
}

// NewGCMTLS returns a GCM cipher specific to TLS
// and should not be used for non-TLS purposes.
func NewGCMTLS(c cipher.Block) (cipher.AEAD, error) {
	return c.(*aesCipher).NewGCMTLS()
}

func (c *aesCipher) NewGCMTLS() (cipher.AEAD, error) {
	return newGCM(c.key, cipherGCMTLS12)
}

// NewGCMTLS13 returns a GCM cipher specific to TLS 1.3 and should not be used
// for non-TLS purposes.
func NewGCMTLS13(c cipher.Block) (cipher.AEAD, error) {
	return c.(*aesCipher).NewGCMTLS13()
}

func (c *aesCipher) NewGCMTLS13() (cipher.AEAD, error) {
	return newGCM(c.key, cipherGCMTLS13)
}

type cbcCipher struct {
	kh bcrypt.KEY_HANDLE
	// Use aesBlockSize, the max of all supported cipher block sizes.
	// The array avoids allocations (vs. a slice).
	iv        [aesBlockSize]byte
	blockSize int
	encrypt   bool
}

func newCBC(encrypt bool, alg string, key, iv []byte) *cbcCipher {
	var blockSize int
	switch alg {
	case bcrypt.AES_ALGORITHM:
		blockSize = aesBlockSize
	case bcrypt.DES_ALGORITHM, bcrypt.DES3_ALGORITHM:
		blockSize = desBlockSize
	default:
		panic("invalid algorithm: " + alg)
	}
	kh, err := newCipherHandle(alg, bcrypt.CHAIN_MODE_CBC, key)
	if err != nil {
		panic(err)
	}
	x := &cbcCipher{kh: kh, encrypt: encrypt, blockSize: blockSize}
	runtime.SetFinalizer(x, (*cbcCipher).finalize)
	x.SetIV(iv)
	return x
}

func (x *cbcCipher) finalize() {
	bcrypt.DestroyKey(x.kh)
}

func (x *cbcCipher) BlockSize() int { return x.blockSize }

func (x *cbcCipher) CryptBlocks(dst, src []byte) {
	if subtle.InexactOverlap(dst, src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(src)%x.blockSize != 0 {
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
		err = bcrypt.Encrypt(x.kh, src, nil, x.iv[:x.blockSize], dst, &ret, 0)
	} else {
		err = bcrypt.Decrypt(x.kh, src, nil, x.iv[:x.blockSize], dst, &ret, 0)
	}
	if err != nil {
		panic(err)
	}
	if int(ret) != len(src) {
		panic("crypto/aes: plaintext not fully encrypted")
	}
	runtime.KeepAlive(x)
}

func (x *cbcCipher) SetIV(iv []byte) {
	if len(iv) != x.blockSize {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv[:], iv)
}

const (
	gcmTagSize           = 16
	gcmStandardNonceSize = 12
	// TLS 1.2 additional data is constructed as:
	//
	//     additional_data = seq_num(8) + TLSCompressed.type(1) + TLSCompressed.version(2) + TLSCompressed.length(2);
	gcmTls12AddSize = 13
	// TLS 1.3 additional data is constructed as:
	//
	//     additional_data = TLSCiphertext.opaque_type(1) || TLSCiphertext.legacy_record_version(2) || TLSCiphertext.length(2)
	gcmTls13AddSize      = 5
	gcmTlsFixedNonceSize = 4
)

type cipherGCMTLS uint8

const (
	cipherGCMTLSNone cipherGCMTLS = iota
	cipherGCMTLS12
	cipherGCMTLS13
)

type aesGCM struct {
	kh  bcrypt.KEY_HANDLE
	tls cipherGCMTLS
	// minNextNonce is the minimum value that the next nonce can be, enforced by
	// all TLS modes.
	minNextNonce uint64
	// mask is the nonce mask used in TLS 1.3 mode.
	mask uint64
	// maskInitialized is true if mask has been initialized. This happens during
	// the first Seal. The initialized mask may be 0. Used by TLS 1.3 mode.
	maskInitialized bool
}

func (g *aesGCM) finalize() {
	bcrypt.DestroyKey(g.kh)
}

func newGCM(key []byte, tls cipherGCMTLS) (*aesGCM, error) {
	kh, err := newCipherHandle(bcrypt.AES_ALGORITHM, bcrypt.CHAIN_MODE_GCM, key)
	if err != nil {
		return nil, err
	}
	g := &aesGCM{kh: kh, tls: tls}
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
	if g.tls != cipherGCMTLSNone {
		if g.tls == cipherGCMTLS12 && len(additionalData) != gcmTls12AddSize {
			panic("cipher: incorrect additional data length given to GCM TLS 1.2")
		} else if g.tls == cipherGCMTLS13 && len(additionalData) != gcmTls13AddSize {
			panic("cipher: incorrect additional data length given to GCM TLS 1.3")
		}
		counter := bigUint64(nonce[gcmTlsFixedNonceSize:])
		if g.tls == cipherGCMTLS13 {
			// In TLS 1.3, the counter in the nonce has a mask and requires
			// further decoding.
			if !g.maskInitialized {
				// According to TLS 1.3 nonce construction details at
				// https://tools.ietf.org/html/rfc8446#section-5.3:
				//
				//   the first record transmitted under a particular traffic
				//   key MUST use sequence number 0.
				//
				//   The padded sequence number is XORed with [a mask].
				//
				//   The resulting quantity (of length iv_length) is used as
				//   the per-record nonce.
				//
				// We need to convert from the given nonce to sequence numbers
				// to keep track of minNextNonce and enforce the counter
				// maximum. On the first call, we know counter^mask is 0^mask,
				// so we can simply store it as the mask.
				g.mask = counter
				g.maskInitialized = true
			}
			counter ^= g.mask
		}
		// BoringCrypto enforces strictly monotonically increasing explicit nonces
		// and to fail after 2^64 - 1 keys as per FIPS 140-2 IG A.5,
		// but BCrypt does not perform this check, so it is implemented here.
		const maxUint64 = 1<<64 - 1
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

func (g *aesGCM) SealWithRandomNonce(out, nonce, plaintext, additionalData []byte) {
	if uint64(len(plaintext)) > uint64((1<<32)-2)*aesBlockSize {
		panic("crypto/cipher: message too large for GCM")
	}
	if len(nonce) != gcmStandardNonceSize {
		panic("crypto/cipher: incorrect nonce length given to GCMWithRandomNonce")
	}
	if len(out) != len(plaintext)+gcmTagSize {
		panic("crypto/cipher: incorrect output length given to GCMWithRandomNonce")
	}
	if subtle.InexactOverlap(out, plaintext) {
		panic("crypto/cipher: invalid buffer overlap of output and input")
	}
	if subtle.AnyOverlap(out, additionalData) {
		panic("crypto/cipher: invalid buffer overlap of output and additional data")
	}

	if g.tls != cipherGCMTLSNone {
		panic("cipher: TLS 1.2 and 1.3 modes do not support random nonce")
	}

	RandReader.Read(nonce)
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
	return
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
