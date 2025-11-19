// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

const (
	// sharedKeySizeMLKEM is the size of a shared key produced by ML-KEM.
	sharedKeySizeMLKEM = 32

	// seedSizeMLKEM is the size of a seed used to generate a decapsulation key.
	seedSizeMLKEM = 64

	// ciphertextSizeMLKEM768 is the size of a ciphertext produced by ML-KEM-768.
	ciphertextSizeMLKEM768 = 1088

	// encapsulationKeySizeMLKEM768 is the size of an ML-KEM-768 encapsulation key (raw key material).
	encapsulationKeySizeMLKEM768 = 1184

	// encapsulationKeyBlobSizeMLKEM768 is the size of the ML-KEM-768 encapsulation key blob
	// (Windows blob format, with header).
	encapsulationKeyBlobSizeMLKEM768 = 1204 // 12 + 8 ("768\0" in UTF-16) + 1184

	// decapsulationKeySizeMLKEM768 is the size of the ML-KEM-768 decapsulation key data (raw key material).
	decapsulationKeySizeMLKEM768 = 2400

	// decapsulationKeyBlobSizeMLKEM768 is the size of the ML-KEM-768 decapsulation key blob
	// (Windows blob format, with header).
	decapsulationKeyBlobSizeMLKEM768 = 2420 // 12 + 8 ("768\0" in UTF-16) + 2400

	// ciphertextSizeMLKEM1024 is the size of a ciphertext produced by ML-KEM-1024.
	ciphertextSizeMLKEM1024 = 1568

	// encapsulationKeySizeMLKEM1024 is the size of an ML-KEM-1024 encapsulation key (raw key material).
	encapsulationKeySizeMLKEM1024 = 1568

	// encapsulationKeyBlobSizeMLKEM1024 is the size of the ML-KEM-1024 encapsulation key blob
	// (Windows blob format, with header).
	encapsulationKeyBlobSizeMLKEM1024 = 1590 // 12 + 10 ("1024\0" in UTF-16) + 1568

	// decapsulationKeySizeMLKEM1024 is the size of the ML-KEM-1024 decapsulation key data (raw key material).
	decapsulationKeySizeMLKEM1024 = 3168

	// decapsulationKeyBlobSizeMLKEM1024 is the size of the ML-KEM-1024 decapsulation key blob
	// (Windows blob format, with header).
	decapsulationKeyBlobSizeMLKEM1024 = 3190 // 12 + 10 ("1024\0" in UTF-16) + 3168
)

// putUint32LE puts a uint32 in little-endian byte order.
func putUint32LE(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

// getUint32LE reads a uint32 in little-endian byte order.
func getUint32LE(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// putUint16LE puts a uint16 in little-endian byte order.
func putUint16LE(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}

type mlkemAlgorithm struct {
	handle bcrypt.ALG_HANDLE
}

func loadMLKEM() (mlkemAlgorithm, error) {
	return loadOrStoreAlg(bcrypt.MLKEM_ALGORITHM, 0, "", func(h bcrypt.ALG_HANDLE) (mlkemAlgorithm, error) {
		return mlkemAlgorithm{handle: h}, nil
	})
}

// SupportsMLKEM returns true if ML-KEM is supported on this platform.
// ML-KEM is supported on Windows 11 24H2/25H2 and Windows Server 2025 and later.
func SupportsMLKEM() bool {
	_, err := loadMLKEM()
	return err == nil
}

// generateMLKEMKey generates a new ML-KEM key pair with the specified parameter set.
func generateMLKEMKey(paramSet string) ([]byte, error) {
	alg, err := loadMLKEM()
	if err != nil {
		return nil, errors.New("mlkem: failed to open algorithm provider")
	}

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.GenerateKeyPair(alg.handle, &hKey, 0, 0)
	if err != nil {
		return nil, errors.New("mlkem: key generation failed")
	}
	defer bcrypt.DestroyKey(hKey)

	// Set the parameter set
	paramSetUTF16 := utf16FromString(paramSet)
	paramSetBytes := make([]byte, len(paramSetUTF16)*2)
	for i, v := range paramSetUTF16 {
		paramSetBytes[i*2] = byte(v)
		paramSetBytes[i*2+1] = byte(v >> 8)
	}
	err = bcrypt.SetProperty(bcrypt.HANDLE(hKey), utf16PtrFromString(bcrypt.PARAMETER_SET_NAME), paramSetBytes, 0)
	if err != nil {
		return nil, errors.New("mlkem: failed to set parameter set")
	}

	err = bcrypt.FinalizeKeyPair(hKey, 0)
	if err != nil {
		return nil, errors.New("mlkem: key finalization failed")
	}

	// Export the private key blob
	var size uint32
	err = bcrypt.ExportKey(hKey, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_BLOB), nil, &size, 0)
	if err != nil {
		return nil, errors.New("mlkem: failed to get key blob size")
	}

	blob := make([]byte, size)
	err = bcrypt.ExportKey(hKey, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_BLOB), blob, &size, 0)
	if err != nil {
		return nil, errors.New("mlkem: failed to export key")
	}

	return blob, nil
}

// newMLKEMDecapsulationKeyFromBytes creates a decapsulation key blob from raw key bytes.
func newMLKEMDecapsulationKeyFromBytes(paramSet string, keyBytes []byte, magic bcrypt.KeyBlobMagicNumber) ([]byte, error) {
	paramSetUTF16 := utf16FromString(paramSet)
	paramSetBytes := make([]byte, len(paramSetUTF16)*2)
	for i, v := range paramSetUTF16 {
		putUint16LE(paramSetBytes[i*2:], v)
	}

	blob := make([]byte, 12+len(paramSetBytes)+len(keyBytes))
	putUint32LE(blob[0:4], uint32(magic))
	putUint32LE(blob[4:8], uint32(len(paramSetBytes))) // cbParameterSet
	putUint32LE(blob[8:12], uint32(len(keyBytes)))     // cbKey
	copy(blob[12:], paramSetBytes)
	copy(blob[12+len(paramSetBytes):], keyBytes)

	return blob, nil
}

// newMLKEMEncapsulationKeyFromBytes creates an encapsulation key blob from raw key bytes.
func newMLKEMEncapsulationKeyFromBytes(paramSet string, keyBytes []byte, magic bcrypt.KeyBlobMagicNumber) ([]byte, error) {
	paramSetUTF16 := utf16FromString(paramSet)
	paramSetBytes := make([]byte, len(paramSetUTF16)*2)
	for i, v := range paramSetUTF16 {
		putUint16LE(paramSetBytes[i*2:], v)
	}

	blob := make([]byte, 12+len(paramSetBytes)+len(keyBytes))
	putUint32LE(blob[0:4], uint32(magic))
	putUint32LE(blob[4:8], uint32(len(paramSetBytes))) // cbParameterSet
	putUint32LE(blob[8:12], uint32(len(keyBytes)))     // cbKey
	copy(blob[12:], paramSetBytes)
	copy(blob[12+len(paramSetBytes):], keyBytes)

	return blob, nil
}

// extractMLKEMKeyBytes extracts the raw key bytes from a blob.
func extractMLKEMKeyBytes(blob []byte) []byte {
	if len(blob) < 12 {
		return nil
	}
	cbParameterSet := getUint32LE(blob[4:8])
	cbKey := getUint32LE(blob[8:12])
	headerSize := 12 + int(cbParameterSet)
	if len(blob) < headerSize+int(cbKey) {
		return nil
	}
	return blob[headerSize : headerSize+int(cbKey)]
}

// DecapsulationKeyMLKEM768 is the secret key used to decapsulate a shared key
// from a ciphertext. It includes various precomputed values.
type DecapsulationKeyMLKEM768 [decapsulationKeyBlobSizeMLKEM768]byte

// GenerateKeyMLKEM768 generates a new decapsulation key, drawing random bytes from
// the default crypto/rand source. The decapsulation key must be kept secret.
func GenerateKeyMLKEM768() (DecapsulationKeyMLKEM768, error) {
	blob, err := generateMLKEMKey(bcrypt.MLKEM_PARAMETER_SET_768)
	if err != nil {
		return DecapsulationKeyMLKEM768{}, err
	}
	var dk DecapsulationKeyMLKEM768
	copy(dk[:], blob)
	return dk, nil
}

// NewDecapsulationKeyMLKEM768 expands a decapsulation key from a 64-byte seed in the
// "d || z" form. The seed must be uniformly random.
func NewDecapsulationKeyMLKEM768(seed []byte) (DecapsulationKeyMLKEM768, error) {
	// The input is raw key bytes extracted from a blob (returned by Bytes())
	// We need to construct the full blob with header
	if len(seed) != decapsulationKeySizeMLKEM768 {
		return DecapsulationKeyMLKEM768{}, errors.New("mlkem: invalid decapsulation key size")
	}

	blob, err := newMLKEMDecapsulationKeyFromBytes(bcrypt.MLKEM_PARAMETER_SET_768, seed, bcrypt.MLKEM_PRIVATE_MAGIC)
	if err != nil {
		return DecapsulationKeyMLKEM768{}, err
	}

	var dk DecapsulationKeyMLKEM768
	copy(dk[:], blob)
	return dk, nil
}

// Bytes returns the decapsulation key as a 64-byte seed in the "d || z" form.
//
// The decapsulation key must be kept secret.
func (dk DecapsulationKeyMLKEM768) Bytes() []byte {
	return extractMLKEMKeyBytes(dk[:])
}

// Decapsulate generates a shared key from a ciphertext and a decapsulation
// key. If the ciphertext is not valid, Decapsulate returns an error.
//
// The shared key must be kept secret.
func (dk DecapsulationKeyMLKEM768) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	if len(ciphertext) != ciphertextSizeMLKEM768 {
		return nil, errors.New("mlkem: invalid ciphertext size")
	}

	alg, err := loadMLKEM()
	if err != nil {
		return nil, errors.New("mlkem: failed to open algorithm provider")
	}

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(alg.handle, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_BLOB), &hKey, dk[:], 0)
	if err != nil {
		return nil, fmt.Errorf("mlkem: failed to import key: %w", err)
	}
	defer bcrypt.DestroyKey(hKey)

	sharedKey = make([]byte, sharedKeySizeMLKEM)
	var cbResult uint32

	err = bcrypt.Decapsulate(hKey, ciphertext, sharedKey, &cbResult, 0)
	if err != nil {
		return nil, fmt.Errorf("mlkem: decapsulation failed: %w", err)
	}
	runtime.KeepAlive(dk)
	return sharedKey[:cbResult], nil
}

// EncapsulationKey returns the public encapsulation key necessary to produce
// ciphertexts.
func (dk DecapsulationKeyMLKEM768) EncapsulationKey() EncapsulationKeyMLKEM768 {
	alg, err := loadMLKEM()
	if err != nil {
		panic(err)
	}

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(alg.handle, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_BLOB), &hKey, dk[:], 0)
	if err != nil {
		panic(err)
	}
	defer bcrypt.DestroyKey(hKey)

	// Export the public key blob
	var size uint32
	err = bcrypt.ExportKey(hKey, 0, utf16PtrFromString(bcrypt.MLKEM_PUBLIC_BLOB), nil, &size, 0)
	if err != nil {
		panic(err)
	}

	pubBlob := make([]byte, size)
	err = bcrypt.ExportKey(hKey, 0, utf16PtrFromString(bcrypt.MLKEM_PUBLIC_BLOB), pubBlob, &size, 0)
	if err != nil {
		panic(err)
	}

	runtime.KeepAlive(dk)
	var ek EncapsulationKeyMLKEM768
	copy(ek[:], pubBlob)
	return ek
}

// An EncapsulationKeyMLKEM768 is the public key used to produce ciphertexts to be
// decapsulated by the corresponding DecapsulationKeyMLKEM768.
type EncapsulationKeyMLKEM768 [encapsulationKeyBlobSizeMLKEM768]byte

// NewEncapsulationKeyMLKEM768 parses an encapsulation key from its encoded form. If
// the encapsulation key is not valid, NewEncapsulationKeyMLKEM768 returns an error.
func NewEncapsulationKeyMLKEM768(encapsulationKey []byte) (EncapsulationKeyMLKEM768, error) {
	if len(encapsulationKey) != encapsulationKeySizeMLKEM768 {
		return EncapsulationKeyMLKEM768{}, errors.New("mlkem: invalid encapsulation key size")
	}

	blob, err := newMLKEMEncapsulationKeyFromBytes(bcrypt.MLKEM_PARAMETER_SET_768, encapsulationKey, bcrypt.MLKEM_PUBLIC_MAGIC)
	if err != nil {
		return EncapsulationKeyMLKEM768{}, err
	}

	var ek EncapsulationKeyMLKEM768
	copy(ek[:], blob)
	return ek, nil
}

// Bytes returns the encapsulation key as a byte slice.
func (ek EncapsulationKeyMLKEM768) Bytes() []byte {
	keyBytes := extractMLKEMKeyBytes(ek[:])
	if keyBytes == nil {
		panic("mlkem: invalid blob size")
	}
	return keyBytes
}

// Encapsulate generates a shared key and an associated ciphertext from an
// encapsulation key, drawing random bytes from the default crypto/rand source.
//
// The shared key must be kept secret.
func (ek EncapsulationKeyMLKEM768) Encapsulate() (sharedKey, ciphertext []byte) {
	alg, err := loadMLKEM()
	if err != nil {
		panic(err)
	}

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(alg.handle, 0, utf16PtrFromString(bcrypt.MLKEM_PUBLIC_BLOB), &hKey, ek[:], 0)
	if err != nil {
		panic(err)
	}
	defer bcrypt.DestroyKey(hKey)

	sharedKey = make([]byte, sharedKeySizeMLKEM)
	var cbResult uint32
	ciphertext = make([]byte, ciphertextSizeMLKEM768)
	var cbCiphertextResult uint32

	err = bcrypt.Encapsulate(hKey, sharedKey, &cbResult, ciphertext, &cbCiphertextResult, 0)
	if err != nil {
		panic(err)
	}

	runtime.KeepAlive(ek)
	return sharedKey[:cbResult], ciphertext[:cbCiphertextResult]
}

// DecapsulationKeyMLKEM1024 is the secret key used to decapsulate a shared key
// from a ciphertext. It includes various precomputed values.
type DecapsulationKeyMLKEM1024 [decapsulationKeyBlobSizeMLKEM1024]byte

// GenerateKeyMLKEM1024 generates a new decapsulation key, drawing random bytes from
// the default crypto/rand source. The decapsulation key must be kept secret.
func GenerateKeyMLKEM1024() (DecapsulationKeyMLKEM1024, error) {
	blob, err := generateMLKEMKey(bcrypt.MLKEM_PARAMETER_SET_1024)
	if err != nil {
		return DecapsulationKeyMLKEM1024{}, err
	}
	var dk DecapsulationKeyMLKEM1024
	copy(dk[:], blob)
	return dk, nil
}

// NewDecapsulationKeyMLKEM1024 expands a decapsulation key from a 64-byte seed in the
// "d || z" form. The seed must be uniformly random.
func NewDecapsulationKeyMLKEM1024(seed []byte) (DecapsulationKeyMLKEM1024, error) {
	// The input is raw key bytes extracted from a blob (returned by Bytes())
	// We need to construct the full blob with header
	if len(seed) != decapsulationKeySizeMLKEM1024 {
		return DecapsulationKeyMLKEM1024{}, errors.New("mlkem: invalid decapsulation key size")
	}

	blob, err := newMLKEMDecapsulationKeyFromBytes(bcrypt.MLKEM_PARAMETER_SET_1024, seed, bcrypt.MLKEM_PRIVATE_MAGIC)
	if err != nil {
		return DecapsulationKeyMLKEM1024{}, err
	}

	var dk DecapsulationKeyMLKEM1024
	copy(dk[:], blob)
	return dk, nil
}

// Bytes returns the decapsulation key as a 64-byte seed in the "d || z" form.
//
// The decapsulation key must be kept secret.
func (dk DecapsulationKeyMLKEM1024) Bytes() []byte {
	return extractMLKEMKeyBytes(dk[:])
}

// Decapsulate generates a shared key from a ciphertext and a decapsulation
// key. If the ciphertext is not valid, Decapsulate returns an error.
//
// The shared key must be kept secret.
func (dk DecapsulationKeyMLKEM1024) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	if len(ciphertext) != ciphertextSizeMLKEM1024 {
		return nil, errors.New("mlkem: invalid ciphertext size")
	}

	alg, err := loadMLKEM()
	if err != nil {
		return nil, errors.New("mlkem: failed to open algorithm provider")
	}

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(alg.handle, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_BLOB), &hKey, dk[:], 0)
	if err != nil {
		return nil, errors.New("mlkem: failed to import key")
	}
	defer bcrypt.DestroyKey(hKey)

	sharedKey = make([]byte, sharedKeySizeMLKEM)
	var cbResult uint32

	err = bcrypt.Decapsulate(hKey, ciphertext, sharedKey, &cbResult, 0)
	if err != nil {
		return nil, errors.New("mlkem: decapsulation failed")
	}
	runtime.KeepAlive(dk)
	return sharedKey[:cbResult], nil
}

// EncapsulationKey returns the public encapsulation key necessary to produce
// ciphertexts.
func (dk DecapsulationKeyMLKEM1024) EncapsulationKey() EncapsulationKeyMLKEM1024 {
	alg, err := loadMLKEM()
	if err != nil {
		panic(err)
	}

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(alg.handle, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_BLOB), &hKey, dk[:], 0)
	if err != nil {
		panic(err)
	}
	defer bcrypt.DestroyKey(hKey)

	// Export the public key blob
	var size uint32
	err = bcrypt.ExportKey(hKey, 0, utf16PtrFromString(bcrypt.MLKEM_PUBLIC_BLOB), nil, &size, 0)
	if err != nil {
		panic(err)
	}

	pubBlob := make([]byte, size)
	err = bcrypt.ExportKey(hKey, 0, utf16PtrFromString(bcrypt.MLKEM_PUBLIC_BLOB), pubBlob, &size, 0)
	if err != nil {
		panic(err)
	}

	runtime.KeepAlive(dk)
	var ek EncapsulationKeyMLKEM1024
	copy(ek[:], pubBlob)
	return ek
}

// An EncapsulationKeyMLKEM1024 is the public key used to produce ciphertexts to be
// decapsulated by the corresponding DecapsulationKeyMLKEM1024.
type EncapsulationKeyMLKEM1024 [encapsulationKeyBlobSizeMLKEM1024]byte

// NewEncapsulationKeyMLKEM1024 parses an encapsulation key from its encoded form. If
// the encapsulation key is not valid, NewEncapsulationKeyMLKEM1024 returns an error.
func NewEncapsulationKeyMLKEM1024(encapsulationKey []byte) (EncapsulationKeyMLKEM1024, error) {
	if len(encapsulationKey) != encapsulationKeySizeMLKEM1024 {
		return EncapsulationKeyMLKEM1024{}, errors.New("mlkem: invalid encapsulation key size")
	}

	blob, err := newMLKEMEncapsulationKeyFromBytes(bcrypt.MLKEM_PARAMETER_SET_1024, encapsulationKey, bcrypt.MLKEM_PUBLIC_MAGIC)
	if err != nil {
		return EncapsulationKeyMLKEM1024{}, err
	}

	var ek EncapsulationKeyMLKEM1024
	copy(ek[:], blob)
	return ek, nil
}

// Bytes returns the encapsulation key as a byte slice.
func (ek EncapsulationKeyMLKEM1024) Bytes() []byte {
	keyBytes := extractMLKEMKeyBytes(ek[:])
	if keyBytes == nil {
		panic("mlkem: invalid blob size")
	}
	return keyBytes
}

// Encapsulate generates a shared key and an associated ciphertext from an
// encapsulation key, drawing random bytes from the default crypto/rand source.
//
// The shared key must be kept secret.
func (ek EncapsulationKeyMLKEM1024) Encapsulate() (sharedKey, ciphertext []byte) {
	alg, err := loadMLKEM()
	if err != nil {
		panic(err)
	}

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(alg.handle, 0, utf16PtrFromString(bcrypt.MLKEM_PUBLIC_BLOB), &hKey, ek[:], 0)
	if err != nil {
		panic(err)
	}
	defer bcrypt.DestroyKey(hKey)

	sharedKey = make([]byte, sharedKeySizeMLKEM)
	var cbResult uint32
	ciphertext = make([]byte, ciphertextSizeMLKEM1024)
	var cbCiphertextResult uint32

	err = bcrypt.Encapsulate(hKey, sharedKey, &cbResult, ciphertext, &cbCiphertextResult, 0)
	if err != nil {
		panic(err)
	}

	runtime.KeepAlive(ek)
	return sharedKey[:cbResult], ciphertext[:cbCiphertextResult]
}
