// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"errors"

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

	// ciphertextSizeMLKEM1024 is the size of a ciphertext produced by ML-KEM-1024.
	ciphertextSizeMLKEM1024 = 1568

	// encapsulationKeySizeMLKEM1024 is the size of an ML-KEM-1024 encapsulation key (raw key material).
	encapsulationKeySizeMLKEM1024 = 1568
)

const (
	sizeOfPrivateSeedMLKEM1024 = 4 + 4 + 4 + 10 + seedSizeMLKEM                 // dwMagic (4) + cbParameterSet (4) + cbKey (4) + ParameterSet (10 "1024\0") + Key (64)
	sizeOfPublicKeyMLKEM1024   = 4 + 4 + 4 + 10 + encapsulationKeySizeMLKEM1024 // dwMagic (4) + cbParameterSet (4) + cbKey (4) + ParameterSet (10 "1024\0") + Key (1568)
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

// generateMLKEMKey generates a new ML-KEM key pair with the specified parameter set
// and writes the raw key bytes (not the blob) into dst.
func generateMLKEMKey(paramSet string, dst []byte) error {
	alg, err := loadMLKEM()
	if err != nil {
		return err
	}

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.GenerateKeyPair(alg.handle, &hKey, 0, 0)
	if err != nil {
		return err
	}
	defer bcrypt.DestroyKey(hKey)

	// Set the parameter set
	if err := setString(bcrypt.HANDLE(hKey), bcrypt.PARAMETER_SET_NAME, paramSet); err != nil {
		return err
	}

	err = bcrypt.FinalizeKeyPair(hKey, 0)
	if err != nil {
		return err
	}

	// Export the private key blob
	blob := make([]byte, sizeOfPrivateSeedMLKEM1024) // use the larger size to be safe and avoid an allocation
	var size uint32
	err = bcrypt.ExportKey(hKey, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_SEED_BLOB), blob, &size, 0)
	if err != nil {
		return err
	}

	// Extract raw key bytes into destination
	return extractMLKEMKeyBytes(dst, blob[:size])
}

// newMLKEMKeyBlob creates a key blob from raw key bytes.
func newMLKEMKeyBlob(dst []byte, paramSet string, keyBytes []byte, magic bcrypt.KeyBlobMagicNumber) error {
	paramSetUTF16 := utf16FromString(paramSet)
	paramSetByteLen := len(paramSetUTF16) * 2

	if len(dst) < 12+paramSetByteLen+len(keyBytes) {
		return errors.New("mlkem: destination blob too small")
	}
	putUint32LE(dst[0:4], uint32(magic))
	putUint32LE(dst[4:8], uint32(paramSetByteLen)) // cbParameterSet
	putUint32LE(dst[8:12], uint32(len(keyBytes)))  // cbKey
	for i, v := range paramSetUTF16 {
		putUint16LE(dst[12+i*2:], v)
	}
	copy(dst[12+paramSetByteLen:], keyBytes)

	return nil
}

// extractMLKEMKeyBytes extracts the raw key bytes from a blob into the provided destination slice.
func extractMLKEMKeyBytes(dst, blob []byte) error {
	if len(blob) < 12 {
		return errors.New("mlkem: blob too small")
	}
	cbParameterSet := getUint32LE(blob[4:8])
	cbKey := getUint32LE(blob[8:12])
	headerSize := 12 + int(cbParameterSet)
	if len(blob) < headerSize+int(cbKey) {
		return errors.New("mlkem: invalid blob size")
	}
	if len(dst) != int(cbKey) {
		return errors.New("mlkem: destination size mismatch")
	}
	copy(dst, blob[headerSize:headerSize+int(cbKey)])
	return nil
}

// mlkemDecapsulate is a shared helper for decapsulating with ML-KEM keys.
func mlkemDecapsulate(paramSet string, seed []byte, ciphertext []byte, expectedCiphertextSize int) ([]byte, error) {
	if len(ciphertext) != expectedCiphertextSize {
		return nil, errors.New("mlkem: invalid ciphertext size")
	}

	alg, err := loadMLKEM()
	if err != nil {
		return nil, err
	}

	// Construct blob from seed
	blob := make([]byte, sizeOfPrivateSeedMLKEM1024) // use the larger size to be safe and avoid an allocation
	err = newMLKEMKeyBlob(blob, paramSet, seed, bcrypt.MLKEM_PRIVATE_SEED_MAGIC)
	if err != nil {
		return nil, err
	}

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(alg.handle, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_SEED_BLOB), &hKey, blob, 0)
	if err != nil {
		return nil, err
	}
	defer bcrypt.DestroyKey(hKey)

	sharedKey := make([]byte, sharedKeySizeMLKEM)
	var cbResult uint32

	err = bcrypt.Decapsulate(hKey, ciphertext, sharedKey, &cbResult, 0)
	if err != nil {
		return nil, err
	}
	return sharedKey[:cbResult], nil
}

// mlkemEncapsulationKey is a shared helper for extracting the encapsulation key from a decapsulation key.
func mlkemEncapsulationKey(paramSet string, seed []byte, dst []byte) {
	alg, err := loadMLKEM()
	if err != nil {
		panic(err)
	}

	// Construct blob from seed
	blob := make([]byte, sizeOfPrivateSeedMLKEM1024) // use the larger size to be safe and avoid an allocation
	err = newMLKEMKeyBlob(blob, paramSet, seed, bcrypt.MLKEM_PRIVATE_SEED_MAGIC)
	if err != nil {
		panic(err)
	}

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(alg.handle, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_SEED_BLOB), &hKey, blob, 0)
	if err != nil {
		panic(err)
	}
	defer bcrypt.DestroyKey(hKey)

	// Export the public key blob
	pubBlob := make([]byte, sizeOfPublicKeyMLKEM1024) // use the larger size to be safe and avoid an allocation
	var size uint32
	err = bcrypt.ExportKey(hKey, 0, utf16PtrFromString(bcrypt.MLKEM_PUBLIC_BLOB), pubBlob, &size, 0)
	if err != nil {
		panic(err)
	}
	// Extract raw public key bytes from blob
	if err := extractMLKEMKeyBytes(dst, pubBlob[:size]); err != nil {
		panic(err)
	}
}

// mlkemEncapsulate is a shared helper for encapsulating with ML-KEM keys.
func mlkemEncapsulate(paramSet string, keyBytes []byte, expectedCiphertextSize int) ([]byte, []byte) {
	alg, err := loadMLKEM()
	if err != nil {
		panic(err)
	}

	// Construct blob from raw key bytes
	blob := make([]byte, sizeOfPublicKeyMLKEM1024) // use the larger size to be safe and avoid an allocation
	err = newMLKEMKeyBlob(blob, paramSet, keyBytes, bcrypt.MLKEM_PUBLIC_MAGIC)
	if err != nil {
		panic(err)
	}

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(alg.handle, 0, utf16PtrFromString(bcrypt.MLKEM_PUBLIC_BLOB), &hKey, blob, 0)
	if err != nil {
		panic(err)
	}
	defer bcrypt.DestroyKey(hKey)

	sharedKey := make([]byte, sharedKeySizeMLKEM)
	var cbResult uint32
	ciphertext := make([]byte, expectedCiphertextSize)
	var cbCiphertextResult uint32

	err = bcrypt.Encapsulate(hKey, sharedKey, &cbResult, ciphertext, &cbCiphertextResult, 0)
	if err != nil {
		panic(err)
	}

	return sharedKey[:cbResult], ciphertext[:cbCiphertextResult]
}

// DecapsulationKeyMLKEM768 is the secret key used to decapsulate a shared key
// from a ciphertext. It includes various precomputed values.
type DecapsulationKeyMLKEM768 [seedSizeMLKEM]byte

// GenerateKeyMLKEM768 generates a new decapsulation key, drawing random bytes from
// the default crypto/rand source. The decapsulation key must be kept secret.
func GenerateKeyMLKEM768() (DecapsulationKeyMLKEM768, error) {
	var dk DecapsulationKeyMLKEM768
	if err := generateMLKEMKey(bcrypt.MLKEM_PARAMETER_SET_768, dk[:]); err != nil {
		return DecapsulationKeyMLKEM768{}, err
	}
	return dk, nil
}

// NewDecapsulationKeyMLKEM768 constructs a decapsulation key from its serialized form.
func NewDecapsulationKeyMLKEM768(seed []byte) (DecapsulationKeyMLKEM768, error) {
	if len(seed) != seedSizeMLKEM {
		return DecapsulationKeyMLKEM768{}, errors.New("mlkem: invalid decapsulation key size")
	}

	var dk DecapsulationKeyMLKEM768
	copy(dk[:], seed)
	return dk, nil
}

// Bytes returns the decapsulation key in its serialized form.
//
// The decapsulation key must be kept secret.
func (dk DecapsulationKeyMLKEM768) Bytes() []byte {
	return dk[:]
}

// Decapsulate generates a shared key from a ciphertext and a decapsulation
// key. If the ciphertext is not valid, Decapsulate returns an error.
//
// The shared key must be kept secret.
func (dk DecapsulationKeyMLKEM768) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	return mlkemDecapsulate(bcrypt.MLKEM_PARAMETER_SET_768, dk[:], ciphertext, ciphertextSizeMLKEM768)
}

// EncapsulationKey returns the public encapsulation key necessary to produce
// ciphertexts.
func (dk DecapsulationKeyMLKEM768) EncapsulationKey() EncapsulationKeyMLKEM768 {
	var ek EncapsulationKeyMLKEM768
	mlkemEncapsulationKey(bcrypt.MLKEM_PARAMETER_SET_768, dk[:], ek[:])
	return ek
}

// An EncapsulationKeyMLKEM768 is the public key used to produce ciphertexts to be
// decapsulated by the corresponding DecapsulationKeyMLKEM768.
type EncapsulationKeyMLKEM768 [encapsulationKeySizeMLKEM768]byte

// NewEncapsulationKeyMLKEM768 parses an encapsulation key from its encoded form. If
// the encapsulation key is not valid, NewEncapsulationKeyMLKEM768 returns an error.
func NewEncapsulationKeyMLKEM768(encapsulationKey []byte) (EncapsulationKeyMLKEM768, error) {
	if len(encapsulationKey) != encapsulationKeySizeMLKEM768 {
		return EncapsulationKeyMLKEM768{}, errors.New("mlkem: invalid encapsulation key size")
	}

	var ek EncapsulationKeyMLKEM768
	copy(ek[:], encapsulationKey)
	return ek, nil
}

// Bytes returns the encapsulation key as a byte slice.
func (ek EncapsulationKeyMLKEM768) Bytes() []byte {
	return ek[:]
}

// Encapsulate generates a shared key and an associated ciphertext from an
// encapsulation key, drawing random bytes from the default crypto/rand source.
//
// The shared key must be kept secret.
func (ek EncapsulationKeyMLKEM768) Encapsulate() (sharedKey, ciphertext []byte) {
	return mlkemEncapsulate(bcrypt.MLKEM_PARAMETER_SET_768, ek[:], ciphertextSizeMLKEM768)
}

// DecapsulationKeyMLKEM1024 is the secret key used to decapsulate a shared key
// from a ciphertext. It includes various precomputed values.
type DecapsulationKeyMLKEM1024 [seedSizeMLKEM]byte

// GenerateKeyMLKEM1024 generates a new decapsulation key, drawing random bytes from
// the default crypto/rand source. The decapsulation key must be kept secret.
func GenerateKeyMLKEM1024() (DecapsulationKeyMLKEM1024, error) {
	var dk DecapsulationKeyMLKEM1024
	if err := generateMLKEMKey(bcrypt.MLKEM_PARAMETER_SET_1024, dk[:]); err != nil {
		return DecapsulationKeyMLKEM1024{}, err
	}
	return dk, nil
}

// NewDecapsulationKeyMLKEM1024 constructs a decapsulation key from its serialized form.
func NewDecapsulationKeyMLKEM1024(seed []byte) (DecapsulationKeyMLKEM1024, error) {
	if len(seed) != seedSizeMLKEM {
		return DecapsulationKeyMLKEM1024{}, errors.New("mlkem: invalid decapsulation key size")
	}

	var dk DecapsulationKeyMLKEM1024
	copy(dk[:], seed)
	return dk, nil
}

// Bytes returns the decapsulation key in its serialized form.
//
// The decapsulation key must be kept secret.
func (dk DecapsulationKeyMLKEM1024) Bytes() []byte {
	return dk[:]
}

// Decapsulate generates a shared key from a ciphertext and a decapsulation
// key. If the ciphertext is not valid, Decapsulate returns an error.
//
// The shared key must be kept secret.
func (dk DecapsulationKeyMLKEM1024) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	return mlkemDecapsulate(bcrypt.MLKEM_PARAMETER_SET_1024, dk[:], ciphertext, ciphertextSizeMLKEM1024)
}

// EncapsulationKey returns the public encapsulation key necessary to produce
// ciphertexts.
func (dk DecapsulationKeyMLKEM1024) EncapsulationKey() EncapsulationKeyMLKEM1024 {
	var ek EncapsulationKeyMLKEM1024
	mlkemEncapsulationKey(bcrypt.MLKEM_PARAMETER_SET_1024, dk[:], ek[:])
	return ek
}

// An EncapsulationKeyMLKEM1024 is the public key used to produce ciphertexts to be
// decapsulated by the corresponding DecapsulationKeyMLKEM1024.
type EncapsulationKeyMLKEM1024 [encapsulationKeySizeMLKEM1024]byte

// NewEncapsulationKeyMLKEM1024 parses an encapsulation key from its encoded form. If
// the encapsulation key is not valid, NewEncapsulationKeyMLKEM1024 returns an error.
func NewEncapsulationKeyMLKEM1024(encapsulationKey []byte) (EncapsulationKeyMLKEM1024, error) {
	if len(encapsulationKey) != encapsulationKeySizeMLKEM1024 {
		return EncapsulationKeyMLKEM1024{}, errors.New("mlkem: invalid encapsulation key size")
	}

	var ek EncapsulationKeyMLKEM1024
	copy(ek[:], encapsulationKey)
	return ek, nil
}

// Bytes returns the encapsulation key as a byte slice.
func (ek EncapsulationKeyMLKEM1024) Bytes() []byte {
	return ek[:]
}

// Encapsulate generates a shared key and an associated ciphertext from an
// encapsulation key, drawing random bytes from the default crypto/rand source.
//
// The shared key must be kept secret.
func (ek EncapsulationKeyMLKEM1024) Encapsulate() (sharedKey, ciphertext []byte) {
	return mlkemEncapsulate(bcrypt.MLKEM_PARAMETER_SET_1024, ek[:], ciphertextSizeMLKEM1024)
}
