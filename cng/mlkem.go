// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"encoding/binary"
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

	// encapsulationKeySizeMLKEM768 is the size of an ML-KEM-768 encapsulation key.
	encapsulationKeySizeMLKEM768 = 1184

	// decapsulationKeySizeMLKEM768 is the size of the ML-KEM-768 decapsulation key data
	// (Windows blob format, without header).
	decapsulationKeySizeMLKEM768 = 2400

	// ciphertextSizeMLKEM1024 is the size of a ciphertext produced by ML-KEM-1024.
	ciphertextSizeMLKEM1024 = 1568

	// encapsulationKeySizeMLKEM1024 is the size of an ML-KEM-1024 encapsulation key.
	encapsulationKeySizeMLKEM1024 = 1568

	// decapsulationKeySizeMLKEM1024 is the size of the ML-KEM-1024 decapsulation key data
	// (Windows blob format, without header).
	decapsulationKeySizeMLKEM1024 = 3168
)

// SupportsMLKEM returns true if ML-KEM is supported on this platform.
// ML-KEM is supported on Windows 11 24H2/25H2 and Windows Server 2025 and later.
func SupportsMLKEM() bool {
	// Try to open the MLKEM algorithm provider to check if it's supported
	var hAlg bcrypt.ALG_HANDLE
	err := bcrypt.OpenAlgorithmProvider(&hAlg, utf16PtrFromString(bcrypt.MLKEM_ALGORITHM), nil, 0)
	if err != nil {
		return false
	}
	bcrypt.CloseAlgorithmProvider(hAlg, 0)
	return true
}

// DecapsulationKeyMLKEM768 is the secret key used to decapsulate a shared key
// from a ciphertext. It includes various precomputed values.
type DecapsulationKeyMLKEM768 struct {
	privBlob []byte // The full private key blob from Windows CNG
}

// GenerateKeyMLKEM768 generates a new decapsulation key, drawing random bytes from
// the default crypto/rand source. The decapsulation key must be kept secret.
func GenerateKeyMLKEM768() (DecapsulationKeyMLKEM768, error) {
	// Open the ML-KEM algorithm provider
	var hAlg bcrypt.ALG_HANDLE
	err := bcrypt.OpenAlgorithmProvider(&hAlg, utf16PtrFromString(bcrypt.MLKEM_ALGORITHM), nil, 0)
	if err != nil {
		return DecapsulationKeyMLKEM768{}, errors.New("mlkem: failed to open algorithm provider")
	}
	defer bcrypt.CloseAlgorithmProvider(hAlg, 0)

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.GenerateKeyPair(hAlg, &hKey, 0, 0)
	if err != nil {
		return DecapsulationKeyMLKEM768{}, errors.New("mlkem: key generation failed")
	}
	defer bcrypt.DestroyKey(hKey)

	// Set the parameter set to ML-KEM-768
	paramSet := utf16FromString(bcrypt.MLKEM_PARAMETER_SET_768)
	paramSetBytes := make([]byte, len(paramSet)*2)
	for i, v := range paramSet {
		paramSetBytes[i*2] = byte(v)
		paramSetBytes[i*2+1] = byte(v >> 8)
	}
	err = bcrypt.SetProperty(bcrypt.HANDLE(hKey), utf16PtrFromString(bcrypt.PARAMETER_SET_NAME), paramSetBytes, 0)
	if err != nil {
		return DecapsulationKeyMLKEM768{}, errors.New("mlkem: failed to set parameter set")
	}

	err = bcrypt.FinalizeKeyPair(hKey, 0)
	if err != nil {
		return DecapsulationKeyMLKEM768{}, errors.New("mlkem: key finalization failed")
	}

	// Export the private key blob
	var size uint32
	err = bcrypt.ExportKey(hKey, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_BLOB), nil, &size, 0)
	if err != nil {
		return DecapsulationKeyMLKEM768{}, errors.New("mlkem: failed to get key blob size")
	}

	blob := make([]byte, size)
	err = bcrypt.ExportKey(hKey, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_BLOB), blob, &size, 0)
	if err != nil {
		return DecapsulationKeyMLKEM768{}, errors.New("mlkem: failed to export key")
	}

	return DecapsulationKeyMLKEM768{privBlob: blob}, nil
}

// NewDecapsulationKeyMLKEM768 expands a decapsulation key from a 64-byte seed in the
// "d || z" form. The seed must be uniformly random.
func NewDecapsulationKeyMLKEM768(seed []byte) (DecapsulationKeyMLKEM768, error) {
	// Windows CNG implementation: we store the full private key blob, not just a seed
	// The input here is actually the full blob (returned by Bytes()), not a seed
	if len(seed) != decapsulationKeySizeMLKEM768 {
		return DecapsulationKeyMLKEM768{}, errors.New("mlkem: invalid decapsulation key size")
	}

	// Create a MLKEM_KEY_BLOB with the raw key data
	// Format: Magic (4) + cbParameterSet (4) + cbKey (4) + ParameterSet (UTF-16 "768\0") + Key data
	paramSet := bcrypt.MLKEM_PARAMETER_SET_768 // utf16FromString adds the null terminator
	paramSetUTF16 := utf16FromString(paramSet)
	paramSetBytes := make([]byte, len(paramSetUTF16)*2)
	for i, v := range paramSetUTF16 {
		binary.LittleEndian.PutUint16(paramSetBytes[i*2:], v)
	}

	blob := make([]byte, 12+len(paramSetBytes)+len(seed))
	binary.LittleEndian.PutUint32(blob[0:4], uint32(bcrypt.MLKEM_PRIVATE_MAGIC))
	binary.LittleEndian.PutUint32(blob[4:8], uint32(len(paramSetBytes))) // cbParameterSet
	binary.LittleEndian.PutUint32(blob[8:12], uint32(len(seed))) // cbKey
	copy(blob[12:], paramSetBytes)
	copy(blob[12+len(paramSetBytes):], seed)

	return DecapsulationKeyMLKEM768{privBlob: blob}, nil
}

// Bytes returns the decapsulation key as a 64-byte seed in the "d || z" form.
//
// The decapsulation key must be kept secret.
func (dk DecapsulationKeyMLKEM768) Bytes() []byte {
	// Windows stores keys as blobs, not seeds
	// Extract the actual private key data from the blob (skip header and parameter set)
	if len(dk.privBlob) < 12 {
		return nil
	}
	cbParameterSet := binary.LittleEndian.Uint32(dk.privBlob[4:8])
	cbKey := binary.LittleEndian.Uint32(dk.privBlob[8:12])
	headerSize := 12 + int(cbParameterSet)
	if len(dk.privBlob) < headerSize+int(cbKey) {
		return nil
	}
	return dk.privBlob[headerSize : headerSize+int(cbKey)]
}

// Decapsulate generates a shared key from a ciphertext and a decapsulation
// key. If the ciphertext is not valid, Decapsulate returns an error.
//
// The shared key must be kept secret.
func (dk DecapsulationKeyMLKEM768) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	if len(ciphertext) != ciphertextSizeMLKEM768 {
		return nil, errors.New("mlkem: invalid ciphertext size")
	}

	// Open the ML-KEM algorithm provider
	var hAlg bcrypt.ALG_HANDLE
	err = bcrypt.OpenAlgorithmProvider(&hAlg, utf16PtrFromString(bcrypt.MLKEM_ALGORITHM), nil, 0)
	if err != nil {
		return nil, errors.New("mlkem: failed to open algorithm provider")
	}
	defer bcrypt.CloseAlgorithmProvider(hAlg, 0)

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(hAlg, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_BLOB), &hKey, dk.privBlob, 0)
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
	// Open the ML-KEM algorithm provider
	var hAlg bcrypt.ALG_HANDLE
	err := bcrypt.OpenAlgorithmProvider(&hAlg, utf16PtrFromString(bcrypt.MLKEM_ALGORITHM), nil, 0)
	if err != nil {
		panic(err)
	}
	defer bcrypt.CloseAlgorithmProvider(hAlg, 0)

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(hAlg, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_BLOB), &hKey, dk.privBlob, 0)
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
	return EncapsulationKeyMLKEM768{blob: pubBlob}
}

// An EncapsulationKeyMLKEM768 is the public key used to produce ciphertexts to be
// decapsulated by the corresponding DecapsulationKeyMLKEM768.
type EncapsulationKeyMLKEM768 struct {
	blob []byte
}

// NewEncapsulationKeyMLKEM768 parses an encapsulation key from its encoded form. If
// the encapsulation key is not valid, NewEncapsulationKeyMLKEM768 returns an error.
func NewEncapsulationKeyMLKEM768(encapsulationKey []byte) (EncapsulationKeyMLKEM768, error) {
	if len(encapsulationKey) != encapsulationKeySizeMLKEM768 {
		return EncapsulationKeyMLKEM768{}, errors.New("mlkem: invalid encapsulation key size")
	}

	// Create a MLKEM_KEY_BLOB with the raw key data
	// Format: Magic (4) + cbParameterSet (4) + cbKey (4) + ParameterSet (UTF-16 "768\0") + Key data
	paramSet := bcrypt.MLKEM_PARAMETER_SET_768 // utf16FromString adds the null terminator
	paramSetUTF16 := utf16FromString(paramSet)
	paramSetBytes := make([]byte, len(paramSetUTF16)*2)
	for i, v := range paramSetUTF16 {
		binary.LittleEndian.PutUint16(paramSetBytes[i*2:], v)
	}

	blob := make([]byte, 12+len(paramSetBytes)+len(encapsulationKey))
	binary.LittleEndian.PutUint32(blob[0:4], uint32(bcrypt.MLKEM_PUBLIC_MAGIC))
	binary.LittleEndian.PutUint32(blob[4:8], uint32(len(paramSetBytes))) // cbParameterSet
	binary.LittleEndian.PutUint32(blob[8:12], uint32(len(encapsulationKey))) // cbKey
	copy(blob[12:], paramSetBytes)
	copy(blob[12+len(paramSetBytes):], encapsulationKey)

	return EncapsulationKeyMLKEM768{blob: blob}, nil
}

// Bytes returns the encapsulation key as a byte slice.
func (ek EncapsulationKeyMLKEM768) Bytes() []byte {
	// Extract the raw key from the blob, skipping the MLKEM_KEY_BLOB header and parameter set
	// Structure: Magic (4) + cbParameterSet (4) + cbKey (4) + ParameterSet + Key
	if len(ek.blob) < 12 {
		panic("mlkem: invalid blob size")
	}
	cbParameterSet := binary.LittleEndian.Uint32(ek.blob[4:8])
	cbKey := binary.LittleEndian.Uint32(ek.blob[8:12])
	headerSize := 12 + int(cbParameterSet)
	if len(ek.blob) < headerSize+int(cbKey) {
		panic("mlkem: invalid blob size")
	}
	return ek.blob[headerSize : headerSize+int(cbKey)]
}

// Encapsulate generates a shared key and an associated ciphertext from an
// encapsulation key, drawing random bytes from the default crypto/rand source.
//
// The shared key must be kept secret.
func (ek EncapsulationKeyMLKEM768) Encapsulate() (sharedKey, ciphertext []byte) {
	// Open the ML-KEM algorithm provider
	var hAlg bcrypt.ALG_HANDLE
	err := bcrypt.OpenAlgorithmProvider(&hAlg, utf16PtrFromString(bcrypt.MLKEM_ALGORITHM), nil, 0)
	if err != nil {
		panic(err)
	}
	defer bcrypt.CloseAlgorithmProvider(hAlg, 0)

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(hAlg, 0, utf16PtrFromString(bcrypt.MLKEM_PUBLIC_BLOB), &hKey, ek.blob, 0)
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
type DecapsulationKeyMLKEM1024 struct {
	privBlob []byte // The full private key blob from Windows CNG
}

// GenerateKeyMLKEM1024 generates a new decapsulation key, drawing random bytes from
// the default crypto/rand source. The decapsulation key must be kept secret.
func GenerateKeyMLKEM1024() (DecapsulationKeyMLKEM1024, error) {
	// Open the ML-KEM algorithm provider
	var hAlg bcrypt.ALG_HANDLE
	err := bcrypt.OpenAlgorithmProvider(&hAlg, utf16PtrFromString(bcrypt.MLKEM_ALGORITHM), nil, 0)
	if err != nil {
		return DecapsulationKeyMLKEM1024{}, errors.New("mlkem: failed to open algorithm provider")
	}
	defer bcrypt.CloseAlgorithmProvider(hAlg, 0)

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.GenerateKeyPair(hAlg, &hKey, 0, 0)
	if err != nil {
		return DecapsulationKeyMLKEM1024{}, errors.New("mlkem: key generation failed")
	}
	defer bcrypt.DestroyKey(hKey)

	// Set the parameter set to ML-KEM-1024
	paramSet := utf16FromString(bcrypt.MLKEM_PARAMETER_SET_1024)
	paramSetBytes := make([]byte, len(paramSet)*2)
	for i, v := range paramSet {
		paramSetBytes[i*2] = byte(v)
		paramSetBytes[i*2+1] = byte(v >> 8)
	}
	err = bcrypt.SetProperty(bcrypt.HANDLE(hKey), utf16PtrFromString(bcrypt.PARAMETER_SET_NAME), paramSetBytes, 0)
	if err != nil {
		return DecapsulationKeyMLKEM1024{}, errors.New("mlkem: failed to set parameter set")
	}

	err = bcrypt.FinalizeKeyPair(hKey, 0)
	if err != nil {
		return DecapsulationKeyMLKEM1024{}, errors.New("mlkem: key finalization failed")
	}

	// Export the private key blob
	var size uint32
	err = bcrypt.ExportKey(hKey, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_BLOB), nil, &size, 0)
	if err != nil {
		return DecapsulationKeyMLKEM1024{}, errors.New("mlkem: failed to get key blob size")
	}

	blob := make([]byte, size)
	err = bcrypt.ExportKey(hKey, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_BLOB), blob, &size, 0)
	if err != nil {
		return DecapsulationKeyMLKEM1024{}, errors.New("mlkem: failed to export key")
	}

	return DecapsulationKeyMLKEM1024{privBlob: blob}, nil
}

// NewDecapsulationKeyMLKEM1024 expands a decapsulation key from a 64-byte seed in the
// "d || z" form. The seed must be uniformly random.
func NewDecapsulationKeyMLKEM1024(seed []byte) (DecapsulationKeyMLKEM1024, error) {
	// Windows CNG implementation: we store the full private key blob, not just a seed
	// The input here is actually the full blob (returned by Bytes()), not a seed
	if len(seed) != decapsulationKeySizeMLKEM1024 {
		return DecapsulationKeyMLKEM1024{}, errors.New("mlkem: invalid decapsulation key size")
	}

	// Create a MLKEM_KEY_BLOB with the raw key data
	// Format: Magic (4) + cbParameterSet (4) + cbKey (4) + ParameterSet (UTF-16 "1024\0") + Key data
	paramSet := bcrypt.MLKEM_PARAMETER_SET_1024 // utf16FromString adds the null terminator
	paramSetUTF16 := utf16FromString(paramSet)
	paramSetBytes := make([]byte, len(paramSetUTF16)*2)
	for i, v := range paramSetUTF16 {
		binary.LittleEndian.PutUint16(paramSetBytes[i*2:], v)
	}

	blob := make([]byte, 12+len(paramSetBytes)+len(seed))
	binary.LittleEndian.PutUint32(blob[0:4], uint32(bcrypt.MLKEM_PRIVATE_MAGIC))
	binary.LittleEndian.PutUint32(blob[4:8], uint32(len(paramSetBytes))) // cbParameterSet
	binary.LittleEndian.PutUint32(blob[8:12], uint32(len(seed))) // cbKey
	copy(blob[12:], paramSetBytes)
	copy(blob[12+len(paramSetBytes):], seed)

	return DecapsulationKeyMLKEM1024{privBlob: blob}, nil
}

// Bytes returns the decapsulation key as a 64-byte seed in the "d || z" form.
//
// The decapsulation key must be kept secret.
func (dk DecapsulationKeyMLKEM1024) Bytes() []byte {
	// Windows stores keys as blobs, not seeds
	// Extract the actual private key data from the blob (skip header and parameter set)
	if len(dk.privBlob) < 12 {
		return nil
	}
	cbParameterSet := binary.LittleEndian.Uint32(dk.privBlob[4:8])
	cbKey := binary.LittleEndian.Uint32(dk.privBlob[8:12])
	headerSize := 12 + int(cbParameterSet)
	if len(dk.privBlob) < headerSize+int(cbKey) {
		return nil
	}
	return dk.privBlob[headerSize : headerSize+int(cbKey)]
}

// Decapsulate generates a shared key from a ciphertext and a decapsulation
// key. If the ciphertext is not valid, Decapsulate returns an error.
//
// The shared key must be kept secret.
func (dk DecapsulationKeyMLKEM1024) Decapsulate(ciphertext []byte) (sharedKey []byte, err error) {
	if len(ciphertext) != ciphertextSizeMLKEM1024 {
		return nil, errors.New("mlkem: invalid ciphertext size")
	}

	// Open the ML-KEM algorithm provider
	var hAlg bcrypt.ALG_HANDLE
	err = bcrypt.OpenAlgorithmProvider(&hAlg, utf16PtrFromString(bcrypt.MLKEM_ALGORITHM), nil, 0)
	if err != nil {
		return nil, errors.New("mlkem: failed to open algorithm provider")
	}
	defer bcrypt.CloseAlgorithmProvider(hAlg, 0)

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(hAlg, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_BLOB), &hKey, dk.privBlob, 0)
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
	// Open the ML-KEM algorithm provider
	var hAlg bcrypt.ALG_HANDLE
	err := bcrypt.OpenAlgorithmProvider(&hAlg, utf16PtrFromString(bcrypt.MLKEM_ALGORITHM), nil, 0)
	if err != nil {
		panic(err)
	}
	defer bcrypt.CloseAlgorithmProvider(hAlg, 0)

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(hAlg, 0, utf16PtrFromString(bcrypt.MLKEM_PRIVATE_BLOB), &hKey, dk.privBlob, 0)
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
	return EncapsulationKeyMLKEM1024{blob: pubBlob}
}

// An EncapsulationKeyMLKEM1024 is the public key used to produce ciphertexts to be
// decapsulated by the corresponding DecapsulationKeyMLKEM1024.
type EncapsulationKeyMLKEM1024 struct {
	blob []byte
}

// NewEncapsulationKeyMLKEM1024 parses an encapsulation key from its encoded form. If
// the encapsulation key is not valid, NewEncapsulationKeyMLKEM1024 returns an error.
func NewEncapsulationKeyMLKEM1024(encapsulationKey []byte) (EncapsulationKeyMLKEM1024, error) {
	if len(encapsulationKey) != encapsulationKeySizeMLKEM1024 {
		return EncapsulationKeyMLKEM1024{}, errors.New("mlkem: invalid encapsulation key size")
	}

	// Create a MLKEM_KEY_BLOB with the raw key data
	// Format: Magic (4) + cbParameterSet (4) + cbKey (4) + ParameterSet (UTF-16 "1024\0") + Key data
	paramSet := bcrypt.MLKEM_PARAMETER_SET_1024 // utf16FromString adds the null terminator
	paramSetUTF16 := utf16FromString(paramSet)
	paramSetBytes := make([]byte, len(paramSetUTF16)*2)
	for i, v := range paramSetUTF16 {
		binary.LittleEndian.PutUint16(paramSetBytes[i*2:], v)
	}

	blob := make([]byte, 12+len(paramSetBytes)+len(encapsulationKey))
	binary.LittleEndian.PutUint32(blob[0:4], uint32(bcrypt.MLKEM_PUBLIC_MAGIC))
	binary.LittleEndian.PutUint32(blob[4:8], uint32(len(paramSetBytes))) // cbParameterSet
	binary.LittleEndian.PutUint32(blob[8:12], uint32(len(encapsulationKey))) // cbKey
	copy(blob[12:], paramSetBytes)
	copy(blob[12+len(paramSetBytes):], encapsulationKey)

	return EncapsulationKeyMLKEM1024{blob: blob}, nil
}

// Bytes returns the encapsulation key as a byte slice.
func (ek EncapsulationKeyMLKEM1024) Bytes() []byte {
	// Extract the raw key from the blob, skipping the MLKEM_KEY_BLOB header and parameter set
	// Structure: Magic (4) + cbParameterSet (4) + cbKey (4) + ParameterSet + Key
	if len(ek.blob) < 12 {
		panic("mlkem: invalid blob size")
	}
	cbParameterSet := binary.LittleEndian.Uint32(ek.blob[4:8])
	cbKey := binary.LittleEndian.Uint32(ek.blob[8:12])
	headerSize := 12 + int(cbParameterSet)
	if len(ek.blob) < headerSize+int(cbKey) {
		panic("mlkem: invalid blob size")
	}
	return ek.blob[headerSize : headerSize+int(cbKey)]
}

// Encapsulate generates a shared key and an associated ciphertext from an
// encapsulation key, drawing random bytes from the default crypto/rand source.
//
// The shared key must be kept secret.
func (ek EncapsulationKeyMLKEM1024) Encapsulate() (sharedKey, ciphertext []byte) {
	// Open the ML-KEM algorithm provider
	var hAlg bcrypt.ALG_HANDLE
	err := bcrypt.OpenAlgorithmProvider(&hAlg, utf16PtrFromString(bcrypt.MLKEM_ALGORITHM), nil, 0)
	if err != nil {
		panic(err)
	}
	defer bcrypt.CloseAlgorithmProvider(hAlg, 0)

	var hKey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(hAlg, 0, utf16PtrFromString(bcrypt.MLKEM_PUBLIC_BLOB), &hKey, ek.blob, 0)
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
