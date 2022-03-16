// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:generate go run github.com/microsoft/go-crypto-winnative/cmd/mksyscall -output zsyscall_windows.go bcrypt_windows.go

package bcrypt

import (
	"syscall"
	"unsafe"
)

const (
	SHA1_ALGORITHM   = "SHA1"
	SHA256_ALGORITHM = "SHA256"
	SHA384_ALGORITHM = "SHA384"
	SHA512_ALGORITHM = "SHA512"
	AES_ALGORITHM    = "AES"
)

const (
	HASH_LENGTH       = "HashDigestLength"
	HASH_BLOCK_LENGTH = "HashBlockLength"
	CHAINING_MODE     = "ChainingMode"
	CHAIN_MODE_ECB    = "ChainingModeECB"
	CHAIN_MODE_CBC    = "ChainingModeCBC"
	KEY_LENGTHS       = "KeyLengths"
)

const (
	USE_SYSTEM_PREFERRED_RNG = 0x00000002
)

type AlgorithmProviderFlags uint32

const (
	ALG_NONE_FLAG        AlgorithmProviderFlags = 0x00000000
	ALG_HANDLE_HMAC_FLAG AlgorithmProviderFlags = 0x00000008
)

type (
	HANDLE      syscall.Handle
	ALG_HANDLE  HANDLE
	HASH_HANDLE HANDLE
	KEY_HANDLE  HANDLE
)

// https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_key_lengths_struct
type KEY_LENGTHS_STRUCT struct {
	MinLength uint32
	MaxLength uint32
	Increment uint32
}

// https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info
type AUTHENTICATED_CIPHER_MODE_INFO struct {
	Size           uint32
	InfoVersion    uint32
	Nonce          *byte
	NonceSize      uint32
	AuthData       *byte
	AuthDataSize   uint32
	Tag            *byte
	TagSize        uint32
	MacContext     *byte
	MacContextSize uint32
	AADSize        uint32
	DataSize       uint64
	Flags          uint32
}

func NewAUTHENTICATED_CIPHER_MODE_INFO(nonce, additionalData, tag []byte) *AUTHENTICATED_CIPHER_MODE_INFO {
	var aad *byte
	if additionalData != nil {
		aad = &additionalData[0]
	}
	info := AUTHENTICATED_CIPHER_MODE_INFO{
		InfoVersion:  1,
		Nonce:        &nonce[0],
		NonceSize:    uint32(len(nonce)),
		AuthData:     aad,
		AuthDataSize: uint32(len(additionalData)),
		Tag:          &tag[0],
		TagSize:      uint32(len(tag)),
	}
	info.Size = uint32(unsafe.Sizeof(info))
	return &info
}

//sys	SetProperty(hObject HANDLE, pszProperty *uint16, pbInput []byte, dwFlags uint32) (s error) = bcrypt.BCryptSetProperty
//sys	GetProperty(hObject HANDLE, pszProperty *uint16, pbOutput []byte, pcbResult *uint32, dwFlags uint32) (s error) = bcrypt.BCryptGetProperty
//sys	OpenAlgorithmProvider(phAlgorithm *ALG_HANDLE, pszAlgId *uint16, pszImplementation *uint16, dwFlags AlgorithmProviderFlags) (s error) = bcrypt.BCryptOpenAlgorithmProvider
//sys	CloseAlgorithmProvider(hAlgorithm ALG_HANDLE, dwFlags uint32) (s error) = bcrypt.BCryptCloseAlgorithmProvider

// SHA and HMAC

//sys	CreateHash(hAlgorithm ALG_HANDLE, phHash *HASH_HANDLE, pbHashObject []byte, pbSecret []byte, dwFlags uint32) (s error) = bcrypt.BCryptCreateHash
//sys	DestroyHash(hHash HASH_HANDLE) (s error) = bcrypt.BCryptDestroyHash
//sys   HashData(hHash HASH_HANDLE, pbInput []byte, dwFlags uint32) (s error) = bcrypt.BCryptHashData
//sys   DuplicateHash(hHash HASH_HANDLE,  phNewHash *HASH_HANDLE, pbHashObject []byte, dwFlags uint32) (s error) = bcrypt.BCryptDuplicateHash
//sys   FinishHash(hHash HASH_HANDLE, pbOutput []byte, dwFlags uint32) (s error) = bcrypt.BCryptFinishHash

// Rand

//sys   GenRandom(hAlgorithm ALG_HANDLE, pbBuffer []byte, dwFlags uint32) (s error) = bcrypt.BCryptGenRandom

// Keys

//sys   GenerateSymmetricKey(hAlgorithm ALG_HANDLE, phKey *KEY_HANDLE, pbKeyObject *byte, cbKeyObject uint32, pbSecret *byte, cbSecret uint32, dwFlags uint32) (s error) = bcrypt.BCryptGenerateSymmetricKey
//sys   DestroyKey(hKey KEY_HANDLE) (s error) = bcrypt.BCryptDestroyKey
//sys   Encrypt(hKey KEY_HANDLE, pbInput *byte, cbInput uint32, pPaddingInfo uintptr, pbIV *byte, cbIV uint32, pbOutput *byte, cbOutput uint32, pcbResult *uint32, dwFlags uint32) (s error) = bcrypt.BCryptEncrypt
//sys   Decrypt(hKey KEY_HANDLE, pbInput *byte, cbInput uint32, pPaddingInfo uintptr, pbIV *byte, cbIV uint32, pbOutput *byte, cbOutput uint32, pcbResult *uint32, dwFlags uint32) (s error) = bcrypt.BCryptDecrypt
