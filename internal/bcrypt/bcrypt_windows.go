// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:generate go run github.com/microsoft/go-crypto-winnative/cmd/mksyscall -output zsyscall_windows.go bcrypt_windows.go

package bcrypt

import (
	"syscall"
)

const (
	SHA1_ALGORITHM   = "SHA1"
	SHA256_ALGORITHM = "SHA256"
	SHA384_ALGORITHM = "SHA384"
	SHA512_ALGORITHM = "SHA512"
)

const (
	HASH_LENGTH       = "HashDigestLength"
	HASH_BLOCK_LENGTH = "HashBlockLength"
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
)

//sys	GetProperty(hObject HANDLE, pszProperty *uint16, pbOutput []byte, pcbResult *uint32, dwFlags uint32) (s error) = bcrypt.BCryptGetProperty
//sys	OpenAlgorithmProvider(phAlgorithm *ALG_HANDLE, pszAlgId *uint16, pszImplementation *uint16, dwFlags AlgorithmProviderFlags) (s error) = bcrypt.BCryptOpenAlgorithmProvider
//sys	CloseAlgorithmProvider(hAlgorithm ALG_HANDLE, dwFlags uint32) (s error) = bcrypt.BCryptCloseAlgorithmProvider
//sys	CreateHash(hAlgorithm ALG_HANDLE, phHash *HASH_HANDLE, pbHashObject []byte, pbSecret []byte, dwFlags uint32) (s error) = bcrypt.BCryptCreateHash
//sys	DestroyHash(hHash HASH_HANDLE) (s error) = bcrypt.BCryptDestroyHash
//sys   HashData(hHash HASH_HANDLE, pbInput []byte, dwFlags uint32) (s error) = bcrypt.BCryptHashData
//sys   DuplicateHash(hHash HASH_HANDLE,  phNewHash *HASH_HANDLE, pbHashObject []byte, dwFlags uint32) (s error) = bcrypt.BCryptDuplicateHash
//sys   FinishHash(hHash HASH_HANDLE, pbOutput []byte, dwFlags uint32) (s error) = bcrypt.BCryptFinishHash
//sys   GenRandom(hAlgorithm ALG_HANDLE, pbBuffer []byte, dwFlags uint32) (s error) = bcrypt.BCryptGenRandom
