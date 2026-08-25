// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:generate go run ../../cmd/mkwinmd -format mkwinsyscall -projection idiomatic -output zwinmd_windows.go bcrypt_windows.go
//go:generate go run ../../cmd/mksyscall -output zsyscall_windows.go zwinmd_windows.go bcrypt_windows.go ntstatus_windows.go

//winmd:func bcrypt.dll.BCryptGetFipsAlgorithmMode -name GetFipsAlgorithmMode
//winmd:func bcrypt.dll.BCryptSetProperty -name SetProperty
//winmd:func bcrypt.dll.BCryptGetProperty -name GetProperty
//winmd:func bcrypt.dll.BCryptOpenAlgorithmProvider -name OpenAlgorithmProvider
//winmd:func bcrypt.dll.BCryptCloseAlgorithmProvider -name CloseAlgorithmProvider
//winmd:func bcrypt.dll.BCryptHash -name Hash
//winmd:func bcrypt.dll.BCryptCreateHash -name CreateHash
//winmd:func bcrypt.dll.BCryptDestroyHash -name DestroyHash
//winmd:func bcrypt.dll.BCryptHashData -name HashData
//winmd:func bcrypt.dll.BCryptDuplicateHash -name DuplicateHash
//winmd:func bcrypt.dll.BCryptFinishHash -name FinishHash
//winmd:func bcrypt.dll.BCryptGenRandom -name GenRandom
//winmd:func bcrypt.dll.BCryptGenerateKeyPair -name GenerateKeyPair
//winmd:func bcrypt.dll.BCryptFinalizeKeyPair -name FinalizeKeyPair
//winmd:func bcrypt.dll.BCryptImportKeyPair -name ImportKeyPair
//winmd:func bcrypt.dll.BCryptExportKey -name ExportKey
//winmd:func bcrypt.dll.BCryptDestroyKey -name DestroyKey
//winmd:func bcrypt.dll.BCryptSignHash -name SignHash
//winmd:func bcrypt.dll.BCryptVerifySignature -name VerifySignature
//winmd:func bcrypt.dll.BCryptSecretAgreement -name SecretAgreement
//winmd:func bcrypt.dll.BCryptDeriveKey -name DeriveKey
//winmd:func bcrypt.dll.BCryptKeyDerivation -name KeyDerivation
//winmd:func bcrypt.dll.BCryptDestroySecret -name DestroySecret
//winmd:func bcrypt.dll.BCryptEncapsulate -name Encapsulate
//winmd:func bcrypt.dll.BCryptDecapsulate -name Decapsulate

//winmd:type Windows.Win32.Security.Cryptography.BCRYPT_KEY_DATA_BLOB_HEADER -name KEY_DATA_BLOB_HEADER
//winmd:type Windows.Win32.Security.Cryptography.BCRYPT_DSA_PARAMETER_HEADER -name DSA_PARAMETER_HEADER
//winmd:type Windows.Win32.Security.Cryptography.BCRYPT_DSA_PARAMETER_HEADER_V2 -name DSA_PARAMETER_HEADER_V2
//winmd:type Windows.Win32.Security.Cryptography.BCRYPT_KEY_LENGTHS_STRUCT -name KEY_LENGTHS_STRUCT
//winmd:type Windows.Win32.Security.Cryptography.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO -name AUTHENTICATED_CIPHER_MODE_INFO
//winmd:type Windows.Win32.Security.Cryptography.BCRYPT_OAEP_PADDING_INFO -name OAEP_PADDING_INFO
//winmd:type Windows.Win32.Security.Cryptography.BCRYPT_PKCS1_PADDING_INFO -name PKCS1_PADDING_INFO
//winmd:type Windows.Win32.Security.Cryptography.BCRYPT_PSS_PADDING_INFO -name PSS_PADDING_INFO
//winmd:type Windows.Win32.Security.Cryptography.BCRYPT_PQDSA_PADDING_INFO -name PQDSA_PADDING_INFO
//winmd:type Windows.Win32.Security.Cryptography.BCRYPT_RSAKEY_BLOB -name RSAKEY_BLOB
//winmd:type Windows.Win32.Security.Cryptography.BCRYPT_ECCKEY_BLOB -name ECCKEY_BLOB
//winmd:type Windows.Win32.Security.Cryptography.BCRYPT_DSA_KEY_BLOB -name DSA_KEY_BLOB
//winmd:type Windows.Win32.Security.Cryptography.BCRYPT_DSA_KEY_BLOB_V2 -name DSA_KEY_BLOB_V2
//winmd:type Windows.Win32.Security.Cryptography.BCRYPT_MLKEM_KEY_BLOB -name MLKEM_KEY_BLOB

// Package bcrypt implements interop with bcrypt.dll, a component of Windows CNG.
// See https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/
//
// Note: this package is not related to the bcrypt password hashing algorithm.
package bcrypt

import (
	"unsafe"
)

const (
	SHA1_ALGORITHM       = "SHA1"
	SHA256_ALGORITHM     = "SHA256"
	SHA384_ALGORITHM     = "SHA384"
	SHA512_ALGORITHM     = "SHA512"
	SHA3_256_ALGORITHM   = "SHA3-256"
	SHA3_384_ALGORITHM   = "SHA3-384"
	SHA3_512_ALGORITHM   = "SHA3-512"
	CSHAKE128_ALGORITHM  = "CSHAKE128"
	CSHAKE256_ALGORITHM  = "CSHAKE256"
	AES_ALGORITHM        = "AES"
	RC4_ALGORITHM        = "RC4"
	RSA_ALGORITHM        = "RSA"
	MD4_ALGORITHM        = "MD4"
	MD5_ALGORITHM        = "MD5"
	ECDSA_ALGORITHM      = "ECDSA"
	ECDH_ALGORITHM       = "ECDH"
	HKDF_ALGORITHM       = "HKDF"
	PBKDF2_ALGORITHM     = "PBKDF2"
	DES_ALGORITHM        = "DES"
	DES3_ALGORITHM       = "3DES" // 3DES_ALGORITHM
	TLS1_1_KDF_ALGORITHM = "TLS1_1_KDF"
	TLS1_2_KDF_ALGORITHM = "TLS1_2_KDF"
	DSA_ALGORITHM        = "DSA"
	MLDSA_ALGORITHM      = "ML-DSA"
	MLKEM_ALGORITHM      = "ML-KEM"

	CHACHA20_POLY1305_ALGORITHM = "CHACHA20_POLY1305"
)

const (
	ECC_CURVE_25519    = "curve25519"
	ECC_CURVE_NISTP224 = "nistP224"
	ECC_CURVE_NISTP256 = "nistP256"
	ECC_CURVE_NISTP384 = "nistP384"
	ECC_CURVE_NISTP521 = "nistP521"
)

const (
	HASH_LENGTH          = "HashDigestLength"
	HASH_BLOCK_LENGTH    = "HashBlockLength"
	CHAINING_MODE        = "ChainingMode"
	CHAIN_MODE_ECB       = "ChainingModeECB"
	CHAIN_MODE_CBC       = "ChainingModeCBC"
	CHAIN_MODE_GCM       = "ChainingModeGCM"
	KEY_LENGTH           = "KeyLength"
	KEY_LENGTHS          = "KeyLengths"
	SIGNATURE_LENGTH     = "SignatureLength"
	BLOCK_LENGTH         = "BlockLength"
	ECC_CURVE_NAME       = "ECCCurveName"
	FUNCTION_NAME_STRING = "FunctionNameString"
	CUSTOMIZATION_STRING = "CustomizationString"
)

const (
	RSAPUBLIC_KEY_BLOB      = "RSAPUBLICBLOB"
	RSAFULLPRIVATE_BLOB     = "RSAFULLPRIVATEBLOB"
	ECCPUBLIC_BLOB          = "ECCPUBLICBLOB"
	ECCPRIVATE_BLOB         = "ECCPRIVATEBLOB"
	DSA_PUBLIC_BLOB         = "DSAPUBLICBLOB"
	DSA_PRIVATE_BLOB        = "DSAPRIVATEBLOB"
	PQDSA_PUBLIC_BLOB       = "PQDSAPUBLICBLOB"
	PQDSA_PRIVATE_BLOB      = "PQDSAPRIVATEBLOB"
	PQDSA_PRIVATE_SEED_BLOB = "PQDSAPRIVATESEEDBLOB"
	MLKEM_PUBLIC_BLOB       = "MLKEMPUBLICBLOB"
	MLKEM_PRIVATE_SEED_BLOB = "MLKEMPRIVATESEEDBLOB"
)

const (
	KDF_HKDF_INFO          = 0x14
	HKDF_HASH_ALGORITHM    = "HkdfHashAlgorithm"
	HKDF_SALT_AND_FINALIZE = "HkdfSaltAndFinalize"
	HKDF_PRK_AND_FINALIZE  = "HkdfPrkAndFinalize"
)

const (
	KDF_HASH_ALGORITHM   = 0x0
	KDF_TLS_PRF_LABEL    = 0x4
	KDF_TLS_PRF_SEED     = 0x5
	KDF_TLS_PRF_PROTOCOL = 0x6
	KDF_ITERATION_COUNT  = 0x10
	KDF_SALT             = 0xF
)

const (
	KEY_DATA_BLOB          = "KeyDataBlob"
	KEY_DATA_BLOB_MAGIC    = 0x4d42444b
	KEY_DATA_BLOB_VERSION1 = 1
)

type Buffer = BCryptBuffer

type BufferDesc = BCryptBufferDesc

const (
	USE_SYSTEM_PREFERRED_RNG = 0x00000002
)

const (
	HASH_DONT_RESET_FLAG = 0x00000001
	HASH_REUSABLE_FLAG   = 0x00000020
)

const (
	KDF_RAW_SECRET = "TRUNCATE"
)

const (
	DSA_PARAMETERS = "DSAParameters"
)

const (
	// Post-quantum related properties and constants
	PARAMETER_SET_NAME       = "ParameterSetName"
	MLDSA_PARAMETER_SET_44   = "44"
	MLDSA_PARAMETER_SET_65   = "65"
	MLDSA_PARAMETER_SET_87   = "87"
	MLKEM_PARAMETER_SET_768  = "768"
	MLKEM_PARAMETER_SET_1024 = "1024"
)

type PadMode = BCRYPT_FLAGS

const (
	PAD_UNDEFINED     PadMode = 0x0
	PAD_NONE          PadMode = 0x1
	PAD_PKCS1         PadMode = 0x2
	PAD_OAEP          PadMode = 0x4
	PAD_PSS           PadMode = 0x8
	PAD_PQDSA         PadMode = 0x20
	MLDSA_EXTERNAL_MU PadMode = 0x40
)

type AlgorithmProviderFlags = BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS

const (
	ALG_NONE_FLAG        AlgorithmProviderFlags = 0x00000000
	ALG_HANDLE_HMAC_FLAG AlgorithmProviderFlags = 0x00000008
)

type KeyBlobMagicNumber uint32

const (
	RSAPUBLIC_MAGIC      KeyBlobMagicNumber = 0x31415352
	RSAFULLPRIVATE_MAGIC KeyBlobMagicNumber = 0x33415352

	ECDSA_PUBLIC_GENERIC_MAGIC  KeyBlobMagicNumber = 0x50444345
	ECDSA_PRIVATE_GENERIC_MAGIC KeyBlobMagicNumber = 0x56444345

	ECDH_PUBLIC_GENERIC_MAGIC  KeyBlobMagicNumber = 0x504B4345
	ECDH_PRIVATE_GENERIC_MAGIC KeyBlobMagicNumber = 0x564B4345

	DSA_PARAMETERS_MAGIC KeyBlobMagicNumber = 0x4d505344
	DSA_PUBLIC_MAGIC     KeyBlobMagicNumber = 0x42505344
	DSA_PRIVATE_MAGIC    KeyBlobMagicNumber = 0x56505344

	DSA_PARAMETERS_MAGIC_V2 KeyBlobMagicNumber = 0x324d5044
	DSA_PUBLIC_MAGIC_V2     KeyBlobMagicNumber = 0x32425044
	DSA_PRIVATE_MAGIC_V2    KeyBlobMagicNumber = 0x32565044

	MLDSA_PUBLIC_MAGIC       KeyBlobMagicNumber = 0x4B505344
	MLDSA_PRIVATE_MAGIC      KeyBlobMagicNumber = 0x4B535344
	MLDSA_PRIVATE_SEED_MAGIC KeyBlobMagicNumber = 0x53535344

	MLKEM_PUBLIC_MAGIC       KeyBlobMagicNumber = 0x504B4C4D
	MLKEM_PRIVATE_MAGIC      KeyBlobMagicNumber = 0x524B4C4D
	MLKEM_PRIVATE_SEED_MAGIC KeyBlobMagicNumber = 0x534B4C4D
)

type (
	HANDLE        = BCRYPT_HANDLE
	ALG_HANDLE    = BCRYPT_ALG_HANDLE
	HASH_HANDLE   = BCRYPT_HASH_HANDLE
	KEY_HANDLE    = BCRYPT_KEY_HANDLE
	SECRET_HANDLE = BCRYPT_SECRET_HANDLE
)

func NewAUTHENTICATED_CIPHER_MODE_INFO(nonce, additionalData, tag []byte) *AUTHENTICATED_CIPHER_MODE_INFO {
	var aad *byte
	if len(additionalData) > 0 {
		aad = &additionalData[0]
	}
	info := AUTHENTICATED_CIPHER_MODE_INFO{
		DwInfoVersion: 1,
		PbNonce:       &nonce[0],
		CbNonce:       uint32(len(nonce)),
		PbAuthData:    aad,
		CbAuthData:    uint32(len(additionalData)),
		PbTag:         &tag[0],
		CbTag:         uint32(len(tag)),
	}
	info.CbSize = uint32(unsafe.Sizeof(info))
	return &info
}

//sys _Encrypt(hKey KEY_HANDLE, pbInput *byte, cbInput uint32, pPaddingInfo unsafe.Pointer, pbIV []byte, pbOutput []byte, pcbResult *uint32, dwFlags PadMode) (ntstatus error) = bcrypt.BCryptEncrypt
//sys _Decrypt(hKey KEY_HANDLE, pbInput *byte, cbInput uint32, pPaddingInfo unsafe.Pointer, pbIV []byte, pbOutput *byte, cbOutput uint32, pcbResult *uint32, dwFlags PadMode) (ntstatus error) = bcrypt.BCryptDecrypt
//sys _GenerateSymmetricKey(hAlgorithm ALG_HANDLE, phKey *KEY_HANDLE, pbKeyObject []byte, pbSecret *byte, cbSecret uint32, dwFlags uint32) (ntstatus error) = bcrypt.BCryptGenerateSymmetricKey
//sys HashDataRaw(hHash HASH_HANDLE, pbInput *byte, cbInput uint32, dwFlags uint32) (ntstatus error) = bcrypt.BCryptHashData

func Encrypt(hKey KEY_HANDLE, plaintext []byte, pPaddingInfo unsafe.Pointer, pbIV []byte, ciphertext []byte, pcbResult *uint32, dwFlags PadMode) (ntstatus error) {
	var pInput *byte
	if len(plaintext) > 0 {
		pInput = &plaintext[0]
	} else {
		// BCryptEncrypt does not support nil plaintext.
		// Allocate a zero byte here just to make CNG happy.
		// It won't be encrypted anyway because the plaintext length is zero.
		pInput = new(byte)
	}
	return _Encrypt(hKey, pInput, uint32(len(plaintext)), pPaddingInfo, pbIV, ciphertext, pcbResult, dwFlags)
}

func Decrypt(hKey KEY_HANDLE, ciphertext []byte, pPaddingInfo unsafe.Pointer, pbIV []byte, plaintext []byte, pcbResult *uint32, dwFlags PadMode) (ntstatus error) {
	// Previous to Windows 2025, BCryptDescrypt did not validate the padding info when ciphertext and plaintext were both zero-length.
	// To maintain compatibility with those versions, we allocate a zero byte when ciphertext is empty.
	var pInput, pOutput *byte
	if len(ciphertext) == 0 && len(plaintext) == 0 {
		pOutput = new(byte)
		pInput = pOutput
	} else {
		if len(plaintext) > 0 {
			pOutput = &plaintext[0]
		}
		if len(ciphertext) > 0 {
			pInput = &ciphertext[0]
		}
	}
	return _Decrypt(hKey, pInput, uint32(len(ciphertext)), pPaddingInfo, pbIV, pOutput, uint32(len(plaintext)), pcbResult, dwFlags)
}

func GenerateSymmetricKey(hAlgorithm ALG_HANDLE, phKey *KEY_HANDLE, pbKeyObject []byte, pbSecret []byte, dwFlags uint32) error {
	cbLen := uint32(len(pbSecret))
	if cbLen == 0 {
		// BCryptGenerateSymmetricKey does not support nil pbSecret,
		// stack-allocate a zero byte here just to make CNG happy.
		pbSecret = make([]byte, 1)
	}
	return _GenerateSymmetricKey(hAlgorithm, phKey, pbKeyObject, &pbSecret[0], cbLen, dwFlags)
}
