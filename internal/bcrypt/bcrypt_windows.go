// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:generate go run github.com/microsoft/go-crypto-winnative/cmd/mksyscall -output zsyscall_windows.go bcrypt_windows.go ntstatus_windows.go

// Package bcrypt implements interop with bcrypt.dll, a component of Windows CNG.
// See https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/
//
// Note: this package is not related to the bcrypt password hashing algorithm.
package bcrypt

import (
	"syscall"
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

type KEY_DATA_BLOB_HEADER struct {
	Magic   uint32
	Version uint32
	Length  uint32
}

type Buffer struct {
	Length uint32
	Type   uint32
	Data   uintptr
}

type BufferDesc struct {
	Version uint32
	Count   uint32 // number of buffers
	Buffers *Buffer
}

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
	// ML-KEM related properties and constants
	PARAMETER_SET_NAME       = "ParameterSetName"
	MLKEM_PARAMETER_SET_768  = "768"
	MLKEM_PARAMETER_SET_1024 = "1024"
)

type HASHALGORITHM_ENUM uint32

const (
	DSA_HASH_ALGORITHM_SHA1 HASHALGORITHM_ENUM = iota
	DSA_HASH_ALGORITHM_SHA256
	DSA_HASH_ALGORITHM_SHA512
)

type DSAFIPSVERSION_ENUM uint32

const (
	DSA_FIPS186_2 DSAFIPSVERSION_ENUM = iota
	DSA_FIPS186_3
)

type DSA_PARAMETER_HEADER struct {
	Length  uint32
	Magic   KeyBlobMagicNumber
	KeySize uint32
	Count   [4]uint8
	Seed    [20]uint8
	Q       [20]uint8
}

type DSA_PARAMETER_HEADER_V2 struct {
	Length          uint32
	Magic           KeyBlobMagicNumber
	KeySize         uint32
	HashAlgorithm   HASHALGORITHM_ENUM
	StandardVersion DSAFIPSVERSION_ENUM
	SeedLength      uint32
	GroupSize       uint32
	Count           [4]uint8
}

type PadMode uint32

const (
	PAD_UNDEFINED PadMode = 0x0
	PAD_NONE      PadMode = 0x1
	PAD_PKCS1     PadMode = 0x2
	PAD_OAEP      PadMode = 0x4
	PAD_PSS       PadMode = 0x8
)

type AlgorithmProviderFlags uint32

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

	MLKEM_PUBLIC_MAGIC       KeyBlobMagicNumber = 0x504B4C4D
	MLKEM_PRIVATE_MAGIC      KeyBlobMagicNumber = 0x524B4C4D
	MLKEM_PRIVATE_SEED_MAGIC KeyBlobMagicNumber = 0x534B4C4D
)

type (
	HANDLE        syscall.Handle
	ALG_HANDLE    HANDLE
	HASH_HANDLE   HANDLE
	KEY_HANDLE    HANDLE
	SECRET_HANDLE HANDLE
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
	if len(additionalData) > 0 {
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

// https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_oaep_padding_info
type OAEP_PADDING_INFO struct {
	AlgId     *uint16
	Label     *byte
	LabelSize uint32
}

// https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_pkcs1_padding_info
type PKCS1_PADDING_INFO struct {
	AlgId *uint16
}

// https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_pss_padding_info
type PSS_PADDING_INFO struct {
	AlgId *uint16
	Salt  uint32
}

// https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
type RSAKEY_BLOB struct {
	Magic         KeyBlobMagicNumber
	BitLength     uint32
	PublicExpSize uint32
	ModulusSize   uint32
	Prime1Size    uint32
	Prime2Size    uint32
}

// https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
type ECCKEY_BLOB struct {
	Magic   KeyBlobMagicNumber
	KeySize uint32
}

// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob
type DSA_KEY_BLOB struct {
	Magic   KeyBlobMagicNumber
	KeySize uint32
	Count   [4]uint8
	Seed    [20]uint8
	Q       [20]uint8
}

// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob_v2
type DSA_KEY_BLOB_V2 struct {
	Magic           KeyBlobMagicNumber
	KeySize         uint32
	HashAlgorithm   HASHALGORITHM_ENUM
	StandardVersion DSAFIPSVERSION_ENUM
	SeedLength      uint32
	GroupSize       uint32
	Count           [4]uint8
}

// https://learn.microsoft.com/en-us/windows/win32/seccng/cng-mlkem
type MLKEM_KEY_BLOB struct {
	Magic KeyBlobMagicNumber
}

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

//sys	GetFipsAlgorithmMode(enabled *bool) (ntstatus error) = bcrypt.BCryptGetFipsAlgorithmMode
//sys	SetProperty(hObject HANDLE, pszProperty *uint16, pbInput []byte, dwFlags uint32) (ntstatus error) = bcrypt.BCryptSetProperty
//sys	GetProperty(hObject HANDLE, pszProperty *uint16, pbOutput []byte, pcbResult *uint32, dwFlags uint32) (ntstatus error) = bcrypt.BCryptGetProperty
//sys	OpenAlgorithmProvider(phAlgorithm *ALG_HANDLE, pszAlgId *uint16, pszImplementation *uint16, dwFlags AlgorithmProviderFlags) (ntstatus error) = bcrypt.BCryptOpenAlgorithmProvider
//sys	CloseAlgorithmProvider(hAlgorithm ALG_HANDLE, dwFlags uint32) (ntstatus error) = bcrypt.BCryptCloseAlgorithmProvider

// SHA and HMAC

//sys	Hash(hAlgorithm ALG_HANDLE, pbSecret []byte, pbInput []byte, pbOutput []byte) (ntstatus error) = bcrypt.BCryptHash
//sys	CreateHash(hAlgorithm ALG_HANDLE, phHash *HASH_HANDLE, pbHashObject []byte, pbSecret []byte, dwFlags uint32) (ntstatus error) = bcrypt.BCryptCreateHash
//sys	DestroyHash(hHash HASH_HANDLE) (ntstatus error) = bcrypt.BCryptDestroyHash
//sys   HashData(hHash HASH_HANDLE, pbInput []byte, dwFlags uint32) (ntstatus error) = bcrypt.BCryptHashData
//sys   HashDataRaw(hHash HASH_HANDLE, pbInput *byte, cbInput uint32, dwFlags uint32) (ntstatus error) = bcrypt.BCryptHashData
//sys   DuplicateHash(hHash HASH_HANDLE,  phNewHash *HASH_HANDLE, pbHashObject []byte, dwFlags uint32) (ntstatus error) = bcrypt.BCryptDuplicateHash
//sys   FinishHash(hHash HASH_HANDLE, pbOutput []byte, dwFlags uint32) (ntstatus error) = bcrypt.BCryptFinishHash

// Rand

//sys   GenRandom(hAlgorithm ALG_HANDLE, pbBuffer []byte, dwFlags uint32) (ntstatus error) = bcrypt.BCryptGenRandom

// Keys

//sys   generateSymmetricKey(hAlgorithm ALG_HANDLE, phKey *KEY_HANDLE, pbKeyObject []byte, pbSecret *byte, cbSecret uint32, dwFlags uint32) (ntstatus error) = bcrypt.BCryptGenerateSymmetricKey
//sys   GenerateKeyPair(hAlgorithm ALG_HANDLE, phKey *KEY_HANDLE, dwLength uint32, dwFlags uint32) (ntstatus error) = bcrypt.BCryptGenerateKeyPair
//sys   FinalizeKeyPair(hKey KEY_HANDLE, dwFlags uint32) (ntstatus error) = bcrypt.BCryptFinalizeKeyPair
//sys   ImportKeyPair (hAlgorithm ALG_HANDLE, hImportKey KEY_HANDLE, pszBlobType *uint16, phKey *KEY_HANDLE, pbInput []byte, dwFlags uint32) (ntstatus error) = bcrypt.BCryptImportKeyPair
//sys   ExportKey(hKey KEY_HANDLE, hExportKey KEY_HANDLE, pszBlobType *uint16, pbOutput []byte, pcbResult *uint32, dwFlags uint32) (ntstatus error) = bcrypt.BCryptExportKey
//sys   DestroyKey(hKey KEY_HANDLE) (ntstatus error) = bcrypt.BCryptDestroyKey
//sys   _Encrypt(hKey KEY_HANDLE, pbInput *byte, cbInput uint32, pPaddingInfo unsafe.Pointer, pbIV []byte, pbOutput []byte, pcbResult *uint32, dwFlags PadMode) (ntstatus error) = bcrypt.BCryptEncrypt
//sys   _Decrypt(hKey KEY_HANDLE, pbInput *byte, cbInput uint32, pPaddingInfo unsafe.Pointer, pbIV []byte, pbOutput *byte, cbOutput uint32, pcbResult *uint32, dwFlags PadMode) (ntstatus error) = bcrypt.BCryptDecrypt
//sys   SignHash (hKey KEY_HANDLE, pPaddingInfo unsafe.Pointer, pbInput []byte, pbOutput []byte, pcbResult *uint32, dwFlags PadMode) (ntstatus error) = bcrypt.BCryptSignHash
//sys   VerifySignature(hKey KEY_HANDLE, pPaddingInfo unsafe.Pointer, pbHash []byte, pbSignature []byte, dwFlags PadMode) (ntstatus error) = bcrypt.BCryptVerifySignature
//sys   SecretAgreement(hPrivKey KEY_HANDLE, hPubKey KEY_HANDLE, phAgreedSecret *SECRET_HANDLE, dwFlags uint32) (ntstatus error) = bcrypt.BCryptSecretAgreement
//sys   DeriveKey(hSharedSecret SECRET_HANDLE, pwszKDF *uint16, pParameterList *BufferDesc, pbDerivedKey []byte, pcbResult *uint32, dwFlags uint32) (ntstatus error) = bcrypt.BCryptDeriveKey
//sys   KeyDerivation(hKey KEY_HANDLE, pParameterList *BufferDesc, pbDerivedKey []byte, pcbResult *uint32, dwFlags uint32) (ntstatus error) = bcrypt.BCryptKeyDerivation
//sys   DestroySecret(hSecret SECRET_HANDLE) (ntstatus error) = bcrypt.BCryptDestroySecret

// ML-KEM uses standard BCrypt functions
// BCryptGenerateKeyPair, BCryptSetProperty, BCryptFinalizeKeyPair, BCryptExportKey, BCryptImportKeyPair
// BCryptEncapsulate, BCryptDecapsulate

//sys   Encapsulate(hKey KEY_HANDLE, pbSecret []byte, pcbResult *uint32, pbCiphertext []byte, pcbCiphertext *uint32, dwFlags uint32) (ntstatus error) = bcrypt.BCryptEncapsulate
//sys   Decapsulate(hKey KEY_HANDLE, pbCiphertext []byte, pbSecret []byte, pcbResult *uint32, dwFlags uint32) (ntstatus error) = bcrypt.BCryptDecapsulate

func GenerateSymmetricKey(hAlgorithm ALG_HANDLE, phKey *KEY_HANDLE, pbKeyObject []byte, pbSecret []byte, dwFlags uint32) error {
	cbLen := uint32(len(pbSecret))
	if cbLen == 0 {
		// BCryptGenerateSymmetricKey does not support nil pbSecret,
		// stack-allocate a zero byte here just to make CNG happy.
		pbSecret = make([]byte, 1)
	}
	return generateSymmetricKey(hAlgorithm, phKey, pbKeyObject, &pbSecret[0], cbLen, dwFlags)
}
