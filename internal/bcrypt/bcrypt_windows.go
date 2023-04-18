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
	RSA_ALGORITHM    = "RSA"
	MD5_ALGORITHM    = "MD5"
	ECDSA_ALGORITHM  = "ECDSA"
	ECDH_ALGORITHM   = "ECDH"
)

const (
	ECC_CURVE_25519    = "curve25519"
	ECC_CURVE_NISTP224 = "nistP224"
	ECC_CURVE_NISTP256 = "nistP256"
	ECC_CURVE_NISTP384 = "nistP384"
	ECC_CURVE_NISTP521 = "nistP521"
)

const (
	HASH_LENGTH       = "HashDigestLength"
	HASH_BLOCK_LENGTH = "HashBlockLength"
	CHAINING_MODE     = "ChainingMode"
	CHAIN_MODE_ECB    = "ChainingModeECB"
	CHAIN_MODE_CBC    = "ChainingModeCBC"
	CHAIN_MODE_GCM    = "ChainingModeGCM"
	KEY_LENGTH        = "KeyLength"
	KEY_LENGTHS       = "KeyLengths"
	BLOCK_LENGTH      = "BlockLength"
	ECC_CURVE_NAME    = "ECCCurveName"
)

const (
	RSAPUBLIC_KEY_BLOB  = "RSAPUBLICBLOB"
	RSAFULLPRIVATE_BLOB = "RSAFULLPRIVATEBLOB"
	ECCPUBLIC_BLOB      = "ECCPUBLICBLOB"
	ECCPRIVATE_BLOB     = "ECCPRIVATEBLOB"
)

const (
	USE_SYSTEM_PREFERRED_RNG = 0x00000002
)

const (
	KDF_RAW_SECRET = "TRUNCATE"
)

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

func Encrypt(hKey KEY_HANDLE, plaintext []byte, pPaddingInfo unsafe.Pointer, pbIV []byte, pbOutput []byte, pcbResult *uint32, dwFlags PadMode) (s error) {
	var pInput *byte
	if len(plaintext) > 0 {
		pInput = &plaintext[0]
	} else {
		// BCryptEncrypt does not support nil plaintext.
		// Allocate a zero byte here just to make CNG happy.
		// It won't be encrypted anyway because the plaintext length is zero.
		pInput = new(byte)
	}
	return _Encrypt(hKey, pInput, uint32(len(plaintext)), pPaddingInfo, pbIV, pbOutput, pcbResult, dwFlags)
}

//sys	GetFipsAlgorithmMode(enabled *bool) (s error) = bcrypt.BCryptGetFipsAlgorithmMode
//sys	SetProperty(hObject HANDLE, pszProperty *uint16, pbInput []byte, dwFlags uint32) (s error) = bcrypt.BCryptSetProperty
//sys	GetProperty(hObject HANDLE, pszProperty *uint16, pbOutput []byte, pcbResult *uint32, dwFlags uint32) (s error) = bcrypt.BCryptGetProperty
//sys	OpenAlgorithmProvider(phAlgorithm *ALG_HANDLE, pszAlgId *uint16, pszImplementation *uint16, dwFlags AlgorithmProviderFlags) (s error) = bcrypt.BCryptOpenAlgorithmProvider
//sys	CloseAlgorithmProvider(hAlgorithm ALG_HANDLE, dwFlags uint32) (s error) = bcrypt.BCryptCloseAlgorithmProvider

// SHA and HMAC

//sys	Hash(hAlgorithm ALG_HANDLE, pbSecret []byte, pbInput []byte, pbOutput []byte) (s error) = bcrypt.BCryptHash
//sys	CreateHash(hAlgorithm ALG_HANDLE, phHash *HASH_HANDLE, pbHashObject []byte, pbSecret []byte, dwFlags uint32) (s error) = bcrypt.BCryptCreateHash
//sys	DestroyHash(hHash HASH_HANDLE) (s error) = bcrypt.BCryptDestroyHash
//sys   HashData(hHash HASH_HANDLE, pbInput []byte, dwFlags uint32) (s error) = bcrypt.BCryptHashData
//sys   HashDataRaw(hHash HASH_HANDLE, pbInput *byte, cbInput uint32, dwFlags uint32) (s error) = bcrypt.BCryptHashData
//sys   DuplicateHash(hHash HASH_HANDLE,  phNewHash *HASH_HANDLE, pbHashObject []byte, dwFlags uint32) (s error) = bcrypt.BCryptDuplicateHash
//sys   FinishHash(hHash HASH_HANDLE, pbOutput []byte, dwFlags uint32) (s error) = bcrypt.BCryptFinishHash

// Rand

//sys   GenRandom(hAlgorithm ALG_HANDLE, pbBuffer []byte, dwFlags uint32) (s error) = bcrypt.BCryptGenRandom

// Keys

//sys   GenerateSymmetricKey(hAlgorithm ALG_HANDLE, phKey *KEY_HANDLE, pbKeyObject []byte, pbSecret []byte, dwFlags uint32) (s error) = bcrypt.BCryptGenerateSymmetricKey
//sys   GenerateKeyPair(hAlgorithm ALG_HANDLE, phKey *KEY_HANDLE, dwLength uint32, dwFlags uint32) (s error) = bcrypt.BCryptGenerateKeyPair
//sys   FinalizeKeyPair(hKey KEY_HANDLE, dwFlags uint32) (s error) = bcrypt.BCryptFinalizeKeyPair
//sys   ImportKeyPair (hAlgorithm ALG_HANDLE, hImportKey KEY_HANDLE, pszBlobType *uint16, phKey *KEY_HANDLE, pbInput []byte, dwFlags uint32) (s error) = bcrypt.BCryptImportKeyPair
//sys   ExportKey(hKey KEY_HANDLE, hExportKey KEY_HANDLE, pszBlobType *uint16, pbOutput []byte, pcbResult *uint32, dwFlags uint32) (s error) = bcrypt.BCryptExportKey
//sys   DestroyKey(hKey KEY_HANDLE) (s error) = bcrypt.BCryptDestroyKey
//sys   _Encrypt(hKey KEY_HANDLE, pbInput *byte, cbInput uint32, pPaddingInfo unsafe.Pointer, pbIV []byte, pbOutput []byte, pcbResult *uint32, dwFlags PadMode) (s error) = bcrypt.BCryptEncrypt
//sys   Decrypt(hKey KEY_HANDLE, pbInput []byte, pPaddingInfo unsafe.Pointer, pbIV []byte, pbOutput []byte, pcbResult *uint32, dwFlags PadMode) (s error) = bcrypt.BCryptDecrypt
//sys   SignHash (hKey KEY_HANDLE, pPaddingInfo unsafe.Pointer, pbInput []byte, pbOutput []byte, pcbResult *uint32, dwFlags PadMode) (s error) = bcrypt.BCryptSignHash
//sys   VerifySignature(hKey KEY_HANDLE, pPaddingInfo unsafe.Pointer, pbHash []byte, pbSignature []byte, dwFlags PadMode) (s error) = bcrypt.BCryptVerifySignature
//sys   SecretAgreement(hPrivKey KEY_HANDLE, hPubKey KEY_HANDLE, phAgreedSecret *SECRET_HANDLE, dwFlags uint32) (s error) = bcrypt.BCryptSecretAgreement
//sys   DeriveKey(hSharedSecret SECRET_HANDLE, pwszKDF *uint16, pParameterList *byte, pbDerivedKey []byte, pcbResult *uint32, dwFlags uint32) (s error) = bcrypt.BCryptDeriveKey
//sys   DestroySecret(hSecret SECRET_HANDLE) (s error) = bcrypt.BCryptDestroySecret
