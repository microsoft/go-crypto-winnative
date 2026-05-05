// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"errors"
	"runtime"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

const (
	// privateKeySizeMLDSA is the size of an ML-DSA private key seed.
	privateKeySizeMLDSA = 32

	// publicKeySizeMLDSA44 is the size of an ML-DSA-44 public key encoding.
	publicKeySizeMLDSA44 = 1312

	// publicKeySizeMLDSA65 is the size of an ML-DSA-65 public key encoding.
	publicKeySizeMLDSA65 = 1952

	// publicKeySizeMLDSA87 is the size of an ML-DSA-87 public key encoding.
	publicKeySizeMLDSA87 = 2592

	// signatureSizeMLDSA44 is the size of an ML-DSA-44 signature.
	signatureSizeMLDSA44 = 2420

	// signatureSizeMLDSA65 is the size of an ML-DSA-65 signature.
	signatureSizeMLDSA65 = 3309

	// signatureSizeMLDSA87 is the size of an ML-DSA-87 signature.
	signatureSizeMLDSA87 = 4627

	sizeOfPQDSAKeyBlobHeader      = 12
	maxMLDSAParameterSetNameBytes = 6
	sizeOfPrivateSeedBlobMLDSA    = sizeOfPQDSAKeyBlobHeader + maxMLDSAParameterSetNameBytes + privateKeySizeMLDSA
	sizeOfPublicKeyBlobMLDSA87    = sizeOfPQDSAKeyBlobHeader + maxMLDSAParameterSetNameBytes + publicKeySizeMLDSA87
)

type mldsaAlgorithm struct {
	handle bcrypt.ALG_HANDLE
}

func loadMLDSA() (mldsaAlgorithm, error) {
	return loadOrStoreAlg(bcrypt.MLDSA_ALGORITHM, 0, "", func(h bcrypt.ALG_HANDLE) (mldsaAlgorithm, error) {
		return mldsaAlgorithm{handle: h}, nil
	})
}

// SupportsMLDSA returns true if ML-DSA is supported on this platform.
func SupportsMLDSA() bool {
	_, err := loadMLDSA()
	return err == nil
}

func generateMLDSAKey(paramSet string, dst []byte) error {
	alg, err := loadMLDSA()
	if err != nil {
		return err
	}

	var hKey bcrypt.KEY_HANDLE
	if err := bcrypt.GenerateKeyPair(alg.handle, &hKey, 0, 0); err != nil {
		return err
	}
	defer bcrypt.DestroyKey(hKey)

	if err := setString(bcrypt.HANDLE(hKey), bcrypt.PARAMETER_SET_NAME, paramSet); err != nil {
		return err
	}
	if err := bcrypt.FinalizeKeyPair(hKey, 0); err != nil {
		return err
	}

	var blob [sizeOfPrivateSeedBlobMLDSA]byte
	var size uint32
	if err := bcrypt.ExportKey(hKey, 0, utf16PtrFromString(bcrypt.PQDSA_PRIVATE_SEED_BLOB), blob[:], &size, 0); err != nil {
		return err
	}
	return extractPQDSAKeyBytes(dst, blob[:size])
}

func newPQDSAKeyBlob(dst []byte, paramSet string, keyBytes []byte, magic bcrypt.KeyBlobMagicNumber) ([]byte, error) {
	paramSetByteLen := (len(paramSet) + 1) * 2
	blobSize := 12 + paramSetByteLen + len(keyBytes)
	if len(dst) < blobSize {
		return nil, errors.New("mldsa: destination blob too small")
	}
	blob := dst[:blobSize]
	putUint32LE(blob[0:4], uint32(magic))
	putUint32LE(blob[4:8], uint32(paramSetByteLen))
	putUint32LE(blob[8:12], uint32(len(keyBytes)))
	for i := 0; i < len(paramSet); i++ {
		if paramSet[i] == 0 || paramSet[i] > 127 {
			panic("newPQDSAKeyBlob only supports ASCII parameter set names, got " + paramSet)
		}
		putUint16LE(blob[12+i*2:], uint16(paramSet[i]))
	}
	putUint16LE(blob[12+len(paramSet)*2:], 0)
	copy(blob[12+paramSetByteLen:], keyBytes)
	return blob, nil
}

func extractPQDSAKeyBytes(dst, blob []byte) error {
	if len(blob) < 12 {
		return errors.New("mldsa: blob too small")
	}
	cbParameterSet := getUint32LE(blob[4:8])
	cbKey := getUint32LE(blob[8:12])
	headerSize := 12 + int(cbParameterSet)
	if len(blob) < headerSize+int(cbKey) {
		return errors.New("mldsa: invalid blob size")
	}
	if len(dst) != int(cbKey) {
		return errors.New("mldsa: destination size mismatch")
	}
	copy(dst, blob[headerSize:headerSize+int(cbKey)])
	return nil
}

func importMLDSAPrivateKey(paramSet string, seed []byte) (bcrypt.KEY_HANDLE, error) {
	alg, err := loadMLDSA()
	if err != nil {
		return 0, err
	}
	var blobBuf [sizeOfPrivateSeedBlobMLDSA]byte
	blob, err := newPQDSAKeyBlob(blobBuf[:], paramSet, seed, bcrypt.MLDSA_PRIVATE_SEED_MAGIC)
	if err != nil {
		return 0, err
	}
	var hKey bcrypt.KEY_HANDLE
	if err := bcrypt.ImportKeyPair(alg.handle, 0, utf16PtrFromString(bcrypt.PQDSA_PRIVATE_SEED_BLOB), &hKey, blob, 0); err != nil {
		return 0, err
	}
	return hKey, nil
}

func importMLDSAPublicKey(paramSet string, publicKey []byte) (bcrypt.KEY_HANDLE, error) {
	alg, err := loadMLDSA()
	if err != nil {
		return 0, err
	}
	var blobBuf [sizeOfPublicKeyBlobMLDSA87]byte
	blob, err := newPQDSAKeyBlob(blobBuf[:], paramSet, publicKey, bcrypt.MLDSA_PUBLIC_MAGIC)
	if err != nil {
		return 0, err
	}
	var hKey bcrypt.KEY_HANDLE
	if err := bcrypt.ImportKeyPair(alg.handle, 0, utf16PtrFromString(bcrypt.PQDSA_PUBLIC_BLOB), &hKey, blob, 0); err != nil {
		return 0, err
	}
	return hKey, nil
}

func mldsaPublicKey(paramSet string, seed, dst []byte) error {
	hKey, err := importMLDSAPrivateKey(paramSet, seed)
	if err != nil {
		return err
	}
	defer bcrypt.DestroyKey(hKey)

	var blob [sizeOfPublicKeyBlobMLDSA87]byte
	var size uint32
	if err := bcrypt.ExportKey(hKey, 0, utf16PtrFromString(bcrypt.PQDSA_PUBLIC_BLOB), blob[:], &size, 0); err != nil {
		return err
	}
	return extractPQDSAKeyBytes(dst, blob[:size])
}

func mldsaPadding(context string) (bcrypt.PQDSA_PADDING_INFO, []byte, bcrypt.PadMode, error) {
	if len(context) > 255 {
		return bcrypt.PQDSA_PADDING_INFO{}, nil, 0, errors.New("mldsa: context too long")
	}
	if context == "" {
		return bcrypt.PQDSA_PADDING_INFO{}, nil, bcrypt.PAD_PQDSA, nil
	}
	contextBytes := []byte(context)
	return bcrypt.PQDSA_PADDING_INFO{
		Context:     &contextBytes[0],
		ContextSize: uint32(len(contextBytes)),
	}, contextBytes, bcrypt.PAD_PQDSA, nil
}

func mldsaSign(paramSet string, seed, message []byte, signatureSize int, context string) ([]byte, error) {
	hKey, err := importMLDSAPrivateKey(paramSet, seed)
	if err != nil {
		return nil, err
	}
	defer bcrypt.DestroyKey(hKey)

	info, contextBytes, flags, err := mldsaPadding(context)
	if err != nil {
		return nil, err
	}
	var infoPtr unsafe.Pointer
	if flags != 0 {
		infoPtr = unsafe.Pointer(&info)
		defer runtime.KeepAlive(contextBytes)
	}

	signature := make([]byte, signatureSize)
	var size uint32
	if err := bcrypt.SignHash(hKey, infoPtr, message, signature, &size, flags); err != nil {
		return nil, err
	}
	return signature[:size], nil
}

func mldsaSignExternalMu(paramSet string, seed, mu []byte, signatureSize int) ([]byte, error) {
	if len(mu) != 64 {
		return nil, errors.New("mldsa: invalid message hash length")
	}
	hKey, err := importMLDSAPrivateKey(paramSet, seed)
	if err != nil {
		return nil, err
	}
	defer bcrypt.DestroyKey(hKey)

	signature := make([]byte, signatureSize)
	var size uint32
	if err := bcrypt.SignHash(hKey, nil, mu, signature, &size, bcrypt.MLDSA_EXTERNAL_MU); err != nil {
		return nil, err
	}
	return signature[:size], nil
}

func mldsaVerify(paramSet string, publicKey, message, signature []byte, signatureSize int, context string) error {
	if len(signature) != signatureSize {
		return errors.New("mldsa: invalid signature length")
	}
	hKey, err := importMLDSAPublicKey(paramSet, publicKey)
	if err != nil {
		return err
	}
	defer bcrypt.DestroyKey(hKey)

	info, contextBytes, flags, err := mldsaPadding(context)
	if err != nil {
		return err
	}
	var infoPtr unsafe.Pointer
	if flags != 0 {
		infoPtr = unsafe.Pointer(&info)
		defer runtime.KeepAlive(contextBytes)
	}
	return bcrypt.VerifySignature(hKey, infoPtr, message, signature, flags)
}

func mldsaVerifyExternalMu(paramSet string, publicKey, mu, signature []byte, signatureSize int) error {
	if len(mu) != 64 {
		return errors.New("mldsa: invalid message hash length")
	}
	if len(signature) != signatureSize {
		return errors.New("mldsa: invalid signature length")
	}
	hKey, err := importMLDSAPublicKey(paramSet, publicKey)
	if err != nil {
		return err
	}
	defer bcrypt.DestroyKey(hKey)
	return bcrypt.VerifySignature(hKey, nil, mu, signature, bcrypt.MLDSA_EXTERNAL_MU)
}

// MLDSAParameters represents one of the fixed ML-DSA parameter sets.
type MLDSAParameters struct {
	name          string
	paramSet      string
	publicKeySize int
	signatureSize int
}

var (
	mldsa44 = MLDSAParameters{
		name:          "ML-DSA-44",
		paramSet:      bcrypt.MLDSA_PARAMETER_SET_44,
		publicKeySize: publicKeySizeMLDSA44,
		signatureSize: signatureSizeMLDSA44,
	}
	mldsa65 = MLDSAParameters{
		name:          "ML-DSA-65",
		paramSet:      bcrypt.MLDSA_PARAMETER_SET_65,
		publicKeySize: publicKeySizeMLDSA65,
		signatureSize: signatureSizeMLDSA65,
	}
	mldsa87 = MLDSAParameters{
		name:          "ML-DSA-87",
		paramSet:      bcrypt.MLDSA_PARAMETER_SET_87,
		publicKeySize: publicKeySizeMLDSA87,
		signatureSize: signatureSizeMLDSA87,
	}
)

// MLDSA44 returns the ML-DSA-44 parameter set.
func MLDSA44() MLDSAParameters { return mldsa44 }

// MLDSA65 returns the ML-DSA-65 parameter set.
func MLDSA65() MLDSAParameters { return mldsa65 }

// MLDSA87 returns the ML-DSA-87 parameter set.
func MLDSA87() MLDSAParameters { return mldsa87 }

func (params MLDSAParameters) valid() bool {
	switch params {
	case mldsa44, mldsa65, mldsa87:
		return true
	default:
		return false
	}
}

// PublicKeySize returns the size of public keys for this parameter set, in bytes.
func (params MLDSAParameters) PublicKeySize() int { return params.publicKeySize }

// SignatureSize returns the size of signatures for this parameter set, in bytes.
func (params MLDSAParameters) SignatureSize() int { return params.signatureSize }

// String returns the name of the parameter set.
func (params MLDSAParameters) String() string { return params.name }

var errInvalidMLDSAParameters = errors.New("mldsa: invalid parameters")

// PrivateKeyMLDSA is an ML-DSA private key seed.
type PrivateKeyMLDSA struct {
	params MLDSAParameters
	seed   [privateKeySizeMLDSA]byte
}

// GenerateKeyMLDSA generates a new ML-DSA private key.
func GenerateKeyMLDSA(params MLDSAParameters) (*PrivateKeyMLDSA, error) {
	if !params.valid() {
		return nil, errInvalidMLDSAParameters
	}
	key := &PrivateKeyMLDSA{params: params}
	if err := generateMLDSAKey(params.paramSet, key.seed[:]); err != nil {
		return nil, err
	}
	return key, nil
}

// NewPrivateKeyMLDSA constructs an ML-DSA private key from its seed.
func NewPrivateKeyMLDSA(params MLDSAParameters, seed []byte) (*PrivateKeyMLDSA, error) {
	if !params.valid() {
		return nil, errInvalidMLDSAParameters
	}
	if len(seed) != privateKeySizeMLDSA {
		return nil, errors.New("mldsa: invalid private key size")
	}
	key := &PrivateKeyMLDSA{params: params}
	copy(key.seed[:], seed)
	return key, nil
}

// Bytes returns the private key seed.
func (key *PrivateKeyMLDSA) Bytes() []byte {
	return key.seed[:]
}

// Parameters returns the parameters associated with this private key.
func (key *PrivateKeyMLDSA) Parameters() MLDSAParameters { return key.params }

// PublicKey returns the corresponding public key.
func (key *PrivateKeyMLDSA) PublicKey() *PublicKeyMLDSA {
	publicKey := &PublicKeyMLDSA{params: key.params}
	if err := mldsaPublicKey(key.params.paramSet, key.seed[:], publicKey.bytes[:key.params.publicKeySize]); err != nil {
		panic(err)
	}
	return publicKey
}

// Sign signs message with context using ML-DSA.
func (key *PrivateKeyMLDSA) Sign(message []byte, context string) ([]byte, error) {
	return mldsaSign(key.params.paramSet, key.seed[:], message, key.params.signatureSize, context)
}

// SignExternalMu signs a pre-hashed mu message representative using ML-DSA.
func (key *PrivateKeyMLDSA) SignExternalMu(mu []byte) ([]byte, error) {
	return mldsaSignExternalMu(key.params.paramSet, key.seed[:], mu, key.params.signatureSize)
}

// PublicKeyMLDSA is an ML-DSA public key.
type PublicKeyMLDSA struct {
	params MLDSAParameters
	bytes  [publicKeySizeMLDSA87]byte
}

// NewPublicKeyMLDSA constructs an ML-DSA public key from its encoding.
func NewPublicKeyMLDSA(params MLDSAParameters, publicKey []byte) (*PublicKeyMLDSA, error) {
	if !params.valid() {
		return nil, errInvalidMLDSAParameters
	}
	if len(publicKey) != params.publicKeySize {
		return nil, errors.New("mldsa: invalid public key size")
	}
	if hKey, err := importMLDSAPublicKey(params.paramSet, publicKey); err != nil {
		return nil, err
	} else {
		bcrypt.DestroyKey(hKey)
	}
	key := &PublicKeyMLDSA{params: params}
	copy(key.bytes[:], publicKey)
	return key, nil
}

// Bytes returns the public key encoding.
func (key *PublicKeyMLDSA) Bytes() []byte {
	return key.bytes[:key.params.publicKeySize]
}

// Parameters returns the parameters associated with this public key.
func (key *PublicKeyMLDSA) Parameters() MLDSAParameters { return key.params }

// Verify verifies an ML-DSA signature.
func (key *PublicKeyMLDSA) Verify(message, signature []byte, context string) error {
	return mldsaVerify(key.params.paramSet, key.bytes[:key.params.publicKeySize], message, signature, key.params.signatureSize, context)
}

// VerifyExternalMu verifies an ML-DSA signature over a pre-hashed mu message representative.
func (key *PublicKeyMLDSA) VerifyExternalMu(mu, signature []byte) error {
	return mldsaVerifyExternalMu(key.params.paramSet, key.bytes[:key.params.publicKeySize], mu, signature, key.params.signatureSize)
}
