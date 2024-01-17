// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"errors"
	"runtime"
	"strconv"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

// As of FIPS 186-4 the maximum Q size is 32 bytes.
//
// See also: cbGroupSize at
// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob_v2
const maxGroupSize = 32

// crypto/dsa doesn't support passing the seed around, but CNG expects it.
// CNG will skip seed verification if the count and seed parameters is all 0xff bytes.
var (
	dsaCountNil = [4]byte{0xff, 0xff, 0xff, 0xff}
	dsaSeedNil  = [maxGroupSize]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
)

type dsaAlgorithm struct {
	handle            bcrypt.ALG_HANDLE
	allowedKeyLengths bcrypt.KEY_LENGTHS_STRUCT
}

func loadDSA() (h dsaAlgorithm, err error) {
	v, err := loadOrStoreAlg(bcrypt.DSA_ALGORITHM, bcrypt.ALG_NONE_FLAG, "", func(h bcrypt.ALG_HANDLE) (interface{}, error) {
		lengths, err := getKeyLengths(bcrypt.HANDLE(h))
		if err != nil {
			return nil, err
		}
		return dsaAlgorithm{h, lengths}, nil
	})
	if err != nil {
		return dsaAlgorithm{}, err
	}
	return v.(dsaAlgorithm), nil
}

// DSAParameters contains the DSA parameters.
type DSAParameters struct {
	P, Q, G BigInt
}

func (p DSAParameters) keySize() uint32 {
	return uint32(len(p.P))
}

func (p DSAParameters) groupSize() uint32 {
	return uint32(len(p.Q))
}

// GenerateDSAParameters generates a set of DSA parameters for a key of size L bytes.
// If L is less than or equal to 1024, the parameters are generated according to FIPS 186-2.
// If L is greater than 1024, the parameters are generated according to FIPS 186-3.
// The returned parameters are suitable for use in GenerateKey.
func GenerateDSAParameters(L int) (params DSAParameters, err error) {
	h, err := loadDSA()
	if err != nil {
		return DSAParameters{}, err
	}
	if !keyIsAllowed(h.allowedKeyLengths, uint32(L)) {
		return DSAParameters{}, errors.New("crypto/dsa: invalid key size")
	}
	// To generate the parameters, we need to generate a key pair and then export the public key.
	// The public key contains the parameters. We then discard the key pair.
	var hkey bcrypt.KEY_HANDLE
	if err := bcrypt.GenerateKeyPair(h.handle, &hkey, uint32(L), 0); err != nil {
		return DSAParameters{}, err
	}
	defer bcrypt.DestroyKey(hkey)

	if err := bcrypt.FinalizeKeyPair(hkey, 0); err != nil {
		return DSAParameters{}, err
	}
	params, _, _, err = decodeDSAKey(hkey, false)
	return params, err
}

// PrivateKeyDSA represents a DSA private key.
type PrivateKeyDSA struct {
	hkey bcrypt.KEY_HANDLE
}

func (k *PrivateKeyDSA) finalize() {
	bcrypt.DestroyKey(k.hkey)
}

func (k *PrivateKeyDSA) Data() (params DSAParameters, X, Y BigInt, err error) {
	defer runtime.KeepAlive(k)
	return decodeDSAKey(k.hkey, true)
}

// PublicKeyDSA represents a DSA public key.
type PublicKeyDSA struct {
	hkey bcrypt.KEY_HANDLE
}

func (k *PublicKeyDSA) finalize() {
	bcrypt.DestroyKey(k.hkey)
}

func (k *PublicKeyDSA) Data() (params DSAParameters, Y BigInt, err error) {
	defer runtime.KeepAlive(k)
	params, _, Y, err = decodeDSAKey(k.hkey, false)
	return
}

// GenerateKeyDSA generates a new private DSA key using the given parameters.
func GenerateKeyDSA(params DSAParameters) (*PrivateKeyDSA, error) {
	h, err := loadDSA()
	if err != nil {
		return nil, err
	}
	keySize := params.keySize()
	if !keyIsAllowed(h.allowedKeyLengths, keySize*8) {
		return nil, errors.New("crypto/dsa: invalid key size")
	}
	var hkey bcrypt.KEY_HANDLE
	if err := bcrypt.GenerateKeyPair(h.handle, &hkey, keySize*8, 0); err != nil {
		return nil, err
	}
	if err := setDSAParameter(hkey, params); err != nil {
		bcrypt.DestroyKey(hkey)
		return nil, err
	}
	if err := bcrypt.FinalizeKeyPair(hkey, 0); err != nil {
		bcrypt.DestroyKey(hkey)
		return nil, err
	}
	k := &PrivateKeyDSA{hkey}
	runtime.SetFinalizer(k, (*PrivateKeyDSA).finalize)
	return k, nil
}

// NewPrivateKeyDSA creates a new DSA private key from the given parameters.
func NewPrivateKeyDSA(params DSAParameters, X, Y BigInt) (*PrivateKeyDSA, error) {
	h, err := loadDSA()
	if err != nil {
		return nil, err
	}
	keySize := params.keySize()
	if !keyIsAllowed(h.allowedKeyLengths, keySize*8) {
		return nil, errors.New("crypto/dsa: invalid key size")
	}
	hkey, err := encodeDSAKey(h.handle, params, X, Y)
	if err != nil {
		return nil, err
	}
	k := &PrivateKeyDSA{hkey}
	runtime.SetFinalizer(k, (*PrivateKeyDSA).finalize)
	return k, nil
}

// NewPublicKeyDSA creates a new DSA public key from the given parameters.
func NewPublicKeyDSA(params DSAParameters, Y BigInt) (*PublicKeyDSA, error) {
	h, err := loadDSA()
	if err != nil {
		return nil, err
	}
	keySize := params.keySize()
	if !keyIsAllowed(h.allowedKeyLengths, keySize*8) {
		return nil, errors.New("crypto/dsa: invalid key size")
	}
	hkey, err := encodeDSAKey(h.handle, params, nil, Y)
	if err != nil {
		return nil, err
	}
	k := &PublicKeyDSA{hkey}
	runtime.SetFinalizer(k, (*PublicKeyDSA).finalize)
	return k, nil
}

// SignDSA signs a hash (which should be the result of hashing a larger message).
func SignDSA(priv *PrivateKeyDSA, hashed []byte) (r, s BigInt, err error) {
	defer runtime.KeepAlive(priv)
	size, err := getUint32(bcrypt.HANDLE(priv.hkey), bcrypt.SIGNATURE_LENGTH)
	if err != nil {
		return nil, nil, err
	}
	var buf [maxGroupSize]byte
	hashed, err = dsaAdjustHashSize(priv.hkey, hashed, buf[:])
	if err != nil {
		return nil, nil, err
	}
	sig := make([]byte, size)
	err = bcrypt.SignHash(priv.hkey, nil, hashed, sig, &size, 0)
	if err != nil {
		return nil, nil, err
	}
	sig = sig[:size]
	// BCRYPTSignHash generates DSA signatures in P1363 format,
	// which is simply (r, s), each of them exactly half of the array.
	if len(sig)%2 != 0 {
		return nil, nil, errors.New("crypto/dsa: invalid signature size from bcrypt")
	}
	return sig[:len(sig)/2], sig[len(sig)/2:], nil
}

// VerifyDSA verifies the signature in r, s of hashed using the public key, pub.
func VerifyDSA(pub *PublicKeyDSA, hashed []byte, r, s BigInt) bool {
	defer runtime.KeepAlive(pub)
	var buf [maxGroupSize]byte
	hashed, err := dsaAdjustHashSize(pub.hkey, hashed, buf[:])
	if err != nil {
		return false
	}
	size, err := getUint32(bcrypt.HANDLE(pub.hkey), bcrypt.SIGNATURE_LENGTH)
	if err != nil {
		return false
	}
	// r and s might be shorter than size
	// if the original big number contained leading zeros,
	// but they must not be longer than the public key size.
	if len(r) > int(size/2) || len(s) > int(size/2) {
		return false
	}
	sig := make([]byte, 0, 2*maxGroupSize)
	prependZeros := func(nonZeroBytes int) {
		if zeros := int(size/2) - nonZeroBytes; zeros > 0 {
			sig = append(sig, make([]byte, zeros)...)
		}
	}
	prependZeros(len(r))
	sig = append(sig, r...)
	prependZeros(len(s))
	sig = append(sig, s...)
	return keyVerify(pub.hkey, nil, hashed, sig, 0) == nil
}

func encodeDSAKey(h bcrypt.ALG_HANDLE, params DSAParameters, X, Y BigInt) (bcrypt.KEY_HANDLE, error) {
	keySize := params.keySize()
	groupSize := params.groupSize()
	private := X != nil
	var blob []byte
	if keySize*8 <= 1024 {
		size := sizeOfDSABlobHeader + keySize*3
		hdr := bcrypt.DSA_KEY_BLOB{
			Magic:   bcrypt.DSA_PUBLIC_MAGIC,
			KeySize: keySize,
			Count:   dsaCountNil,
		}
		if private {
			size += uint32(len(hdr.Q)) // private key is always 20 bytes
			hdr.Magic = bcrypt.DSA_PRIVATE_MAGIC
		}
		copy(hdr.Seed[:], dsaSeedNil[:])
		copy(hdr.Q[:], params.Q[:])
		blob = make([]byte, size)
		copy(blob, (*(*[sizeOfDSABlobHeader]byte)(unsafe.Pointer(&hdr)))[:])
		data := blob[sizeOfDSABlobHeader:]
		if err := encodeBigInt(data, []sizedBigInt{
			{params.P, keySize},
			{params.G, keySize},
			{Y, keySize},
			{X, groupSize},
		}); err != nil {
			return 0, err
		}
	} else {
		size := sizeOfDSAV2BlobHeader + 3*keySize + 2*groupSize
		hashAlg := hashAlgFromGroup(int(groupSize))
		hdr := bcrypt.DSA_KEY_BLOB_V2{
			Magic:           bcrypt.DSA_PUBLIC_MAGIC_V2,
			KeySize:         keySize,
			GroupSize:       groupSize,
			HashAlgorithm:   hashAlg,
			StandardVersion: bcrypt.DSA_FIPS186_3,
			SeedLength:      groupSize, // crypto/dsa doesn't use the seed, but it must be equal to groupSize.
			Count:           dsaCountNil,
		}
		if private {
			size += groupSize
			hdr.Magic = bcrypt.DSA_PRIVATE_MAGIC_V2
		}
		blob = make([]byte, size)
		copy(blob, (*(*[sizeOfDSAV2BlobHeader]byte)(unsafe.Pointer(&hdr)))[:])
		data := blob[sizeOfDSAV2BlobHeader:]
		if err := encodeBigInt(data, []sizedBigInt{
			{dsaSeedNil[:], groupSize},
			{params.Q, groupSize},
			{params.P, keySize},
			{params.G, keySize},
			{Y, keySize},
			{X, groupSize},
		}); err != nil {
			return 0, err
		}
	}
	kind := bcrypt.DSA_PUBLIC_BLOB
	if private {
		kind = bcrypt.DSA_PRIVATE_BLOB
	}
	var hkey bcrypt.KEY_HANDLE
	err := bcrypt.ImportKeyPair(h, 0, utf16PtrFromString(kind), &hkey, blob, 0)
	if err != nil {
		return 0, err
	}
	return hkey, nil
}

// decodeDSAKey decodes a DSA key. If private is true, the private exponent, X, is also returned.
func decodeDSAKey(hkey bcrypt.KEY_HANDLE, private bool) (params DSAParameters, X, Y BigInt, err error) {
	var data []byte
	consumeBigInt := func(size uint32) BigInt {
		b := data[:size]
		data = data[size:]
		return b
	}
	var L uint32
	L, err = getUint32(bcrypt.HANDLE(hkey), bcrypt.KEY_LENGTH)
	if err != nil {
		return
	}
	if L <= 1024 {
		var hdr bcrypt.DSA_KEY_BLOB
		hdr, data, err = exportDSAKey(hkey, private)
		if err != nil {
			return
		}
		magic := bcrypt.DSA_PUBLIC_MAGIC
		if private {
			magic = bcrypt.DSA_PRIVATE_MAGIC
		}
		if hdr.Magic != magic || hdr.KeySize*8 != uint32(L) {
			err = errors.New("crypto/dsa: exported key is corrupted")
			return
		}
		params = DSAParameters{
			Q: hdr.Q[:],
			P: consumeBigInt(hdr.KeySize),
			G: consumeBigInt(hdr.KeySize),
		}
		Y = consumeBigInt(hdr.KeySize)
		if private {
			X = consumeBigInt(uint32(len(hdr.Q))) // private key is always 20 bytes
		}
	} else {
		var hdr bcrypt.DSA_KEY_BLOB_V2
		hdr, data, err = exporDSAV2Key(hkey, private)
		if err != nil {
			return
		}
		magic := bcrypt.DSA_PUBLIC_MAGIC_V2
		if private {
			magic = bcrypt.DSA_PRIVATE_MAGIC_V2
		}
		if hdr.Magic != magic || hdr.KeySize*8 != uint32(L) {
			err = errors.New("crypto/dsa: exported key is corrupted")
			return
		}
		// Discard the seed, crypto/dsa doesn't use it.
		consumeBigInt(hdr.SeedLength)
		params = DSAParameters{
			Q: consumeBigInt(hdr.GroupSize),
			P: consumeBigInt(hdr.KeySize),
			G: consumeBigInt(hdr.KeySize),
		}
		Y = consumeBigInt(hdr.KeySize)
		if private {
			X = consumeBigInt(hdr.GroupSize)
		}
	}
	return params, X, Y, nil
}

// setDSAParameter sets the DSA parameters for the given key.
func setDSAParameter(hkey bcrypt.KEY_HANDLE, params DSAParameters) error {
	keySize := params.keySize()
	groupSize := params.groupSize()
	var blob []byte
	if keySize*8 <= 1024 {
		blob = make([]byte, sizeOfDSAParamsHeader+keySize*2)
		hdr := bcrypt.DSA_PARAMETER_HEADER{
			Length:  uint32(len(blob)),
			Magic:   bcrypt.DSA_PARAMETERS_MAGIC,
			KeySize: keySize,
			Count:   dsaCountNil,
		}
		copy(hdr.Seed[:], dsaSeedNil[:])
		copy(hdr.Q[:], params.Q[:])
		copy(blob, (*(*[sizeOfDSAParamsHeader]byte)(unsafe.Pointer(&hdr)))[:])
		data := blob[sizeOfDSAParamsHeader:]
		if err := encodeBigInt(data, []sizedBigInt{
			{params.P, keySize},
			{params.G, keySize},
		}); err != nil {
			return err
		}
	} else {
		blob = make([]byte, sizeOfDSAParamsV2Header+2*keySize+2*groupSize)
		hashAlg := hashAlgFromGroup(int(groupSize))
		hdr := bcrypt.DSA_PARAMETER_HEADER_V2{
			Length:          uint32(len(blob)),
			Magic:           bcrypt.DSA_PARAMETERS_MAGIC_V2,
			KeySize:         keySize,
			GroupSize:       groupSize,
			HashAlgorithm:   hashAlg,
			StandardVersion: bcrypt.DSA_FIPS186_3,
			SeedLength:      groupSize, // crypto/dsa doesn't use the seed, but CNG expects it to be groupSize.
			Count:           dsaCountNil,
		}
		copy(blob, (*(*[sizeOfDSAParamsV2Header]byte)(unsafe.Pointer(&hdr)))[:])
		data := blob[sizeOfDSAParamsV2Header:]
		if err := encodeBigInt(data, []sizedBigInt{
			{dsaSeedNil[:], groupSize},
			{params.Q, groupSize},
			{params.P, keySize},
			{params.G, keySize},
		}); err != nil {
			return err
		}

	}
	return bcrypt.SetProperty(bcrypt.HANDLE(hkey), utf16PtrFromString(bcrypt.DSA_PARAMETERS), blob, 0)
}

func dsaAdjustHashSize(hkey bcrypt.KEY_HANDLE, hashed []byte, buf []byte) ([]byte, error) {
	// Windows CNG requires that the hash output and Q match sizes, but we can better
	// interoperate with other FIPS 186-3 implementations if we perform truncation
	// here, before sending it to CNG.
	//
	// If, on the other hand, Q is too big, we need to left-pad the hash with zeroes
	// (since it gets treated as a big-endian number).
	params, _, _, err := decodeDSAKey(hkey, false)
	if err != nil {
		return nil, err
	}
	groupSize := int(params.groupSize())
	if groupSize > len(buf) {
		panic("output buffer too small")
	}
	if groupSize == len(hashed) {
		return hashed, nil
	}
	if groupSize < len(hashed) {
		return hashed[:groupSize], nil
	}
	if err := encodeBigInt(buf, []sizedBigInt{
		{hashed, uint32(groupSize)},
	}); err != nil {
		return nil, err
	}
	return buf[:groupSize], nil
}

func hashAlgFromGroup(groupSize int) bcrypt.HASHALGORITHM_ENUM {
	switch groupSize {
	case 20:
		return bcrypt.DSA_HASH_ALGORITHM_SHA1
	case 32:
		return bcrypt.DSA_HASH_ALGORITHM_SHA256
	case 64:
		return bcrypt.DSA_HASH_ALGORITHM_SHA512
	default:
		panic("invalid group size: " + strconv.Itoa(groupSize))
	}
}
