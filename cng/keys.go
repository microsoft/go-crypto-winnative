// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"errors"
	"unsafe"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

const (
	sizeOfECCBlobHeader = uint32(unsafe.Sizeof(bcrypt.ECCKEY_BLOB{}))
	sizeOfRSABlobHeader = uint32(unsafe.Sizeof(bcrypt.RSAKEY_BLOB{}))
)

// exportRSAKey exports hkey into a bcrypt.ECCKEY_BLOB header and data.
func exportCCKey(hkey bcrypt.KEY_HANDLE, private bool) (bcrypt.ECCKEY_BLOB, []byte, error) {
	var magic string
	if private {
		magic = bcrypt.ECCPRIVATE_BLOB
	} else {
		magic = bcrypt.ECCPUBLIC_BLOB
	}
	blob, err := exportKey(hkey, magic)
	if err != nil {
		return bcrypt.ECCKEY_BLOB{}, nil, err
	}
	if len(blob) < int(sizeOfECCBlobHeader) {
		return bcrypt.ECCKEY_BLOB{}, nil, errors.New("cng: exported key is corrupted")
	}
	hdr := (*(*bcrypt.ECCKEY_BLOB)(unsafe.Pointer(&blob[0])))
	return hdr, blob[sizeOfECCBlobHeader:], nil
}

// exportRSAKey exports hkey into a bcrypt.RSAKEY_BLOB header and data.
func exportRSAKey(hkey bcrypt.KEY_HANDLE, private bool) (bcrypt.RSAKEY_BLOB, []byte, error) {
	var magic string
	if private {
		magic = bcrypt.RSAFULLPRIVATE_BLOB
	} else {
		magic = bcrypt.RSAPUBLIC_KEY_BLOB
	}
	blob, err := exportKey(hkey, magic)
	if err != nil {
		return bcrypt.RSAKEY_BLOB{}, nil, err
	}
	if len(blob) < int(sizeOfRSABlobHeader) {
		return bcrypt.RSAKEY_BLOB{}, nil, errors.New("cng: exported key is corrupted")
	}
	hdr := (*(*bcrypt.RSAKEY_BLOB)(unsafe.Pointer(&blob[0])))
	return hdr, blob[sizeOfRSABlobHeader:], nil
}

// exportKey exports hkey to a memory blob.
func exportKey(hkey bcrypt.KEY_HANDLE, magic string) ([]byte, error) {
	psBlobType := utf16PtrFromString(magic)
	var size uint32
	err := bcrypt.ExportKey(hkey, 0, psBlobType, nil, &size, 0)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, size)
	err = bcrypt.ExportKey(hkey, 0, psBlobType, blob, &size, 0)
	if err != nil {
		return nil, err
	}
	return blob, err
}

// importECCKey imports a public/private key pair from the given parameters.
// Id D is nil only the public components will be populates.
func importECCKey(h bcrypt.ALG_HANDLE, id string, bits uint32, X, Y, D BigInt) (bcrypt.KEY_HANDLE, error) {
	blob, err := encodeECCKey(id, bits, X, Y, D)
	if err != nil {
		return 0, err
	}
	var kind string
	if D == nil {
		kind = bcrypt.ECCPUBLIC_BLOB
	} else {
		kind = bcrypt.ECCPRIVATE_BLOB
	}
	var hkey bcrypt.KEY_HANDLE
	err = bcrypt.ImportKeyPair(h, 0, utf16PtrFromString(kind), &hkey, blob, 0)
	if err != nil {
		return 0, err
	}
	return hkey, nil
}

// encodeECCKey generates a bcrypt.ECCKEY_BLOB from the given parameters.
func encodeECCKey(id string, bits uint32, X, Y, D BigInt) ([]byte, error) {
	var hdr bcrypt.ECCKEY_BLOB
	hdr.KeySize = (bits + 7) / 8
	if len(X) > int(hdr.KeySize) || len(Y) > int(hdr.KeySize) || len(D) > int(hdr.KeySize) {
		return nil, errors.New("crypto/ecdsa: invalid parameters")
	}
	switch id {
	case bcrypt.ECDSA_P256_ALGORITHM, bcrypt.ECDSA_P384_ALGORITHM, bcrypt.ECDSA_P521_ALGORITHM:
		if D == nil {
			hdr.Magic = bcrypt.ECDSA_PUBLIC_GENERIC_MAGIC
		} else {
			hdr.Magic = bcrypt.ECDSA_PRIVATE_GENERIC_MAGIC
		}
	case bcrypt.ECDH_P256_ALGORITHM, bcrypt.ECDH_P384_ALGORITHM, bcrypt.ECDH_P521_ALGORITHM:
		if D == nil {
			hdr.Magic = bcrypt.ECDH_PUBLIC_GENERIC_MAGIC
		} else {
			hdr.Magic = bcrypt.ECDH_PRIVATE_GENERIC_MAGIC
		}
	default:
		panic("unsupported key ID: " + id)
	}
	var blob []byte
	if D == nil {
		blob = make([]byte, sizeOfECCBlobHeader+hdr.KeySize*2)
	} else {
		blob = make([]byte, sizeOfECCBlobHeader+hdr.KeySize*3)
	}
	copy(blob, (*(*[sizeOfECCBlobHeader]byte)(unsafe.Pointer(&hdr)))[:])
	data := blob[sizeOfECCBlobHeader:]
	encode := func(b BigInt, size uint32) {
		// b might be shorter than size if the original big number contained leading zeros.
		leadingZeros := int(size) - len(b)
		copy(data[leadingZeros:], b)
		data = data[size:]
	}
	encode(X, hdr.KeySize)
	encode(Y, hdr.KeySize)
	if D != nil {
		encode(D, hdr.KeySize)
	}
	return blob, nil
}