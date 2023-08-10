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
	sizeOfECCBlobHeader     = uint32(unsafe.Sizeof(bcrypt.ECCKEY_BLOB{}))
	sizeOfRSABlobHeader     = uint32(unsafe.Sizeof(bcrypt.RSAKEY_BLOB{}))
	sizeOfKeyDataBlobHeader = uint32(unsafe.Sizeof(bcrypt.KEY_DATA_BLOB_HEADER{}))
)

// exportRSAKey exports hkey into a bcrypt.ECCKEY_BLOB header and data.
func exportECCKey(hkey bcrypt.KEY_HANDLE, private bool) (bcrypt.ECCKEY_BLOB, []byte, error) {
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

// exportKeyData exports hkey into a bcrypt.KEY_DATA_BLOB_HEADER header and data.
func exportKeyData(hkey bcrypt.KEY_HANDLE) (bcrypt.KEY_DATA_BLOB_HEADER, []byte, error) {
	blob, err := exportKey(hkey, bcrypt.KEY_DATA_BLOB)
	if err != nil {
		return bcrypt.KEY_DATA_BLOB_HEADER{}, nil, err
	}
	if len(blob) < int(sizeOfKeyDataBlobHeader) {
		return bcrypt.KEY_DATA_BLOB_HEADER{}, nil, errors.New("cng: exported key is corrupted")
	}
	hdr := (*(*bcrypt.KEY_DATA_BLOB_HEADER)(unsafe.Pointer(&blob[0])))
	if hdr.Magic != bcrypt.KEY_DATA_BLOB_MAGIC {
		return bcrypt.KEY_DATA_BLOB_HEADER{}, nil, errors.New("cng: unknown key format")
	}
	return hdr, blob[sizeOfKeyDataBlobHeader : sizeOfKeyDataBlobHeader+hdr.Length], nil
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
// If D is nil, only the public components will be populated.
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
		return nil, errors.New("cng: invalid parameters")
	}
	switch id {
	case bcrypt.ECDSA_ALGORITHM:
		if D == nil {
			hdr.Magic = bcrypt.ECDSA_PUBLIC_GENERIC_MAGIC
		} else {
			hdr.Magic = bcrypt.ECDSA_PRIVATE_GENERIC_MAGIC
		}
	case bcrypt.ECDH_ALGORITHM:
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
	err := encodeBigInt(data, []sizedBigInt{
		{X, hdr.KeySize}, {Y, hdr.KeySize},
		{D, hdr.KeySize},
	})
	if err != nil {
		return nil, err
	}
	return blob, nil
}

// sizedBigInt defines a big integer with
// a size that can be different from the
// one provided by len(b).
type sizedBigInt struct {
	b    BigInt
	size uint32
}

// encodeBigInt encodes ints into data.
// It stops iterating over ints when it finds one nil element.
func encodeBigInt(data []byte, ints []sizedBigInt) error {
	for _, v := range ints {
		if v.b == nil {
			return nil
		}
		// b might be shorter than size if the original big number contained leading zeros.
		leadingZeros := int(v.size) - len(v.b)
		if leadingZeros < 0 {
			return errors.New("cng: invalid parameters")
		}
		copy(data[leadingZeros:], v.b)
		data = data[v.size:]
	}
	return nil
}
