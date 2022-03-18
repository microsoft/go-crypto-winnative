// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

type randReader int

func (randReader) Read(b []byte) (int, error) {
	// BCryptGenRandom only accepts 2**32-1 bytes at a time, so truncate.
	inputLen := uint32(len(b))
	if inputLen == 0 {
		return 0, nil
	}
	err := bcrypt.GenRandom(0, &b[0], uint32(len(b)), bcrypt.USE_SYSTEM_PREFERRED_RNG)
	if err != nil {
		return 0, err
	}
	return int(inputLen), nil
}

const RandReader = randReader(0)
