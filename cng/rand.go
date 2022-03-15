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
	if len(b) == 0 {
		return 0, nil
	}
	err := bcrypt.GenRandom(0, &b[0], uint32(len(b)), bcrypt.USE_SYSTEM_PREFERRED_RNG)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

const RandReader = randReader(0)
