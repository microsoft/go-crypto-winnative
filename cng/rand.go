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
	n := len32(b)
	const flags = bcrypt.USE_SYSTEM_PREFERRED_RNG
	err := bcrypt.GenRandom(0, b[:n], flags)
	if err != nil {
		return 0, err
	}
	return n, nil
}

const RandReader = randReader(0)
