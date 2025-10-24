// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

// MLKEM constants for testing against the stdlib
var (
	SharedKeySizeMLKEM            = sharedKeySizeMLKEM
	SeedSizeMLKEM                 = seedSizeMLKEM
	CiphertextSizeMLKEM768        = ciphertextSizeMLKEM768
	EncapsulationKeySizeMLKEM768  = encapsulationKeySizeMLKEM768
	CiphertextSizeMLKEM1024       = ciphertextSizeMLKEM1024
	EncapsulationKeySizeMLKEM1024 = encapsulationKeySizeMLKEM1024
)
