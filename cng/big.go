// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
package cng

// This file does not have build constraints to
// facilitate using BigInt in Go crypto.
// Go crypto references BigInt unconditionally,
// even if it is not finally used.

// A BigInt is the big-endian bytes from a math/big BigInt.
// Windows BCrypt accepts this specific data format.
// This definition allows us to avoid importing math/big.
// Conversion between BigInt and *big.Int is in cng/bbig.
type BigInt []byte
