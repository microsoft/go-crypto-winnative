// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
package cng

import "math/bits"

// This file does not have build constraints to
// facilitate using BigInt in Go crypto.
// Go crypto references BigInt unconditionally,
// even if it is not finally used.

// A BigInt is the big-endian bytes from a math/big BigInt,
// which are normalized to remove any leading 0 byte.
// Windows BCrypt accepts this specific data format.
// This definition allows us to avoid importing math/big.
// Conversion between BigInt and *big.Int is in cng/bbig.
type BigInt []byte

const _S = bits.UintSize / 8 // word size in bytes

// Length of x in bits.
func (x BigInt) bitLen() int {
	if len(x) == 0 {
		return 0
	}
	// x is normalized, so the length in bits is
	// the length in bits of x minus one byte (_S),
	// plus the minimum number of bits to represent the first byte.
	return (len(x)-1)*_S + bits.Len(uint(x[0]))
}
