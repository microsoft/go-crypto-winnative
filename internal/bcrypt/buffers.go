// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bcrypt

import (
	"errors"
	"math"
)

var errBufferTooLarge = errors.New("bcrypt: buffer length out of range")

// CheckBufferSizes checks that sizes fit in the unsigned 32-bit length fields
// used by BCrypt.
func CheckBufferSizes(sizes ...int) error {
	for _, size := range sizes {
		if uint64(size) > math.MaxUint32 {
			return errBufferTooLarge
		}
	}
	return nil
}
