// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bcrypt

import "syscall"

const errBufferTooLarge = syscall.EINVAL

// CheckBufferSizes checks that sizes fit in the unsigned 32-bit length fields
// used by BCrypt. It returns syscall.EINVAL, like the generated slice wrappers.
func CheckBufferSizes(sizes ...int) error {
	for _, size := range sizes {
		if uint64(size) > (1<<32)-1 {
			return errBufferTooLarge
		}
	}
	return nil
}
