// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bcrypt

type bufferSizeError struct{}

func (bufferSizeError) Error() string { return "bcrypt: buffer length out of range" }

var errBufferTooLarge error = bufferSizeError{}

// CheckBufferSizes checks that sizes fit in the unsigned 32-bit length fields
// used by BCrypt.
func CheckBufferSizes(sizes ...int) error {
	for _, size := range sizes {
		if uint64(size) > (1<<32)-1 {
			return errBufferTooLarge
		}
	}
	return nil
}
