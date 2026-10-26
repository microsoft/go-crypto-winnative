// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bcrypt

func FailGenRandomForTesting() func() {
	saved := procBCryptGenRandom
	// BCryptHashData has the same ABI and rejects the nil algorithm handle
	// passed by RandReader, giving a deterministic native error.
	procBCryptGenRandom = procBCryptHashData
	return func() { procBCryptGenRandom = saved }
}
