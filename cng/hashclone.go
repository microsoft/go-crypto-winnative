// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows

package cng

import (
	"hash"
)

type HashCloner = hash.Cloner
