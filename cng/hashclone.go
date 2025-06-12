// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"hash"
)

// HashCloner is an interface that defines a Clone method.
type HashCloner interface {
	hash.Hash
	// Clone returns a separate Hash instance with the same state as h.
	Clone() (HashCloner, error)
}
