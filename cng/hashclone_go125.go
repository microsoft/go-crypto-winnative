// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build go1.25 && windows
// +build go1.25,windows

package cng

import (
	"hash"
)

type HashCloner = hash.Cloner
