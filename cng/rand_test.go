// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import "testing"

func TestRand(t *testing.T) {
	_, err := RandReader.Read(make([]byte, 5))
	if err != nil {
		t.Fatal(err)
	}
}
