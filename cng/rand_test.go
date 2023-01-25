// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"io"
	"testing"
)

func TestRand(t *testing.T) {
	b := make([]byte, 5)
	n, err := RandReader.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if want := len(b); n != want {
		t.Errorf("got:%v want:%v", len(b), n)
	}
}

func TestRandBig(t *testing.T) {
	if testing.Short() {
		// This test can take ~20s to complete.
		t.Skip("skipping test in short mode.")
	}
	b := make([]byte, 1<<32+60)
	n, err := io.ReadFull(RandReader, b)
	if err != nil {
		t.Fatal(err)
	}
	if want := len(b); n != int(want) {
		t.Errorf("got:%v want:%v", want, n)
	}
}
