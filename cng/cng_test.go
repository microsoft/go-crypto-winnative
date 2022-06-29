// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/microsoft/go-crypto-winnative/cng"
)

func TestMain(m *testing.M) {
	fips, _ := cng.FIPS()
	fmt.Println("FIPS enabled:", fips)
	os.Exit(m.Run())
}

func TestFIPS(t *testing.T) {
	_, err := cng.FIPS()
	if err != nil {
		t.Errorf("FIPS() error = %v", err)
	}
}
