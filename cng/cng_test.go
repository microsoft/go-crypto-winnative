// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng_test

import (
	"fmt"
	"io"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/microsoft/go-crypto-winnative/cng"
)

func TestMain(m *testing.M) {
	fips, err := cng.FIPS()
	if err != nil {
		fmt.Printf("FIPS() error = %v\n", err)
	}
	fmt.Println("FIPS enabled:", fips)
	os.Exit(m.Run())
}

func TestFIPS(t *testing.T) {
	enabled, err := cng.FIPS()
	if err != nil {
		t.Errorf("FIPS() error = %v", err)
	}
	if s := os.Getenv("GO_TEST_FIPS"); s != "" {
		wantFips, err := strconv.Atoi(s)
		if err != nil {
			t.Fatalf("failed to parse $GO_TEST_FIPS = %q as integer: %v", s, err)
		}
		if want := (wantFips == 1); enabled != want {
			t.Errorf("FIPS() = %v, want = %v", enabled, want)
		}
	}
}

func newRandReader(t *testing.T) io.Reader {
	seed := time.Now().UnixNano()
	t.Logf("Deterministic RNG seed: 0x%x", seed)
	return rand.New(rand.NewSource(seed))
}
