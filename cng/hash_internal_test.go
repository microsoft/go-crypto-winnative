// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha3"
	"testing"

	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

func TestHashOneShotWithContext(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("abc"), bytes.Repeat([]byte{0x5a}, 8192)} {
		want := sha256.Sum256(data)
		var got [sha256.Size]byte
		if err := hashOneShotWithContext(bcrypt.SHA256_ALGORITHM, data, got[:]); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("SHA256 = %x, want %x", got, want)
		}
	}
	for _, bits := range []int{128, 256} {
		if !SupportsSHAKE(bits) {
			continue
		}
		for _, size := range []int{0, 32, 1024} {
			data := []byte("message")
			var id string
			var want []byte
			if bits == 128 {
				id = bcrypt.CSHAKE128_ALGORITHM
				want = sha3.SumSHAKE128(data, size)
			} else {
				id = bcrypt.CSHAKE256_ALGORITHM
				want = sha3.SumSHAKE256(data, size)
			}
			got := make([]byte, size)
			if err := hashOneShotWithContext(id, data, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("SHAKE%d output size %d = %x, want %x", bits, size, got, want)
			}
		}
	}
}
