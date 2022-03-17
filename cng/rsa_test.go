// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"strconv"
	"testing"
)

func TestRSAKeyGeneration(t *testing.T) {
	for _, size := range []int{2048, 3072} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			N, E, D, P, Q, Dp, Dq, Qinv, err := GenerateKeyRSA(size)
			if err != nil {
				t.Fatalf("GenerateKeyRSA(%d): %v", size, err)
			}
			_, err = NewPrivateKeyRSA(N, E, D, P, Q, Dp, Dq, Qinv)
			if err != nil {
				t.Fatalf("NewPrivateKeyRSA(%d): %v", size, err)
			}
			_, err = NewPublicKeyRSA(N, E)
			if err != nil {
				t.Fatalf("NewPublicKeyRSA(%d): %v", size, err)
			}
		})
	}
}
