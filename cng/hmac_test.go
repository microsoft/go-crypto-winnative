// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"bytes"
	"hash"
	"testing"
)

func TestHMAC(t *testing.T) {
	key := []byte{1, 2, 3}
	var tests = []struct {
		name string
		fn   func() hash.Hash
	}{
		{"sha1", NewSHA1},
		{"sha256", NewSHA256},
		{"sha384", NewSHA384},
		{"sha512", NewSHA512},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHMAC(tt.fn, key)
			h.Write([]byte("hello"))
			sumHello := h.Sum(nil)

			h = NewHMAC(tt.fn, key)
			h.Write([]byte("hello world"))
			sumHelloWorld := h.Sum(nil)

			// Test that Sum has no effect on future Sum or Write operations.
			// This is a bit unusual as far as usage, but it's allowed
			// by the definition of Go hash.Hash, and some clients expect it to work.
			h = NewHMAC(tt.fn, key)
			h.Write([]byte("hello"))
			if sum := h.Sum(nil); !bytes.Equal(sum, sumHello) {
				t.Fatalf("1st Sum after hello = %x, want %x", sum, sumHello)
			}
			if sum := h.Sum(nil); !bytes.Equal(sum, sumHello) {
				t.Fatalf("2nd Sum after hello = %x, want %x", sum, sumHello)
			}

			h.Write([]byte(" world"))
			if sum := h.Sum(nil); !bytes.Equal(sum, sumHelloWorld) {
				t.Fatalf("1st Sum after hello world = %x, want %x", sum, sumHelloWorld)
			}
			if sum := h.Sum(nil); !bytes.Equal(sum, sumHelloWorld) {
				t.Fatalf("2nd Sum after hello world = %x, want %x", sum, sumHelloWorld)
			}

			h.Reset()
			h.Write([]byte("hello"))
			if sum := h.Sum(nil); !bytes.Equal(sum, sumHello) {
				t.Fatalf("Sum after Reset + hello = %x, want %x", sum, sumHello)
			}
		})
	}
}
