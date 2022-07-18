// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"bytes"
	"fmt"
	"hash"
	"testing"
)

func TestHMAC_EmptyKey(t *testing.T) {
	const payload = "message"
	var tests = []struct {
		name string
		fn   func() hash.Hash
		out  string
	}{
		{"sha1", NewSHA1, "d5d1ed05121417247616cfc8378f360a39da7cfa"},
		{"sha256", NewSHA256, "eb08c1f56d5ddee07f7bdf80468083da06b64cf4fac64fe3a90883df5feacae4"},
		{"sha384", NewSHA384, "a1302a8028a419bb834bfae53c5e98ab48e07aed9ef8b980a821df28685902003746ade315072edd8ce009a1d23705ec"},
		{"sha512", NewSHA512, "08fce52f6395d59c2a3fb8abb281d74ad6f112b9a9c787bcea290d94dadbc82b2ca3e5e12bf2277c7fedbb0154d5493e41bb7459f63c8e39554ea3651b812492"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHMAC(tt.fn, nil)
			h.Write([]byte(payload))
			sum := fmt.Sprintf("%x", h.Sum(nil))
			if sum != tt.out {
				t.Errorf("have %s want %s\n", sum, tt.out)
			}
		})
	}
}

func TestHMAC(t *testing.T) {
	key := []byte{1, 2, 3}
	var tests = []struct {
		name string
		fn   func() hash.Hash
		key  []byte
	}{
		{"sha1", NewSHA1, key},
		{"sha256", NewSHA256, key},
		{"sha256-big", NewSHA256, append(key, make([]byte, 1000)...)},
		{"sha384", NewSHA384, key},
		{"sha512", NewSHA512, key},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHMAC(tt.fn, tt.key)
			h.Write([]byte("hello"))
			sumHello := h.Sum(nil)

			h = NewHMAC(tt.fn, tt.key)
			h.Write([]byte("hello world"))
			sumHelloWorld := h.Sum(nil)

			// Test that Sum has no effect on future Sum or Write operations.
			// This is a bit unusual as far as usage, but it's allowed
			// by the definition of Go hash.Hash, and some clients expect it to work.
			h = NewHMAC(tt.fn, tt.key)
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
