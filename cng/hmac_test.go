// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng_test

import (
	"bytes"
	"crypto"
	"fmt"
	"testing"

	"github.com/microsoft/go-crypto-winnative/cng"
)

func TestHMAC_EmptyKey(t *testing.T) {
	const payload = "message"
	var tests = []struct {
		name string
		fn   func() *cng.Hash
		out  string
	}{
		{"sha1", cng.NewSHA1, "d5d1ed05121417247616cfc8378f360a39da7cfa"},
		{"sha256", cng.NewSHA256, "eb08c1f56d5ddee07f7bdf80468083da06b64cf4fac64fe3a90883df5feacae4"},
		{"sha384", cng.NewSHA384, "a1302a8028a419bb834bfae53c5e98ab48e07aed9ef8b980a821df28685902003746ade315072edd8ce009a1d23705ec"},
		{"sha512", cng.NewSHA512, "08fce52f6395d59c2a3fb8abb281d74ad6f112b9a9c787bcea290d94dadbc82b2ca3e5e12bf2277c7fedbb0154d5493e41bb7459f63c8e39554ea3651b812492"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := cng.NewHMAC(tt.fn, nil)
			h.Write([]byte(payload))
			sum := fmt.Sprintf("%x", h.Sum(nil))
			if sum != tt.out {
				t.Errorf("have %s want %s\n", sum, tt.out)
			}
		})
	}
}

// TestHMACSHA3 verifies HMAC with SHA-3 on Windows versions where CNG exposes
// SHA-3 (Windows 11 24H2 / Server 2025+); it skips on older Windows, where
// sha3.New* is not backend-backed. The expected tags were generated with Go's
// crypto/hmac over crypto/sha3.
func TestHMACSHA3(t *testing.T) {
	if !cng.SupportsHash(crypto.SHA3_256) {
		t.Skip("SHA-3 not supported on this Windows version")
	}
	const payload = "message"
	var tests = []struct {
		name string
		fn   func() *cng.Hash
		out  string
	}{
		{"sha3-256", cng.NewSHA3_256, "87bab4787b2681ec9a121f3d57677e90f227bcd71a97fe198e794eff5a12468b"},
		{"sha3-384", cng.NewSHA3_384, "d63a431dbb6b8e87451683527c561cc983cd3c93d2122cdbe2a89906233731a61e111109df38c24daa503a14aaa4e331"},
		{"sha3-512", cng.NewSHA3_512, "ed089cb5b29ac6ba3736f5c106f14fea11dac27e9984f111f0f2e47a5a48d1eee91ec5d17615cd7853247bfac98483e3bb9e0f1fc48a0768ae914235d2ac96f7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := cng.NewHMAC(tt.fn, nil)
			if h == nil {
				t.Fatal("NewHMAC returned nil for SHA-3")
			}
			h.Write([]byte(payload))
			sum := fmt.Sprintf("%x", h.Sum(nil))
			if sum != tt.out {
				t.Errorf("have %s want %s", sum, tt.out)
			}
		})
	}
}

func TestHMAC(t *testing.T) {
	key := []byte{1, 2, 3}
	var tests = []struct {
		name string
		fn   func() *cng.Hash
		key  []byte
	}{
		{"sha1", cng.NewSHA1, key},
		{"sha256", cng.NewSHA256, key},
		{"sha256-big", cng.NewSHA256, append(key, make([]byte, 1000)...)},
		{"sha384", cng.NewSHA384, key},
		{"sha512", cng.NewSHA512, key},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := cng.NewHMAC(tt.fn, tt.key)
			h.Write([]byte("hello"))
			sumHello := h.Sum(nil)

			h = cng.NewHMAC(tt.fn, tt.key)
			h.Write([]byte("hello world"))
			sumHelloWorld := h.Sum(nil)

			// Test that Sum has no effect on future Sum or Write operations.
			// This is a bit unusual as far as usage, but it's allowed
			// by the definition of Go hash.Hash, and some clients expect it to work.
			h = cng.NewHMAC(tt.fn, tt.key)
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
