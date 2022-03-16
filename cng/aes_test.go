// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows
// +build windows

package cng

import (
	"bytes"
	"testing"
)

func TestAESInvalidKeySize(t *testing.T) {
	_, err := NewAESCipher([]byte{1})
	if err == nil {
		t.Error("error expected")
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	key := []byte("D249BF6DEC97B1EBD69BC4D6B3A3C49D")
	ci, err := NewAESCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	plainText := make([]byte, ci.BlockSize())
	plainText[1] = 1
	plainText[15] = 15
	cipherText := make([]byte, ci.BlockSize())
	decrypted := make([]byte, ci.BlockSize())
	ci.Encrypt(cipherText, plainText)
	ci.Decrypt(decrypted, cipherText)
	if !bytes.Equal(decrypted, plainText) {
		t.Errorf("unexpected decrypted result\ngot: %#v\nexp: %#v", decrypted, plainText)
	}
}
