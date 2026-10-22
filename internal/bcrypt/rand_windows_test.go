// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bcrypt_test

import (
	"bytes"
	"crypto/cipher"
	"testing"

	"github.com/microsoft/go-crypto-winnative/cng"
	"github.com/microsoft/go-crypto-winnative/internal/bcrypt"
)

func TestGCMNonceReadFailure(t *testing.T) {
	block, err := cng.NewAESCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bcrypt.FailGenRandomForTesting())
	nonce := bytes.Repeat([]byte{0x5a}, gcm.NonceSize())
	_, wantErr := cng.RandReader.Read(nonce)
	if wantErr == nil {
		t.Fatal("expected the replacement native call to fail")
	}
	plaintext := []byte("message")
	out := bytes.Repeat([]byte{0xa5}, len(plaintext)+gcm.Overhead())
	wantOut := bytes.Clone(out)
	defer func() {
		if got := recover(); got != wantErr {
			t.Errorf("panic = %v, want %v", got, wantErr)
		}
		if !bytes.Equal(out, wantOut) {
			t.Error("output changed after nonce generation failed")
		}
	}()
	gcm.(interface {
		SealWithRandomNonce(out, nonce, plaintext, additionalData []byte)
	}).SealWithRandomNonce(out, nonce, plaintext, nil)
}
