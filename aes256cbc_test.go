package aes256cbc

import (
	"testing"
)

func Test(t *testing.T) {
	key := random(32)
	t.Logf("key: %s", key)
	original := "Hello World"
	encrypted, err := Encrypt([]byte(original), key)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	if string(decrypted) != original {
		t.Errorf("Decrypted text does not match original text")
	}
}
