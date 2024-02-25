package aes256cbc

import (
	"testing"
)

func TestHello(t *testing.T) {
	key := random(32)
	println("key:", key)
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

func TestDecrypt(t *testing.T) {
	key := "sIBZrzG9l4Y3li37khem1hhiB1y0n02P"
	encrypted := "S41oeSkhwvKM4aEqQAfj4IO7uTEFP2H4Q2bJig=="
	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	println(string(decrypted))
}
