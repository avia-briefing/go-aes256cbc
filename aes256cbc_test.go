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
	key := "BpLnfgDsc2WD8F2qNfHK5a84jjJkwzDk"
	encrypted := "BvaOPsYfRHDTd1vPLElaYvmLbulPoDEewU29UqTPNEMuNH5+BK7gqjJ1Ghf/6lsTwXXUV8UQ5sIlpS8C"
	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	println(string(decrypted))
}
