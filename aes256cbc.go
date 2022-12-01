package aes256cbc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

func Encrypt(data []byte, key string) (string, error) {
	keyData, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	data, err = pad(data, aes.BlockSize)
	if err != nil {
		return "", err
	}
	iv := random(aes.BlockSize)
	mode := cipher.NewCBCEncrypter(keyData, []byte(iv))
	mode.CryptBlocks(data, data)
	return iv + base64.StdEncoding.EncodeToString(data), nil
}

func Decrypt(encrypted string, password string) ([]byte, error) {
	keyData, err := aes.NewCipher([]byte(password))
	if err != nil {
		return nil, err
	}
	if len(encrypted) <= aes.BlockSize {
		return nil, fmt.Errorf("encrypted data too short")
	}
	iv := encrypted[:aes.BlockSize]
	encryptedString := encrypted[aes.BlockSize:]
	data, err := base64.StdEncoding.DecodeString(encryptedString)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(keyData, []byte(iv))
	mode.CryptBlocks(data, data)
	data, err = unpad(data, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// PKCS#7 padding

func pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, fmt.Errorf("invalid blocksize %d", blocksize)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("invalid data")
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

func unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, fmt.Errorf("invalid blocksize %d", blocksize)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("invalid data")
	}
	if len(b)%blocksize != 0 {
		return nil, fmt.Errorf("invalid data length")
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return b[:len(b)-n], nil
}

// String generates a random string using only letters provided in the letters parameter
// if user ommit letters parameters, this function will use defLetters instead
func random(n int, letters ...string) string {
	defLetters := []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	var letterRunes []rune
	if len(letters) == 0 {
		letterRunes = defLetters
	} else {
		letterRunes = []rune(letters[0])
	}
	var bb bytes.Buffer
	bb.Grow(n)
	l := uint32(len(letterRunes))
	// on each loop, generate one random rune and append to output
	for i := 0; i < n; i++ {
		bb.WriteRune(letterRunes[binary.BigEndian.Uint32(genBytes(4))%l])
	}
	return bb.String()
}

// Bytes generates n random bytes
func genBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}
