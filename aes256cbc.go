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

func pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := blocklen - (len(data) % blocklen)
	if padlen == 0 {
		padlen = blocklen
	}
	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

func unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	// the last byte is the length of padding
	padlen := int(data[len(data)-1])
	// check padding integrity, all bytes should be the same
	pad := data[len(data)-padlen:]
	for _, padbyte := range pad {
		if padbyte != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padlen], nil
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
