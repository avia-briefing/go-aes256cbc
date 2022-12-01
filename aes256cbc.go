package aes256cbc

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"math/rand"

	"github.com/mergermarket/go-pkcs7"
)

func Encrypt(data []byte, key string) (string, error) {
	keyData, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	data, err = pkcs7.Pad(data, aes.BlockSize)
	if err != nil {
		return "", err
	}
	iv := randomString(aes.BlockSize)
	mode := cipher.NewCBCEncrypter(keyData, []byte(iv))
	mode.CryptBlocks(data, data)
	return iv + base64.StdEncoding.EncodeToString(data), nil
}

func Decrypt(encrypted string, password string) ([]byte, error) {
	keyData, err := aes.NewCipher([]byte(password))
	if err != nil {
		return nil, err
	}
	iv := encrypted[:aes.BlockSize]
	encryptedString := encrypted[aes.BlockSize:]
	data, err := base64.StdEncoding.DecodeString(encryptedString)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(keyData, []byte(iv))
	mode.CryptBlocks(data, data)
	data, err = pkcs7.Unpad(data, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}
