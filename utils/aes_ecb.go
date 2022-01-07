package utils

import (
	"crypto/aes"
	"crypto/sha1"
	"encoding/base64"
	"errors"
)

func Sha1(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}

func AesSha1prng(sk []byte, encryptLength int) ([]byte, error) {
	hashs := Sha1(Sha1(sk))
	maxLen := len(hashs)
	realLen := encryptLength / 8
	if realLen > maxLen {
		return nil, errors.New("invalid length!")
	}

	return hashs[0:realLen], nil
}

func generateAESKeyECB(sk []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, sk)
	for i := 16; i < len(sk); {
		for j := 0; j < 16 && i < len(sk); j, i = j+1, i+1 {
			genKey[j] ^= sk[i]
		}
	}
	return genKey
}

func AesEncryptECB(src []byte, sk []byte) (string, error) {
	key, err := AesSha1prng(sk, 128)
	if err != nil {
		return "", err
	}

	cipher, _ := aes.NewCipher(generateAESKeyECB(key))
	length := (len(src) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, src)
	pad := byte(len(plain) - len(src))
	for i := len(src); i < len(plain); i++ {
		plain[i] = pad
	}
	encrypted := make([]byte, len(plain))
	for bs, be := 0, cipher.BlockSize(); bs <= len(src); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Encrypt(encrypted[bs:be], plain[bs:be])
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func AesDecryptECB(msg string, sk []byte) (string, error) {
	encrypted, _ := base64.StdEncoding.DecodeString(msg)
	key, err := AesSha1prng(sk, 128)
	if err != nil {
		return "", err
	}

	cipher, _ := aes.NewCipher(generateAESKeyECB(key))
	decrypted := make([]byte, len(encrypted))
	for bs, be := 0, cipher.BlockSize(); bs < len(encrypted); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
	}
	trim := len(decrypted) - int(decrypted[len(decrypted)-1])

	return string(decrypted[0:trim]), nil
}
