package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

func Sha256withRSA(plain string, sk string) (string, error) {
	skPem, _ := pem.Decode([]byte(sk))
	if skPem == nil {
		return "", errors.New("传入的密钥有误")
	}
	var skRSA *rsa.PrivateKey
	var err error
	switch skPem.Type {
	case PKCS1_SK_TYPE:
		skRSA, err = x509.ParsePKCS1PrivateKey(skPem.Bytes)
		if err != nil {
			return "", err
		}
	case PKCS8_SK_TYPE:
		tmp, err := x509.ParsePKCS8PrivateKey(skPem.Bytes)
		if err != nil {
			return "", err
		}
		skRSA = tmp.(*rsa.PrivateKey)
	}

	h := sha256.Sum256([]byte(plain))
	sign, err := rsa.SignPKCS1v15(rand.Reader, skRSA, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	finalSign := base64.StdEncoding.EncodeToString(sign)

	return finalSign, nil
}
