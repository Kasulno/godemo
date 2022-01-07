package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

const (
	PKCS1_SK_TYPE string = "RSA PRIVATE KEY"
	PKCS1_PK_TYPE string = "RSA PUBLIC KEY"
	PKCS8_SK_TYPE string = "PRIVATE KEY"
	PKCS8_PK_TYPE string = "PUBLIC KEY"
)

func GenerateRSAKeyPairPKCS1(size int) (string, string, error) {
	if size != 1024 && size != 2048 && size != 3072 && size != 4096 {
		return "", "", errors.New("私钥长度不正确，请从1024、2048、3072、4096中选择")
	}

	sk, _ := rsa.GenerateKey(rand.Reader, size)
	skPKCS1Bytes := x509.MarshalPKCS1PrivateKey(sk)
	skBytes := pem.EncodeToMemory(&pem.Block{
		Type:  PKCS1_SK_TYPE,
		Bytes: skPKCS1Bytes,
	})

	pkPKCS1Bytes := x509.MarshalPKCS1PublicKey(&sk.PublicKey)
	pkBytes := pem.EncodeToMemory(&pem.Block{
		Type:  PKCS1_PK_TYPE,
		Bytes: pkPKCS1Bytes,
	})

	return string(skBytes), string(pkBytes), nil
}

func GenerateRSAKeyPairPKCS8(size int) (string, string, error) {
	if size != 1024 && size != 2048 && size != 3072 && size != 4096 {
		return "", "", errors.New("私钥长度不正确，请从1024、2048、3072、4096中选择")
	}

	sk, _ := rsa.GenerateKey(rand.Reader, size)
	skPKCS8Bytes, _ := x509.MarshalPKCS8PrivateKey(sk)
	skBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: skPKCS8Bytes,
	})

	pkPKIXBytes, _ := x509.MarshalPKIXPublicKey(&sk.PublicKey)
	pkBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkPKIXBytes,
	})

	return string(skBytes), string(pkBytes), nil
}

func RSAEncrypt(plainText string, pk string) (string, error) {
	pkBytes := []byte(pk)

	// pem解码
	pkPem, _ := pem.Decode(pkBytes)

	var pkRSA *rsa.PublicKey
	var err error

	switch pkPem.Type {
	case PKCS1_PK_TYPE:
		pkRSA, err = x509.ParsePKCS1PublicKey(pkPem.Bytes)
		if err != nil {
			return "", err
		}
	case PKCS8_PK_TYPE:
		tmp, err := x509.ParsePKIXPublicKey(pkPem.Bytes)
		if err != nil {
			return "", err
		}
		pkRSA = tmp.(*rsa.PublicKey)
	default:
		return "", errors.New("未知的公钥类型")
	}

	// 对明文进行加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, pkRSA, []byte(plainText))
	if err != nil {
		return "", err
	}
	// 返回密文
	return string(cipherText), nil
}

func RSADecrypt(cipherText string, sk string) (string, error) {
	skBytes := []byte(sk)

	// pem解码
	skPem, _ := pem.Decode(skBytes)

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
	default:
		return "", errors.New("未知的私钥类型")
	}

	// 对密文进行解密
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, skRSA, []byte(cipherText))
	//返回明文
	return string(plainText), nil
}
