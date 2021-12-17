package hash

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"project/internal/pkg/utils"
)

const (
	SK_FILE_NAME = ""
	PK_FILE_NAME = ""
)

//func GenerateRSAKey(path string) error {
//	sk, err := rsa.GenerateKey(rand.Reader, 2048)
//	if err != nil {
//		return err
//	}
//	x509sk, err := x509.MarshalPKCS8PrivateKey(sk)
//	if err != nil {
//		return err
//	}
//
//	pk := &sk.PublicKey
//	x509pk, err := x509.MarshalPKIXPublicKey(pk)
//	if err != nil {
//		return err
//	}
//
//	keyPath, err := FormatPath(path)
//	if err != nil {
//		return err
//	}
//}

func RSAEncrypt(plainText string, path string) (string, error) {
	// 打开公钥文件
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 读取文件的内容
	pkBytes, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	// pem解码
	pkBlock, _ := pem.Decode(pkBytes)

	// x509解码
	pkI, err := x509.ParsePKIXPublicKey(pkBlock.Bytes)
	if err != nil {
		return "", err
	}

	// 类型断言赋值
	pk := pkI.(*rsa.PublicKey)

	// 对明文进行加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, pk, []byte(plainText))
	if err != nil {
		return "", err
	}
	// 返回密文
	return string(cipherText), nil
}

func RSADecrypt(cipherText string, path string) (string, error) {
	// 打开私钥文件
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 获取文件内容
	skBytes, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	// pem解码
	skBlock, _ := pem.Decode(skBytes)

	// X509解码
	sk, err := x509.ParsePKCS1PrivateKey(skBlock.Bytes)
	if err != nil {
		return "", err
	}

	// 对密文进行解密
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, sk, []byte(cipherText))
	//返回明文
	return string(plainText), nil
}

func GenerateRSAKey(path string) (string, string, error) {
	// rsa.GenerateKey 函数使用随机数据生成器random生成一对具有指定字位数的RSA密钥
	// rand.Reader 是一个全局、共享的密码用强随机数生成器
	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// 通过x509标准将得到的RSA私钥序列化为ASN.1的DER编码字符串
	x509sk := x509.MarshalPKCS1PrivateKey(sk)

	// 格式化路径，生成文件路径
	filePath, err := utils.FormatPath(path)
	if err != nil {
		return "", "", err
	}
	skFilePath := filePath + "sk.pem"
	pkFilePath := filePath + "pk.pem"

	// 创建文件保存私钥
	skFile, err := os.Create(skFilePath)
	if err != nil {
		return "", "", nil
	}
	defer skFile.Close()

	// 使用pem格式对私钥进行编码
	// 构建一个pem.Block结构体对象
	skBlock := pem.Block{Type: "Private Key", Bytes: x509sk}
	// 将数据保存到文件
	pem.Encode(skFile, &skBlock)

	// 获取公钥的数据
	pk := sk.PublicKey
	// X509对公钥编码
	// 使用PKIX规范进行签名
	x509pk, err := x509.MarshalPKIXPublicKey(&pk)
	if err != nil {
		return "", "", err
	}

	// 创建用于保存公钥的文件
	pkFile, err := os.Create(pkFilePath)
	if err != nil {
		return "", "", err
	}
	defer pkFile.Close()

	// 使用pem格式对公钥进行编码
	// 创建一个pem.Block结构体对象
	pkBlock := pem.Block{Type: "Public Key", Bytes: x509pk}
	// 保存到文件
	pem.Encode(pkFile, &pkBlock)

	return skFilePath, pkFilePath, nil
}
