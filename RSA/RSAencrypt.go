package RSA

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

type RSA struct {
	OrigData    []byte // 待加密数据
	PKCS        string // PKCS类型("PKCS8"/"PKCS1")
	Bits        int    // 秘钥的长度
	DecryptData string // 待解密的数据
	SignData    []byte // 待加签数据
	EncryptType string // 加密的类型("MD5"/"SHA1"/"SHA256")
}

//全局变量
var privateKey, publicKey []byte

// 生成秘钥对
func (r RSA) GenRsaKey(privateKeyName, publicKeyName string) error {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, r.Bits)
	if err != nil {
		return err
	}
	var (
		derStream []byte
		block     *pem.Block
		file      *os.File
	)
	if r.PKCS == "PKCS8" {
		derStream, _ = x509.MarshalPKCS8PrivateKey(privateKey)
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: derStream,
		}
		file, err := os.Create(privateKeyName + ".pem")
		if err != nil {
			return err
		}
		err = pem.Encode(file, block)
		if err != nil {
			return err
		}
	} else if r.PKCS == "PKCS1" {
		derStream = x509.MarshalPKCS1PrivateKey(privateKey)
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: derStream,
		}
		file, err := os.Create(privateKeyName + ".pem")
		if err != nil {
			return err
		}
		err = pem.Encode(file, block)
		if err != nil {
			return err
		}
	}

	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	file, err = os.Create(publicKeyName + ".pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

// RSAEncrypt 解析公钥
func (r RSA) RSAEncrypt(publicKeyName string) ([]byte, error) {
	// 读取公钥
	var err error
	publicKey, err = ioutil.ReadFile(publicKeyName + ".pem")
	if err != nil {
		os.Exit(-1)
	}
	//解密pem格式的公钥
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 类型断言
	pub := pubInterface.(*rsa.PublicKey)
	//加密
	return rsaEncrypt(pub, string(r.OrigData))
}

// rsaEncrypt 数据加密
func rsaEncrypt(pub *rsa.PublicKey, data string) ([]byte, error) {
	partLen := pub.N.BitLen()/8 - 11
	chunks := split([]byte(data), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		bts, err := rsa.EncryptPKCS1v15(rand.Reader, pub, chunk)
		if err != nil {
			return nil, err
		}
		buffer.Write(bts)
	}

	return buffer.Bytes(), nil
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}

// rsaPrivateDe 解密读取秘钥
func (r RSA) RsaPrivateDe(privateKeyName string) (string, error) {
	// 读取私钥
	var (
		err           error
		privInterface interface{}
	)
	privateKey, err = ioutil.ReadFile(privateKeyName + ".pem")
	if err != nil {
		os.Exit(-1)
	}
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", errors.New("private key error!")
	}

	if r.PKCS == "PKCS8" {
		privInterface, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
	} else if r.PKCS == "PKCS1" {
		privInterface, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
	}

	// 类型断言
	priv, _ := privInterface.(*rsa.PrivateKey)
	plainText, err := rsaPrivateDecrypt(priv, r.DecryptData, r.Bits)
	if err != nil {
		return "", err
	}
	return plainText, nil
}

// RsaPrivateDecrypt 私钥解密
func rsaPrivateDecrypt(priv *rsa.PrivateKey, encrypted string, partLen int) (string, error) {
	partLen = partLen / 8
	raw, err := base64.StdEncoding.DecodeString(encrypted)
	chunks := split([]byte(raw), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, priv, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(decrypted)
	}
	return buffer.String(), err
}

// 私钥加签
func (r RSA) RsaSign(privateKeyName string) (string, error) {
	// 读取私钥
	var (
		err           error
		privInterface interface{}
		signature     []byte
	)
	privateKey, err = ioutil.ReadFile(privateKeyName + ".pem")
	if err != nil {
		os.Exit(-1)
	}

	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", errors.New("private key error!")
	}
	if r.PKCS == "PKCS8" {
		privInterface, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
	} else if r.PKCS == "PKCS1" {
		privInterface, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
	}
	// 类型断言
	priv, _ := privInterface.(*rsa.PrivateKey)
	// 根据加签类型加密签名
	switch {
	case r.EncryptType == "MD5":
		hash := md5.New()
		hash.Write(r.SignData)
		signature, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.MD5, hash.Sum(nil))
	case r.EncryptType == "SHA1":
		hash := sha1.New()
		hash.Write(r.SignData)
		signature, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, hash.Sum(nil))
	case r.EncryptType == "SHA256":
		hash := sha256.New()
		hash.Write(r.SignData)
		signature, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash.Sum(nil))
	}

	if err != nil {
		return "", err
	}
	out := base64.StdEncoding.EncodeToString(signature)
	return out, nil
}

// 公钥验签
func (r RSA) RsaVerySignWithBase64(publicKeyName, origData, signData string) error {
	// 读取公钥
	var err error
	publicKey, err = ioutil.ReadFile(publicKeyName + ".pem")
	if err != nil {
		os.Exit(-1)
	}
	//解密pem格式的公钥
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return errors.New("public key error")
	}
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	// 类型断言
	pub := pubInterface.(*rsa.PublicKey)

	sign, err := base64.StdEncoding.DecodeString(signData)
	if err != nil {
		return err
	}
	switch {
	case r.EncryptType == "MD5":
		hash := md5.New()
		hash.Write([]byte(origData))
		return rsa.VerifyPKCS1v15(pub, crypto.MD5, hash.Sum(nil), sign)
	case r.EncryptType == "SHA1":
		hash := sha1.New()
		hash.Write([]byte(origData))
		return rsa.VerifyPKCS1v15(pub, crypto.SHA1, hash.Sum(nil), sign)
	case r.EncryptType == "SHA256":
		hash := sha256.New()
		hash.Write([]byte(origData))
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash.Sum(nil), sign)
	}
	return err
}
