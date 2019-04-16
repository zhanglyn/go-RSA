package RSA

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

type TestText struct {
	Name string `json:"name"`
	No   int32  `json:"no"`
}

func Test_init(t *testing.T) {
	//结构声明
	r := RSA{
		PKCS: "PKCS8",
		Bits: 1024,
	}
	// 自动生成秘钥对
	// if err := r.GenRsaKey("private", "public"); err != nil {
	// 	t.Errorf("GenRsaKey err : %v", err)
	// }
	// 公钥加密
	testText := &TestText{
		Name: "test",
		No:   1,
	}
	b, err := json.Marshal(testText)
	if err != nil {
		t.Errorf("json Marshal err : %v", err)
	}
	r.OrigData = b
	dataText, err := r.RSAEncrypt("public")
	if err != nil {
		t.Errorf("RSAEncrypt err: %v", err)
	}
	// base64编码
	ba := base64.StdEncoding.EncodeToString(dataText)
	t.Log("dataText-------->", string(ba))
	fmt.Println("dataText-------->", string(ba))
	r.DecryptData = ba
	cryptoText, err := r.RsaPrivateDe("private")
	if err != nil {
		t.Errorf("RsaPrivateDe err: %v", err)
	}
	t.Log("cryptoText------->", cryptoText)
	fmt.Println("cryptoText-------->", cryptoText)

}

func Test_Sign(t *testing.T) {
	//结构声明
	r := RSA{
		PKCS: "PKCS8",
		Bits: 1024,
	}
	// 自动生成秘钥对
	// if err := r.GenRsaKey("private_sign", "public_sign"); err != nil {
	// 	t.Errorf("GenRsaKey err : %v", err)
	// }
	testText := &TestText{
		Name: "test",
		No:   1,
	}
	b, err := json.Marshal(testText)
	if err != nil {
		t.Errorf("json Marshal err : %v", err)
	}
	r.EncryptType = "MD5"
	r.SignData = b
	signature, err := r.RsaSign("private_sign")
	if err != nil {
		t.Errorf("RsaSign err :%v", err)
	}
	t.Log("加签密文：", signature)

	if err := r.RsaVerySignWithBase64("public_sign", string(b), signature); err != nil {
		t.Errorf("RsaVerySignWithBase64 err :%v", err)
	}
}
