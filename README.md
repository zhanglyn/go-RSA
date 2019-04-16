# Go-RSA 

Go-RSA 提供RSA公钥加密、私钥解密、私钥加签、公钥验签集成方法

## Overview

使用Go语言进行RSA加解密以及加签验签之中，会根据秘钥的长度，PKCS类型不同衍生出很多对应的加解密以及加签的方法；现在将其都集成在一个工具包内，通过填写参数，进行直接调用，可以省去许多时间。

## Fearture

非对称加密方法

## Example

`package RSA

 

import (

​    "encoding/base64"

​    "encoding/json"

​    "fmt"

​    "testing"

)

 

type TestText struct {

​    Name string `json:"name"`

​    No   int32  `json:"no"`

}

 

func Test_init(t *testing.T) {

​    //结构声明

​    r := RSA{

​        PKCS: "PKCS8",

​        Bits: 1024,

​    }

​    // 自动生成秘钥对

​     if err := r.GenRsaKey("private", "public"); err != nil {

​      t.Errorf("GenRsaKey err : %v", err)

​     }

​    // 公钥加密

​    testText := &TestText{

​        Name: "test",

​        No:   1,

​    }

​    b, err := json.Marshal(testText)

​    if err != nil {

​        t.Errorf("json Marshal err : %v", err)

​    }

​    r.OrigData = b

​    dataText, err := r.RSAEncrypt("public")

​    if err != nil {

​        t.Errorf("RSAEncrypt err: %v", err)

​    }

​    // base64编码

​    ba := base64.StdEncoding.EncodeToString(dataText)

​    t.Log("dataText-------->", string(ba))

​    fmt.Println("dataText-------->", string(ba))

​    r.DecryptData = ba

​    cryptoText, err := r.RsaPrivateDe("private")

​    if err != nil {

​        t.Errorf("RsaPrivateDe err: %v", err)

​    }

​    t.Log("cryptoText------->", cryptoText)

​    fmt.Println("cryptoText-------->", cryptoText)

 

}

 

func Test_Sign(t *testing.T) {

​    //结构声明

​    r := RSA{

​        PKCS: "PKCS8",

​        Bits: 1024,

​    }

​    // 自动生成秘钥对

​     if err := r.GenRsaKey("private_sign", "public_sign"); err != nil {

​     t.Errorf("GenRsaKey err : %v", err)

​     }

​    testText := &TestText{

​        Name: "test",

​        No:   1,

​    }

​    b, err := json.Marshal(testText)

​    if err != nil {

​        t.Errorf("json Marshal err : %v", err)

​    }

​    r.EncryptType = "MD5"

​    r.SignData = b

​    signature, err := r.RsaSign("private_sign")

​    if err != nil {

​        t.Errorf("RsaSign err :%v", err)

​    }

​    t.Log("加签密文：", signature)

 

​    if err := r.RsaVerySignWithBase64("public_sign", string(b), signature); err != nil {

​        t.Errorf("RsaVerySignWithBase64 err :%v", err)

​    }

}

 `