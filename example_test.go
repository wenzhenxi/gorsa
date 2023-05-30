// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Keep in sync with ../base32/example_test.go.

package gorsa

import (
	"fmt"
	"testing"
)

func Test_Example(t *testing.T) {
	res, err := GenerateKey(1024)
	if err != nil {
		fmt.Println(err)
		return
	}
	publicKey := res.PublicKeyBase64
	privateKey := res.PrivateKeyBase64

	fmt.Println("\n私钥: \n\r" + privateKey)
	fmt.Println("\n公钥: \n\r" + publicKey)
	fmt.Println("\n私钥加密 —— 公钥解密")

	str := `{"domainId":"id", "externalUserId":"test001"}`
	fmt.Println("\n\r明文：\r\n" + str)
	encodedData, err := PriKeyEncrypt(str, privateKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("\n密文：\r\n" + encodedData)

	decodedData, err := PublicDecrypt(encodedData, publicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("\n解密后文字: \r\n" + decodedData)
}
