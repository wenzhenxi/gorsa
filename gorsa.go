package gorsa

import (
	"encoding/base64"
)

// PublicEncrypt 公钥加密
func PublicEncrypt(data, publicKey string) (string, error) {

	grsa := RSASecurity{}
	grsa.SetPublicKey(publicKey)

	rsadata, err := grsa.PubKeyENCTYPT([]byte(data))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(rsadata), nil
}

// PriKeyEncrypt 私钥加密
func PriKeyEncrypt(data, privateKey string) (string, error) {

	grsa := RSASecurity{}
	grsa.SetPrivateKey(privateKey)

	rsadata, err := grsa.PriKeyENCTYPT([]byte(data))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(rsadata), nil
}

// PublicDecrypt 公钥解密
func PublicDecrypt(data, publicKey string) (string, error) {

	databs, _ := base64.StdEncoding.DecodeString(data)

	grsa := RSASecurity{}
	if err := grsa.SetPublicKey(publicKey); err != nil {
		return "", err
	}

	rsadata, err := grsa.PubKeyDECRYPT(databs)
	if err != nil {
		return "", err
	}
	//return hex.EncodeToString(rsadata),nil
	return string(rsadata), nil
}

// 私钥解密
func PriKeyDecrypt(data, privateKey string) (string, error) {

	databs, _ := base64.StdEncoding.DecodeString(data)

	grsa := RSASecurity{}

	if err := grsa.SetPrivateKey(privateKey); err != nil {
		return "", err
	}

	rsadata, err := grsa.PriKeyDECRYPT(databs)
	if err != nil {
		return "", err
	}

	//return hex.EncodeToString(rsadata), nil
	return string(rsadata), nil
}
