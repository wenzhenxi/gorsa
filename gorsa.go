package gorsa

import (
	"encoding/base64"
	"encoding/hex"
)

// PublicEncrypt 公钥加密
func PublicEncrypt(data, publicKey string) (string, error) {

	gRsa := RSASecurity{}
	gRsa.SetPublicKey(publicKey)

	rsaData, err := gRsa.PubKeyENCTYPT([]byte(data))
	if err != nil {
		return "", err
	}

	baseData := base64.StdEncoding.EncodeToString(rsaData)
	return hex.EncodeToString([]byte(baseData)), nil
}

// PriKeyEncrypt 私钥加密
func PriKeyEncrypt(data, privateKey string) (string, error) {

	gRsa := RSASecurity{}
	gRsa.SetPrivateKey(privateKey)

	rsaData, err := gRsa.PriKeyENCTYPT([]byte(data))
	if err != nil {
		return "", err
	}

	baseData := base64.StdEncoding.EncodeToString(rsaData)
	return hex.EncodeToString([]byte(baseData)), nil
}

// PublicDecrypt 公钥解密
func PublicDecrypt(data, publicKey string) (string, error) {
	dataByte, err := hex.DecodeString(data)
	if err != nil {
		return "", err
	}

	dataBs, err := base64.StdEncoding.DecodeString(string(dataByte))
	if err != nil {
		return "", err
	}

	gRsa := RSASecurity{}
	if err := gRsa.SetPublicKey(publicKey); err != nil {
		return "", err
	}

	rsaData, err := gRsa.PubKeyDECRYPT(dataBs)
	if err != nil {
		return "", err
	}

	return string(rsaData), nil
}

// PriKeyDecrypt 私钥解密
func PriKeyDecrypt(data, privateKey string) (string, error) {
	dataByte, err := hex.DecodeString(data)
	if err != nil {
		return "", err
	}

	dataBs, _ := base64.StdEncoding.DecodeString(string(dataByte))

	gRsa := RSASecurity{}

	if err := gRsa.SetPrivateKey(privateKey); err != nil {
		return "", err
	}

	rsaData, err := gRsa.PriKeyDECRYPT(dataBs)
	if err != nil {
		return "", err
	}

	return string(rsaData), nil
}
