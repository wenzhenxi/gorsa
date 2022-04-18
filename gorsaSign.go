package gorsa

// 使用RSAWithMD5算法签名
func SignMd5WithRsa(data string, privateKey string) (string, error) {
	grsa := RSASecurity{}
	grsa.SetPrivateKey(privateKey)

	sign, err := grsa.SignMd5WithRsa(data)
	if err != nil {
		return "", err
	}

	return sign, err
}

// 使用RSAWithSHA1算法签名
func SignSha1WithRsa(data string, privateKey string) (string, error) {
	grsa := RSASecurity{}
	grsa.SetPrivateKey(privateKey)

	sign, err := grsa.SignSha1WithRsa(data)
	if err != nil {
		return "", err
	}

	return sign, err
}

// 使用RSAWithSHA256算法签名
func SignSha256WithRsa(data string, privateKey string) (string, error) {
	grsa := RSASecurity{}
	grsa.SetPrivateKey(privateKey)

	sign, err := grsa.SignSha256WithRsa(data)
	if err != nil {
		return "", err
	}
	return sign, err
}

// 使用RSAWithMD5验证签名
func VerifySignMd5WithRsa(data string, signData string, publicKey string) error {
	grsa := RSASecurity{}
	grsa.SetPublicKey(publicKey)
	return grsa.VerifySignMd5WithRsa(data, signData)
}

// 使用RSAWithSHA1验证签名
func VerifySignSha1WithRsa(data string, signData string, publicKey string) error {
	grsa := RSASecurity{}
	grsa.SetPublicKey(publicKey)
	return grsa.VerifySignSha1WithRsa(data, signData)
}

// 使用RSAWithSHA256验证签名
func VerifySignSha256WithRsa(data string, signData string, publicKey string) error {
	grsa := RSASecurity{}
	grsa.SetPublicKey(publicKey)
	return grsa.VerifySignSha256WithRsa(data, signData)
}
