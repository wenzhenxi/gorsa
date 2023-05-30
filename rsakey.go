package gorsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

type RSAKey struct {
	PublicKeyPem  []byte //公钥pem字符串
	PrivateKeyPem []byte //私钥pem字符串

	PublicKeyBase64  string //公钥base64字符串
	PrivateKeyBase64 string //私钥base64字符串

	PublicKey  *rsa.PublicKey  //公钥
	PrivateKey *rsa.PrivateKey //私钥
}

// GenerateKey 生成RSA私钥和公钥
// bits 证书大小
func GenerateKey(bits int) (resp RSAKey, err error) {
	// -------------------------- 设置私钥 --------------------------
	// GenerateKey 函数使用随机数据生成器，random 生成一对具有指定字位数的RSA密钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits) // Reader 是一个全局、共享的密码用强随机数生成器
	if err != nil {
		return
	}
	// 通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	X509PrivateKey, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	// 对x509私钥，进行pem格式编码
	privateKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "Private key",
		Bytes: X509PrivateKey,
	})
	// 对x509私钥，进行base64格式编码
	privateKeyBase64 := fmt.Sprintf(
		"-----BEGIN Private key-----\n%s\n-----END Private key-----",
		base64.StdEncoding.EncodeToString(X509PrivateKey),
	)
	resp.PrivateKeyBase64 = privateKeyBase64
	resp.PrivateKeyPem = privateKeyPem
	resp.PrivateKey = privateKey

	// -------------------------- 设置公钥 --------------------------
	// 获取公钥的数据
	publicKey := &privateKey.PublicKey
	// X509对公钥编码
	X509PublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return
	}
	// 对x509公钥，进行pem格式编码
	publicKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "Public key",
		Bytes: X509PublicKey,
	})
	// 对x509公钥，进行base64格式编码
	publicKeyBase64 := fmt.Sprintf("-----BEGIN Public key-----\n%s\n-----END Public key-----",
		base64.StdEncoding.EncodeToString(X509PublicKey),
	)
	resp.PublicKeyBase64 = publicKeyBase64
	resp.PublicKeyPem = publicKeyPem
	resp.PublicKey = publicKey
	return
}
