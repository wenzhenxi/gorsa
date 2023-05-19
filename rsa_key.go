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
	PubStr string          //公钥字符串
	PriStr string          //私钥字符串
	PubKey *rsa.PublicKey  //公钥
	PriKey *rsa.PrivateKey //私钥
}

// GenerateRSAKey 生成RSA私钥和公钥
// bits 证书大小
func GenerateRSAKey(bits int) (resp RSAKey, err error) {

	// -------------------------- 设置私钥 --------------------------
	// GenerateKey 函数使用随机数据生成器，random生成一对具有指定字位数的RSA密钥
	// Reader 是一个全局、共享的密码用强随机数生成器
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}
	//保存私钥
	//通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	//使用pem格式对x509输出的内容进行编码
	//构建一个pem.Block结构体对象
	privateBlock := pem.Block{Type: "RSA Private Key", Bytes: X509PrivateKey}
	// 保存到内存
	privateKeyPem := pem.EncodeToMemory(&privateBlock)
	privateKeyStr := base64.StdEncoding.EncodeToString(privateKeyPem)
	// 设置返回值：私钥
	resp.PriStr = fmt.Sprintf("-----BEGIN Private key-----\n%v\n-----END Private key-----\n", privateKeyStr)
	resp.PriKey = privateKey

	// -------------------------- 设置公钥 --------------------------
	//获取公钥的数据
	publicKey := privateKey.PublicKey
	//X509对公钥编码
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return
	}
	//pem格式编码
	//创建一个pem.Block结构体对象
	publicBlock := pem.Block{Type: "RSA Public Key", Bytes: X509PublicKey}
	//保存到内存
	publicKeyPem := pem.EncodeToMemory(&publicBlock)
	publicKeyStr := base64.StdEncoding.EncodeToString(publicKeyPem)
	// 设置返回值：公钥
	resp.PubStr = fmt.Sprintf("-----BEGIN Public key-----\n%v\n-----END Public key-----\n", publicKeyStr)
	resp.PubKey = &publicKey
	return
}
