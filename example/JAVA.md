# 对应java版本

```java
package com.example.demo;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class Main {
    public static final String CHARSET = "UTF-8";
    public static final String RSA_ALGORITHM = "RSA";
    public static final int KEY_SIZE = 1024;

    public static Map<String, String> createKeys() {
        //为RSA算法创建一个KeyPairGenerator对象
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("No such algorithm-->[" + RSA_ALGORITHM + "]");
        }

        //初始化KeyPairGenerator对象,密钥长度
        kpg.initialize(KEY_SIZE);
        //生成密匙对
        KeyPair keyPair = kpg.generateKeyPair();
        //得到公钥
        Key publicKey = keyPair.getPublic();
        String publicKeyStr = Base64.encodeBase64String(publicKey.getEncoded());
        //得到私钥
        Key privateKey = keyPair.getPrivate();
        String privateKeyStr = Base64.encodeBase64String(privateKey.getEncoded());
        Map<String, String> keyPairMap = new HashMap<String, String>();
        keyPairMap.put("publicKey", publicKeyStr);
        keyPairMap.put("privateKey", privateKeyStr);

        return keyPairMap;
    }

    public static RSAPublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //通过X509编码的Key指令获得公钥对象
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKey));
        RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
        return key;
    }


    public static RSAPrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //通过PKCS#8编码的Key指令获得私钥对象
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKey));
        RSAPrivateKey key = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
        return key;
    }

    public static String privateEncrypt(String data, RSAPrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);

            return Base64.encodeBase64String(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data.getBytes(CHARSET), privateKey.getModulus().bitLength()));
        } catch (Exception e) {
            throw new RuntimeException("加密字符串[" + data + "]时遇到异常", e);
        }
    }


    public static String publicDecrypt(String data, RSAPublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, Base64.decodeBase64(data), publicKey.getModulus().bitLength()), CHARSET);
        } catch (Exception e) {
            throw new RuntimeException("解密字符串[" + data + "]时遇到异常", e);
        }
    }

    private static byte[] rsaSplitCodec(Cipher cipher, int opmode, byte[] datas, int keySize) {
        int maxBlock = 0;
        if (opmode == Cipher.DECRYPT_MODE) {
            maxBlock = keySize / 8;
        } else {
            maxBlock = keySize / 8 - 11; // 加密
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] buff;
        int i = 0;
        try {
            while (datas.length > offSet) {
                if (datas.length - offSet > maxBlock) {
                    buff = cipher.doFinal(datas, offSet, maxBlock);
                } else {
                    buff = cipher.doFinal(datas, offSet, datas.length - offSet);
                }
                out.write(buff, 0, buff.length);
                i++;
                offSet = i * maxBlock;
            }
        } catch (Exception e) {
            e.getMessage();
        }
        byte[] resultDatas = out.toByteArray();
        try {
            out.close();
        } catch (Exception e) {
            e.getMessage();
        }
        return resultDatas;
    }

    public static String toHexString(String s) {
        String str = "";
        for (int i = 0; i < s.length(); i++) {
            int ch = (int) s.charAt(i);
            str += Integer.toHexString(ch);
        }
        return str;
    }


    /**
     * 16进制字符串转换为字符串
     *
     * @param s
     * @return
     */
    public static String hexStringToString(String s) {
        if (s == null || s.equals("")) {
            return null;
        }
        s = s.replace(" ", "");
        byte[] baKeyword = new byte[s.length() / 2];
        for (int i = 0; i < baKeyword.length; i++) {
            try {
                baKeyword[i] = (byte) (0xff & Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        try {
            s = new String(baKeyword, "gbk");
            new String();
        } catch (Exception e1) {
            e1.printStackTrace();
        }
        return s;
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> keyMap = createKeys();
        String publicKey = keyMap.get("publicKey");
        String privateKey = keyMap.get("privateKey");
        System.out.println("公钥: \n\r" + publicKey);
        System.out.println("私钥： \n\r" + privateKey);
        System.out.println("私钥加密——公钥解密");

        String str = "{\"domainId\":\"ssotest\",\"externalUserId\":\"A0001\",\"timestamp\":1672502400}";
        System.out.println("\r明文：\r\n" + str);

        String encodedData = privateEncrypt(str, getPrivateKey(privateKey));
        System.out.println("密文：\r\n" + toHexString(encodedData));

        String decodedData = publicDecrypt(encodedData, getPublicKey(publicKey));
        System.out.println("解密后文字: \r\n" + decodedData);

//        String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIeiSgcWa8kiEqMzvqV0BTd8MGAi5fw0WMxVXv58VghIc9t30czF4D289ce+0aJh/DR2ZIWrBzEDjrda07tdBDU27kcTniJ3T2DVPNAOFcpVUA20OIok0BRBYK7Ac8iqJccJB/q/TXKdHyNHbPjQ6kwp7Wx2cQCWh5j2rWXXzW9vAgMBAAECgYB6K9yydaexDFftWXaoYdExIVQRxF2UxzIVG/DtGeIEo/53+X2pDbPm6IYa3e7GbaxXNS1mmZ9oruOmlNGTOz3FwWJN+C33WQMLBOlO2gUQSqLZ4X8EvTEBiMvF42U5pDqyAh0EgGtDL4TtA34CgEyX7Iw7rKgfhVvE1OWuDiQ3QQJBAL7rQZt0RARAEqG+WAEPWaN3iUsLkiClZnyfF3hVQug3n/OVSDm7iuKZyYRHIEanTGrfabq7fPw/qD+4fJcMj00CQQC13obu3bhBwCc01ApWR6cy4+liKexpGTvUK+5LpPiM72jFhPyRXdmYsdeXmE6SuxIYDx6xJVip4O1YuC99YxOrAkBjDkas9Gbx2ZiRKOQaMK+ue6/VKvy3SXniQNz5hys+ttWbmSGvKpoFtgrzQcACSH0CmkYOJ4bSjeiqnvqtmEulAkEAkjtdtTxzhfKR06lWsm8kogedRP++hfbzIzM7hHkeHHv3ezHlvqB+cIc2eT7Olq5x6wRlQjxsIROo47gc/y2lxwJAazp24jLnV9kGT6+hC8k79z9kFqs9x8H7Vil1IF/ciwSMSHq4IlT2X8CkgyR6iAZd9SNU24tcj05uVbpP14zC+g==";
//        String encodedData = privateEncrypt(str, getPrivateKey(privateKey));
//        System.out.println(encodedData.toString());
//        System.out.println("密文：\r\n" + toHexString(encodedData));

//        String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCHokoHFmvJIhKjM76ldAU3fDBgIuX8NFjMVV7+fFYISHPbd9HMxeA9vPXHvtGiYfw0dmSFqwcxA463WtO7XQQ1Nu5HE54id09g1TzQDhXKVVANtDiKJNAUQWCuwHPIqiXHCQf6v01ynR8jR2z40OpMKe1sdnEAloeY9q1l181vbwIDAQAB";
//        String encodedData = "QyNDS8CxI2ziE5Jz0jIBnJLy/L8lsXIpGhouhXw2DnEJ8ZxgnWHoEpHR8sPmbVzOCYvJQ5e4pSrYlGtwtry8bcR4Kn4W2P7XfeIhzTGKWwJFdSyUZeD2AmBMnV25xOoIUQ7BARt58rqy/M+v692ndReXtlshn7ce8FNPexGXlVk=";
//        String decodedData = publicDecrypt(encodedData, getPublicKey(publicKey));
//        System.out.println("GO加密，Java解密后文字: \r\n" + decodedData);

    }
}

```
