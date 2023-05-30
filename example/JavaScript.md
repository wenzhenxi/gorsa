# 对应 js 版本

```js
var NodeRSA = require('node-rsa');

const encrypt_rsa = function (data) {

const privateKey = new NodeRSA("-----BEGIN PRIVATE KEY-----\n" +

"客户生成私钥\n" +

"-----END PRIVATE KEY-----");

const result = privateKey.encryptPrivate(data, "base64");

const hexResult = Buffer.from(result, 'utf8').toString('hex');

return hexResult;

}
```
