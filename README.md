# gm-crypto

## x509  

扩展golang官方的x509库，支持国密SM2

### 生成国密密钥
#### 生成国密 SM2 私钥
```
openssl ecparam -name SM2 -genkey -noout -out sm2-key.pem
```
#### 生成国密 SM2 公钥
```
openssl ec -in sm2-key.pem -pubout -out sm2pubkey.pem
```
### 生成国密证书
#### 生成证书请求
```
openssl req -key sm2-key.pem -new -out sm2.req
```
#### 生成证书
```
openssl x509 -req -in sm2.req -signkey sm2-key.pem -out sm2-cert.pem
```

## tls

扩展golang官方的tls库，支持国密SM2

