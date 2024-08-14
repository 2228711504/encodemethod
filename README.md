// # 设置256位密钥（64个十六进制字符）
```
export ENCRYPTION_KEY="00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
```
// # 设置128位IV（32个十六进制字符）
```
export ENCRYPTION_IV="AABBCCDDEEFF00112233445566778899"
```

// # 32字节的密钥 (64个十六进制字符)
```
export CHACHA20_KEY="00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
```
// # 8字节的IV (16个十六进制字符)
```
export CHACHA20_IV="AABBCCDDEEFF0011"
```

# 生成 2048 位的 RSA 私钥
```
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
```
# 从私钥生成公钥
```
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

```
openssl pkey -pubin -in public_key.pem -outform DER -out public_key.der
openssl rsa -in private_key.pem -outform DER -out private_key.der
export RSA_PUBLIC_KEY_PATH="./public_key.der"
export RSA_PRIVATE_KEY_PATH="./private_key.der"
g++ -std=c++17 encode3.cpp -o encode3 -lcryptopp
```

RSA/OAEP-MGF1(SHA-1): message length of 1024 exceeds the maximum of 214 for this public key

