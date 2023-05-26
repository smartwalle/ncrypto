package ncrypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"github.com/smartwalle/ncrypto/internal"
	"github.com/smartwalle/ncrypto/pkcs1"
	"github.com/smartwalle/ncrypto/pkcs8"
)

func packageData(data []byte, packageSize int) (r [][]byte) {
	var src = make([]byte, len(data))
	copy(src, data)

	r = make([][]byte, 0)
	if len(src) <= packageSize {
		return append(r, src)
	}
	for len(src) > 0 {
		var p = src[:packageSize]
		r = append(r, p)
		src = src[packageSize:]
		if len(src) <= packageSize {
			r = append(r, src)
			break
		}
	}
	return r
}

// RSAEncrypt 使用公钥 key 对数据 data 进行 RSA 加密
func RSAEncrypt(plaintext, key []byte) ([]byte, error) {
	pubKey, err := internal.DecodePublicKey(key)
	if err != nil {
		return nil, err
	}

	return RSAEncryptWithKey(plaintext, pubKey)
}

// RSAEncryptWithKey 使用公钥 key 对数据 data 进行 RSA 加密
func RSAEncryptWithKey(plaintext []byte, key *rsa.PublicKey) ([]byte, error) {
	var pData = packageData(plaintext, key.N.BitLen()/8-11)
	var ciphertext = make([]byte, 0, 0)

	for _, d := range pData {
		var c, e = rsa.EncryptPKCS1v15(rand.Reader, key, d)
		if e != nil {
			return nil, e
		}
		ciphertext = append(ciphertext, c...)
	}

	return ciphertext, nil
}

// RSADecryptWithPKCS1 使用私钥 key 对数据 data 进行 RSA 解密，key 的格式为 pkcs1
func RSADecryptWithPKCS1(ciphertext, key []byte) ([]byte, error) {
	priKey, err := pkcs1.DecodePrivateKey(key)
	if err != nil {
		return nil, err
	}

	return RSADecryptWithKey(ciphertext, priKey)
}

// RSADecryptWithPKCS8 使用私钥 key 对数据 data 进行 RSA 解密，key 的格式为 pkcs8
func RSADecryptWithPKCS8(ciphertext, key []byte) ([]byte, error) {
	priKey, err := pkcs8.DecodePrivateKey(key)
	if err != nil {
		return nil, err
	}

	return RSADecryptWithKey(ciphertext, priKey)
}

// RSADecryptWithKey 使用私钥 key 对数据 data 进行 RSA 解密
func RSADecryptWithKey(ciphertext []byte, key *rsa.PrivateKey) ([]byte, error) {
	var pData = packageData(ciphertext, key.PublicKey.N.BitLen()/8)
	var plaintext = make([]byte, 0, 0)

	for _, d := range pData {
		var p, e = rsa.DecryptPKCS1v15(rand.Reader, key, d)
		if e != nil {
			return nil, e
		}
		plaintext = append(plaintext, p...)
	}
	return plaintext, nil
}

func RSASignWithPKCS1(plaintext, key []byte, hash crypto.Hash) ([]byte, error) {
	priKey, err := pkcs1.DecodePrivateKey(key)
	if err != nil {
		return nil, err
	}
	return RSASignWithKey(plaintext, priKey, hash)
}

func RSASignWithPKCS8(plaintext, key []byte, hash crypto.Hash) ([]byte, error) {
	priKey, err := pkcs8.DecodePrivateKey(key)
	if err != nil {
		return nil, err
	}
	return RSASignWithKey(plaintext, priKey, hash)
}

func RSASignWithKey(plaintext []byte, key *rsa.PrivateKey, hash crypto.Hash) ([]byte, error) {
	var h = hash.New()
	h.Write(plaintext)
	var hashed = h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, key, hash, hashed)
}

func RSAVerify(ciphertext, signature, key []byte, hash crypto.Hash) error {
	pubKey, err := internal.DecodePublicKey(key)
	if err != nil {
		return err
	}
	return RSAVerifyWithKey(ciphertext, signature, pubKey, hash)
}

func RSAVerifyWithKey(ciphertext, signature []byte, key *rsa.PublicKey, hash crypto.Hash) error {
	var h = hash.New()
	h.Write(ciphertext)
	var hashed = h.Sum(nil)
	return rsa.VerifyPKCS1v15(key, hash, hashed, signature)
}
