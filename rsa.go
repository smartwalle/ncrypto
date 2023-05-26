package ncrypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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

// RSAEncrypt 使用公钥 key 对数据 plaintext 进行加密
func RSAEncrypt(plaintext []byte, key *rsa.PublicKey) ([]byte, error) {
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

// RSADecrypt 使用私钥 key 对数据 ciphertext 进行解密
func RSADecrypt(ciphertext []byte, key *rsa.PrivateKey) ([]byte, error) {
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

func RSASignPKCS1v15(plaintext []byte, key *rsa.PrivateKey, hash crypto.Hash) ([]byte, error) {
	var h = hash.New()
	h.Write(plaintext)
	var hashed = h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, key, hash, hashed)
}

func RSAVerifyPKCS1v15(ciphertext, signature []byte, key *rsa.PublicKey, hash crypto.Hash) error {
	var h = hash.New()
	h.Write(ciphertext)
	var hashed = h.Sum(nil)
	return rsa.VerifyPKCS1v15(key, hash, hashed, signature)
}
