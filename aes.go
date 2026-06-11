package ncrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/smartwalle/ncrypto/pbkdf2"
)

var (
	ErrInvalidIVSize        = errors.New("invalid iv size")
	ErrCiphertextNotAligned = errors.New("ciphertext is not block-aligned")
	ErrCiphertextTooShort   = errors.New("ciphertext too short")
)

const (
	kPKCSSaltLen      = 8
	kPKCSDefaultIter  = 2048
	kPKCSDefaultMagic = "Salted__"
	kEVPMaxIvLen      = 16
)

func RandBytes(length int) (data []byte, err error) {
	data = make([]byte, length)
	if _, err = io.ReadFull(rand.Reader, data); err != nil {
		return nil, err
	}
	return data, err
}

func AESCBCEncryptWithSalt(plaintext, key []byte, iter int, magic string, padding Padding, h func() hash.Hash) ([]byte, error) {
	return AESEncryptWithSalt(plaintext, key, iter, magic, h, padding, AESCBCEncrypt)
}

func AESCBCDecryptWithSalt(data, key []byte, iter int, magic string, padding Padding, h func() hash.Hash) ([]byte, error) {
	return AESDecryptWithSalt(data, key, iter, magic, h, padding, AESCBCDecrypt)
}

func AESEncryptWithSalt(plaintext, key []byte, iter int, magic string, h func() hash.Hash, padding Padding, f func(plaintext, key, iv []byte, padding Padding) ([]byte, error)) ([]byte, error) {
	if iter <= 0 {
		iter = kPKCSDefaultIter
	}

	if h == nil {
		h = md5.New
	}

	salt, err := RandBytes(kPKCSSaltLen)
	if err != nil {
		return nil, err
	}
	var sKey = pbkdf2.Key(key, salt, iter, len(key), h)
	var sIV = pbkdf2.Key(sKey, salt, iter, kEVPMaxIvLen, h)

	ciphertext, err := f(plaintext, sKey, sIV, padding)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 0, len(magic)+kPKCSSaltLen+len(ciphertext))
	result = append(result, []byte(magic)...)
	result = append(result, salt...)
	result = append(result, ciphertext...)

	return result, nil
}

func AESDecryptWithSalt(ciphertext, key []byte, iterCount int, magic string, h func() hash.Hash, padding Padding, f func(ciphertext, key, iv []byte, padding Padding) ([]byte, error)) ([]byte, error) {
	if iterCount <= 0 {
		iterCount = kPKCSDefaultIter
	}

	if h == nil {
		h = md5.New
	}

	if len(ciphertext) <= len(magic)+kPKCSSaltLen {
		return nil, ErrCiphertextTooShort
	}

	var salt = ciphertext[len(magic) : len(magic)+kPKCSSaltLen]
	var sKey = pbkdf2.Key(key, salt, iterCount, len(key), h)
	var sIV = pbkdf2.Key(sKey, salt, iterCount, kEVPMaxIvLen, h)

	var plaintext, err = f(ciphertext[len(magic)+kPKCSSaltLen:], sKey, sIV, padding)
	return plaintext, err
}

// AESCBCEncrypt 由key的长度决定是128, 192 还是 256
func AESCBCEncrypt(plaintext, key, iv []byte, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var blockSize = block.BlockSize()
	if len(iv) < blockSize {
		return nil, ErrInvalidIVSize
	}
	iv = iv[:blockSize]

	src, err := padding.Pad(plaintext, blockSize)
	if err != nil {
		return nil, err
	}
	var dst = make([]byte, len(src))

	var mode = cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(dst, src)
	return dst, nil
}

func AESCBCDecrypt(ciphertext, key, iv []byte, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var blockSize = block.BlockSize()
	if len(iv) < blockSize {
		return nil, ErrInvalidIVSize
	}
	iv = iv[:blockSize]

	if len(ciphertext) == 0 || len(ciphertext)%blockSize != 0 {
		return nil, ErrCiphertextNotAligned
	}

	var dst = make([]byte, len(ciphertext))

	var mode = cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(dst, ciphertext)
	return padding.Unpad(dst, block.BlockSize())
}

func AESCFBEncrypt(plaintext, key, iv []byte, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var blockSize = block.BlockSize()
	if len(iv) < blockSize {
		return nil, ErrInvalidIVSize
	}
	iv = iv[:blockSize]

	src, err := padding.Pad(plaintext, blockSize)
	if err != nil {
		return nil, err
	}
	var dst = make([]byte, len(src))

	var mode = cipher.NewCFBEncrypter(block, iv)
	mode.XORKeyStream(dst, src)
	return dst, nil
}

func AESCFBDecrypt(ciphertext, key, iv []byte, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var blockSize = block.BlockSize()
	if len(iv) < blockSize {
		return nil, ErrInvalidIVSize
	}
	iv = iv[:blockSize]

	var dst = make([]byte, len(ciphertext))

	var mode = cipher.NewCFBDecrypter(block, iv)
	mode.XORKeyStream(dst, ciphertext)
	return padding.Unpad(dst, block.BlockSize())
}

func AESECBEncrypt(plaintext, key []byte, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var blockSize = block.BlockSize()

	src, err := padding.Pad(plaintext, blockSize)
	if err != nil {
		return nil, err
	}

	var dst = make([]byte, len(src))
	var start = 0
	var end = blockSize

	for start < len(src) {
		block.Encrypt(dst[start:end], src[start:end])
		start = start + blockSize
		end = end + blockSize
	}
	return dst, nil
}

func AESECBDecrypt(ciphertext, key []byte, padding Padding) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var blockSize = block.BlockSize()
	if len(ciphertext) == 0 || len(ciphertext)%blockSize != 0 {
		return nil, ErrCiphertextNotAligned
	}

	var dst = make([]byte, len(ciphertext))
	var start = 0
	var end = blockSize

	for start < len(ciphertext) {
		block.Decrypt(dst[start:end], ciphertext[start:end])
		start = start + blockSize
		end = end + blockSize
	}

	return padding.Unpad(dst, blockSize)
}

func AESGCMEncrypt(plaintext, key, additional []byte) ([]byte, error) {
	var block, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, err := RandBytes(mode.NonceSize())
	if err != nil {
		return nil, err
	}
	return mode.Seal(nonce, nonce, plaintext, additional), nil
}

func AESGCMEncryptWithNonce(plaintext, key, nonce, additional []byte) ([]byte, error) {
	var block, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != mode.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size, must contain %d characters", mode.NonceSize())
	}

	return mode.Seal(nil, nonce, plaintext, additional), nil
}

func AESGCMDecrypt(ciphertext, key, additional []byte) ([]byte, error) {
	var block, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := mode.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	var nonce []byte
	nonce, ciphertext = ciphertext[:nonceSize], ciphertext[nonceSize:]
	return mode.Open(nil, nonce, ciphertext, additional)
}

func AESGCMDecryptWithNonce(ciphertext, key, nonce, additional []byte) ([]byte, error) {
	var block, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != mode.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size, must contain %d characters", mode.NonceSize())
	}

	return mode.Open(nil, nonce, ciphertext, additional)
}
