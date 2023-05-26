package pkcs1

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/smartwalle/ncrypto/internal"
)

const (
	kPKCS1Prefix = "-----BEGIN RSA PRIVATE KEY-----"
	kPKCS1Suffix = "-----END RSA PRIVATE KEY-----"
)

func FormatPrivateKey(raw string) []byte {
	return internal.FormatKey(raw, kPKCS1Prefix, kPKCS1Suffix, 64)
}

func FormatPublicKey(raw string) []byte {
	return internal.FormatPublicKey(raw)
}

func EncodePrivateKey(privateKey *rsa.PrivateKey) ([]byte, error) {
	privateBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateBytes}

	var privateBuffer bytes.Buffer
	if err := pem.Encode(&privateBuffer, privateBlock); err != nil {
		return nil, err
	}
	return privateBuffer.Bytes(), nil
}

func DecodePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to load private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, err
}

func EncodePublicKey(publicKey *rsa.PublicKey) ([]byte, error) {
	return internal.EncodePublicKey(publicKey)
}

func DecodePublicKey(data []byte) (*rsa.PublicKey, error) {
	return internal.DecodePublicKey(data)
}

func GenerateKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, err
}

func GenerateKeyBytes(bits int) (private, public []byte, error error) {
	privateKey, publicKey, err := GenerateKey(bits)
	if err != nil {
		return nil, nil, err
	}

	privateBytes, err := EncodePrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	publicBytes, err := internal.EncodePublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	return privateBytes, publicBytes, err
}
